package ltechnologies.onionphone.onionvpn.service.lifecycle

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityAction
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import timber.log.Timber

/**
 * Nested stability recovery graph: IGNORE/WARN → no-op; SOFT/HARD_RECOVER → Tor bounce (cooldown).
 * Arti has no CIRC/STREAM reason catalogs — soft/hard still work when invoked from network path.
 */
internal class TunnelStabilityRecovery(
    private val tor: TorProcessManager,
    private val scope: CoroutineScope,
    private val cooldownMs: Long = STABILITY_RECOVER_COOLDOWN_MS,
) {
    private var lastHandledStabilityCode: String = ""
    private var lastStabilityRecoverMs: Long = 0L

    fun maybeApply(st: TorControlStatus) {
        // Classic control-plane events only exist on C Tor.
        if (tor.engine == TorEngine.ARTI) return
        val actionName = st.lastStabilityAction
        if (actionName.isBlank()) return
        val action = runCatching { StabilityAction.valueOf(actionName) }.getOrNull() ?: return
        if (action != StabilityAction.SOFT_RECOVER && action != StabilityAction.HARD_RECOVER) return
        val code = st.lastStabilityCode
        val now = System.currentTimeMillis()
        val codeChanged = code != lastHandledStabilityCode
        if (!codeChanged && now - lastStabilityRecoverMs < cooldownMs) {
            return
        }
        if (now - lastStabilityRecoverMs < cooldownMs) return
        lastStabilityRecoverMs = now
        lastHandledStabilityCode = code
        when (action) {
            StabilityAction.HARD_RECOVER -> {
                OpTrace.warn("stability", "HARD_RECOVER code=$code")
                Timber.w("Stability HARD_RECOVER code=%s", code)
                scope.launch {
                    tor.recoverNetworkHard().onFailure {
                        OpTrace.warn("stability", "HARD_RECOVER failed — soft fallback", it)
                        Timber.w(it, "Stability HARD_RECOVER failed — falling back to soft")
                        tor.onNetworkChanged()
                    }
                }
            }
            StabilityAction.SOFT_RECOVER -> {
                OpTrace.info("stability", "SOFT_RECOVER code=$code")
                Timber.i("Stability SOFT_RECOVER code=%s", code)
                tor.onNetworkChanged()
            }
            else -> Unit
        }
    }

    fun reset() {
        lastHandledStabilityCode = ""
        lastStabilityRecoverMs = 0L
    }

    companion object {
        const val STABILITY_RECOVER_COOLDOWN_MS = 120_000L
    }
}
