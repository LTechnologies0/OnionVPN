package ltechnologies.onionphone.onionvpn.service.lifecycle

import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityAction
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import timber.log.Timber

/**
 * Nested stability recovery graph: IGNORE/WARN → no-op; SOFT/HARD_RECOVER → Tor bounce (cooldown).
 */
internal class TunnelStabilityRecovery(
    private val tor: TorProcessManager,
    private val cooldownMs: Long = STABILITY_RECOVER_COOLDOWN_MS,
) {
    private var lastHandledStabilityCode: String = ""
    private var lastStabilityRecoverMs: Long = 0L

    fun maybeApply(st: TorControlStatus) {
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
                Timber.w("Stability HARD_RECOVER code=%s", code)
                tor.recoverNetworkHard().onFailure {
                    Timber.w(it, "Stability HARD_RECOVER failed — falling back to soft")
                    tor.onNetworkChanged()
                }
            }
            StabilityAction.SOFT_RECOVER -> {
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
