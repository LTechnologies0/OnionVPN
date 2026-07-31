package ltechnologies.onionphone.onionvpn.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.service.TunnelForegroundService
import ltechnologies.onionphone.onionvpn.tunnel.TunnelOrchestrator
import timber.log.Timber

/**
 * Starts the Tor + DNSCrypt tunnel after device boot when the user opted in
 * ([ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences.autoStartOnBoot]).
 *
 * Requires prior VPN consent ([VpnService.prepare] == null). Otherwise boot cannot
 * show the system VPN dialog — user must open the app once.
 */
@AndroidEntryPoint
class BootCompletedReceiver : BroadcastReceiver() {
    @Inject lateinit var preferencesStore: TunnelPreferencesStore
    @Inject lateinit var orchestrator: TunnelOrchestrator

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action !in BOOT_ACTIONS) return
        // Never runBlocking on the receiver thread (often main) — DataStore + start can ANR.
        val pending = goAsync()
        val appCtx = context.applicationContext
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                val prefs = withTimeoutOrNull(8_000) { preferencesStore.preferences.first() }
                    ?: return@launch
                if (!prefs.autoStartOnBoot) {
                    Timber.d("Boot autostart disabled — skip")
                    return@launch
                }
                if (VpnService.prepare(appCtx) != null) {
                    Timber.i("Boot autostart: VPN permission missing — open app once")
                    return@launch
                }
                val phase = TunnelForegroundService.snapshot.value.phase
                if (phase != TunnelPhase.Idle && phase != TunnelPhase.Error) {
                    Timber.d("Boot autostart: tunnel already %s", phase)
                    return@launch
                }
                Timber.i("Boot autostart: starting tunnel")
                orchestrator.start(prefs)
            } catch (e: Exception) {
                Timber.w(e, "Boot autostart failed")
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        private val BOOT_ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            "android.intent.action.QUICKBOOT_POWERON",
            "com.htc.intent.action.QUICKBOOT_POWERON",
        )
    }
}
