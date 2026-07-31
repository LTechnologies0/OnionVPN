package ltechnologies.onionphone.onionvpn.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
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
        val pending = goAsync()
        try {
            val prefs = runBlocking {
                withTimeoutOrNull(8_000) { preferencesStore.preferences.first() }
            } ?: return
            if (!prefs.autoStartOnBoot) {
                Timber.d("Boot autostart disabled — skip")
                return
            }
            if (VpnService.prepare(context) != null) {
                Timber.i("Boot autostart: VPN permission missing — open app once")
                return
            }
            val phase = TunnelForegroundService.snapshot.value.phase
            if (phase != TunnelPhase.Idle && phase != TunnelPhase.Error) {
                Timber.d("Boot autostart: tunnel already %s", phase)
                return
            }
            Timber.i("Boot autostart: starting tunnel")
            orchestrator.start(prefs)
        } catch (e: Exception) {
            Timber.w(e, "Boot autostart failed")
        } finally {
            pending.finish()
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
