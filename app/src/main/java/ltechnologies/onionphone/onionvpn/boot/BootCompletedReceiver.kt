package ltechnologies.onionphone.onionvpn.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.UserManager
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
 * Also handles [Intent.ACTION_USER_UNLOCKED]: closing/reopening an Android Private Space
 * kills the VPN process; OS Always-On may leave a Blocking TUN without Tor. Unlock is a
 * second chance to restore Connected (or start if Idle after Always-On missed the FGS).
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
        if (action !in HANDLED_ACTIONS) return
        // Never runBlocking on the receiver thread (often main) — DataStore + start can ANR.
        val pending = goAsync()
        val appCtx = context.applicationContext
        CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
            try {
                when (action) {
                    Intent.ACTION_USER_UNLOCKED -> handleUserUnlocked(appCtx)
                    else -> handleBootAutostart(appCtx)
                }
            } catch (e: Exception) {
                Timber.w(e, "Boot/unlock receiver failed action=%s", action)
            } finally {
                pending.finish()
            }
        }
    }

    private suspend fun handleBootAutostart(appCtx: Context) {
        val prefs = withTimeoutOrNull(8_000) { preferencesStore.preferences.first() }
            ?: return
        if (!prefs.autoStartOnBoot) {
            Timber.d("Boot autostart disabled — skip")
            return
        }
        if (VpnService.prepare(appCtx) != null) {
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
    }

    private suspend fun handleUserUnlocked(appCtx: Context) {
        if (VpnService.prepare(appCtx) != null) {
            Timber.d("USER_UNLOCKED: no VPN consent — skip")
            return
        }
        val um = appCtx.getSystemService(UserManager::class.java)
        if (um != null) {
            val quiet = runCatching {
                um.isQuietModeEnabled(android.os.Process.myUserHandle())
            }.getOrDefault(false)
            if (quiet) {
                Timber.d("USER_UNLOCKED: quiet mode still on — skip")
                return
            }
        }
        val phase = TunnelForegroundService.snapshot.value.phase
        if (phase == TunnelPhase.Connected || phase == TunnelPhase.Validating ||
            phase == TunnelPhase.StartingTor || phase == TunnelPhase.StartingDnsCrypt ||
            phase == TunnelPhase.StartingVpn || phase == TunnelPhase.StartingOpenVpn
        ) {
            Timber.d("USER_UNLOCKED: tunnel already %s", phase)
            return
        }
        val alwaysOnPkg = runCatching {
            android.provider.Settings.Secure.getString(
                appCtx.contentResolver,
                "always_on_vpn_app",
            )
        }.getOrNull()
        val weOwnAlwaysOn = alwaysOnPkg == appCtx.packageName
        val stuckBlocking = phase == TunnelPhase.Blocking
        if (!weOwnAlwaysOn && !stuckBlocking) {
            Timber.d(
                "USER_UNLOCKED: skip (alwaysOnPkg=%s phase=%s)",
                alwaysOnPkg,
                phase,
            )
            return
        }
        Timber.i(
            "USER_UNLOCKED: restoring tunnel phase=%s alwaysOn=%s",
            phase,
            weOwnAlwaysOn,
        )
        val intent = Intent(appCtx, TunnelForegroundService::class.java).apply {
            action = TunnelForegroundService.ACTION_ALWAYS_ON
        }
        runCatching {
            appCtx.startForegroundService(intent)
        }.onFailure { err ->
            Timber.w(err, "USER_UNLOCKED ALWAYS_ON failed — fallback orchestrator.start")
            val prefs = withTimeoutOrNull(8_000) { preferencesStore.preferences.first() }
                ?: return
            orchestrator.start(prefs)
        }
    }

    companion object {
        private val HANDLED_ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_LOCKED_BOOT_COMPLETED,
            Intent.ACTION_USER_UNLOCKED,
            "android.intent.action.QUICKBOOT_POWERON",
            "com.htc.intent.action.QUICKBOOT_POWERON",
        )
    }
}
