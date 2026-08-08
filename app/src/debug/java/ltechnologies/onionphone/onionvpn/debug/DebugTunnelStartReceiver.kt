package ltechnologies.onionphone.onionvpn.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.MainActivity
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import timber.log.Timber

/**
 * DEBUG-only exported receiver for MCP/adb.
 *
 * Prefer launching via shell (BAL-safe on Android 14+):
 * ```
 * adb shell am start --user 0 \
 *   -n ltechnologies.onionphone.onionvpn/.MainActivity \
 *   --ez debug_start_tunnel true \
 *   --es tor_engine ARTI --es tun_data_plane ONIONMASQ
 * ```
 *
 * Broadcast still writes prefs, but [Context.startActivity] from a background receiver is
 * often blocked (`BAL_BLOCK`). Do not rely on broadcast alone to bring the UI up.
 *
 * ```
 * adb shell am broadcast -a ltechnologies.onionphone.onionvpn.DEBUG_START_TUNNEL \
 *   -n ltechnologies.onionphone.onionvpn/.debug.DebugTunnelStartReceiver \
 *   --es tor_engine ARTI --es tun_data_plane ONIONMASQ
 * ```
 */
@AndroidEntryPoint
class DebugTunnelStartReceiver : BroadcastReceiver() {
    @Inject lateinit var preferencesStore: TunnelPreferencesStore

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION) {
            Timber.w("DebugTunnelStartReceiver ignored action=%s", intent?.action)
            return
        }
        val pending = goAsync()
        val engineExtra = intent.getStringExtra(EXTRA_TOR_ENGINE)
        val planeExtra = intent.getStringExtra(EXTRA_TUN_DATA_PLANE)
        val appContext = context.applicationContext
        scope.launch {
            try {
                preferencesStore.update { prefs ->
                    prefs.copy(
                        torEngine = TorEngine.fromPreference(engineExtra ?: TorEngine.ARTI.name),
                        tunDataPlane = TunDataPlane.fromPreference(
                            planeExtra ?: TunDataPlane.ONIONMASQ.name,
                        ),
                        appLockEnabled = false,
                        autoStartOnAppLaunch = true,
                        allowAdbClearnetLeak = true,
                    )
                }
                Timber.i(
                    "DEBUG_START_TUNNEL prefs saved — launching MainActivity engine=%s plane=%s",
                    engineExtra ?: TorEngine.ARTI.name,
                    planeExtra ?: TunDataPlane.ONIONMASQ.name,
                )
                appContext.startActivity(
                    Intent(appContext, MainActivity::class.java).apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                        putExtra(EXTRA_DEBUG_START_TUNNEL, true)
                        putExtra(EXTRA_TOR_ENGINE, engineExtra ?: TorEngine.ARTI.name)
                        putExtra(EXTRA_TUN_DATA_PLANE, planeExtra ?: TunDataPlane.ONIONMASQ.name)
                    },
                )
            } catch (t: Throwable) {
                Timber.e(t, "DEBUG_START_TUNNEL failed")
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION = "ltechnologies.onionphone.onionvpn.DEBUG_START_TUNNEL"
        const val EXTRA_TOR_ENGINE = "tor_engine"
        const val EXTRA_TUN_DATA_PLANE = "tun_data_plane"
        const val EXTRA_DEBUG_START_TUNNEL = "debug_start_tunnel"
    }
}
