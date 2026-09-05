package ltechnologies.onionphone.onionvpn.tunnel

import android.content.Context
import android.content.Intent
import android.net.VpnService
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.StateFlow
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.service.TunnelForegroundService
import timber.log.Timber

@Singleton
class TunnelOrchestrator @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    val snapshot: StateFlow<TunnelSnapshot> = TunnelForegroundService.snapshot

    fun prepareVpnPermission(): Intent? = VpnService.prepare(context)

    fun start(preferences: TunnelPreferences = TunnelPreferences()) {
        Timber.i(
            "TunnelOrchestrator.start engine=%s plane=%s ovpn=%s noLogs=%s",
            preferences.torEngine,
            preferences.tunDataPlane,
            preferences.openVpnOverTorEnabled,
            preferences.noLogsEnabled,
        )
        context.startForegroundService(
            Intent(context, TunnelForegroundService::class.java).apply {
                action = TunnelForegroundService.ACTION_START
                putExtra(TunnelForegroundService.EXTRA_ROUTE_ALL, preferences.routeAllTrafficThroughTor)
                putExtra(TunnelForegroundService.EXTRA_KILL_SWITCH, true)
                putExtra(TunnelForegroundService.EXTRA_DNSCRYPT_SERVER, preferences.dnsCryptServerName)
                putExtra(TunnelForegroundService.EXTRA_DNS_MODE, preferences.dnsResolverMode.name)
                putExtra(TunnelForegroundService.EXTRA_TOR_ENGINE, preferences.torEngine.name)
                // OPSEC: never put bridges / node lists / OVPN Auth on Intent extras
                // (dumpsys / bugreport). DataStore is source of truth in startTunnel().
                putExtra(TunnelForegroundService.EXTRA_TOR_NEW_CIRCUIT, preferences.torNewCircuitPeriodSec)
                putExtra(TunnelForegroundService.EXTRA_TOR_MAX_DIRTINESS, preferences.torMaxCircuitDirtinessSec)
                putExtra(TunnelForegroundService.EXTRA_DNS_NOLOG, preferences.dnsCryptRequireNoLog)
                putExtra(TunnelForegroundService.EXTRA_DNS_NOFILTER, preferences.dnsCryptRequireNoFilter)
                putExtra(TunnelForegroundService.EXTRA_DNS_FORCE_TCP, preferences.dnsCryptForceTcp)
                putExtra(TunnelForegroundService.EXTRA_DNS_DNSSEC, preferences.dnsCryptRequireDnssec)
                putExtra(TunnelForegroundService.EXTRA_NO_LOGS, preferences.noLogsEnabled)
                putExtra(TunnelForegroundService.EXTRA_VPN_APP_MODE, preferences.vpnAppRoutingMode.name)
                putExtra(
                    TunnelForegroundService.EXTRA_VPN_APP_PACKAGES,
                    preferences.vpnAppPackages.joinToString("\n"),
                )
                putExtra(
                    TunnelForegroundService.EXTRA_ALLOW_ADB_CLEARNET_LEAK,
                    preferences.allowAdbClearnetLeak,
                )
                putExtra(
                    TunnelForegroundService.EXTRA_REQUIRE_OS_LOCKDOWN,
                    preferences.requireOsLockdown,
                )
                putExtra(TunnelForegroundService.EXTRA_TUN_DATA_PLANE, preferences.tunDataPlane.name)
                putExtra(TunnelForegroundService.EXTRA_OPENVPN_OVER_TOR, preferences.openVpnOverTorEnabled)
                putExtra(
                    TunnelForegroundService.EXTRA_OPENVPN_PROFILE,
                    preferences.openVpnProfileConfigured,
                )
            },
        )
    }

    fun stop() {
        Timber.i("TunnelOrchestrator.stop")
        context.startService(
            Intent(context, TunnelForegroundService::class.java).setAction(TunnelForegroundService.ACTION_STOP),
        )
    }

    fun newNym() {
        Timber.i("TunnelOrchestrator.newNym")
        context.startService(
            Intent(context, TunnelForegroundService::class.java)
                .setAction(TunnelForegroundService.ACTION_NEWNYM),
        )
    }

    /** Live SETCONF MaxCircuitDirtiness / NewCircuitPeriod while connected. */
    fun applyCircuitTiming(preferences: TunnelPreferences) {
        context.startService(
            Intent(context, TunnelForegroundService::class.java).apply {
                action = TunnelForegroundService.ACTION_APPLY_CIRCUIT_TIMING
                putExtra(TunnelForegroundService.EXTRA_TOR_MAX_DIRTINESS, preferences.torMaxCircuitDirtinessSec)
                putExtra(TunnelForegroundService.EXTRA_TOR_NEW_CIRCUIT, preferences.torNewCircuitPeriodSec)
            },
        )
    }
}
