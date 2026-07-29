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

@Singleton
class TunnelOrchestrator @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    val snapshot: StateFlow<TunnelSnapshot> = TunnelForegroundService.snapshot

    fun prepareVpnPermission(): Intent? = VpnService.prepare(context)

    fun start(preferences: TunnelPreferences = TunnelPreferences()) {
        context.startForegroundService(
            Intent(context, TunnelForegroundService::class.java).apply {
                action = TunnelForegroundService.ACTION_START
                putExtra(TunnelForegroundService.EXTRA_ROUTE_ALL, preferences.routeAllTrafficThroughTor)
                putExtra(TunnelForegroundService.EXTRA_KILL_SWITCH, preferences.killSwitchEnabled)
                putExtra(TunnelForegroundService.EXTRA_DNSCRYPT_SERVER, preferences.dnsCryptServerName)
                putExtra(TunnelForegroundService.EXTRA_DNS_MODE, preferences.dnsResolverMode.name)
                putExtra(TunnelForegroundService.EXTRA_TOR_BRIDGES, preferences.torBridges)
                putExtra(TunnelForegroundService.EXTRA_TOR_ENTRY, preferences.torEntryNodes)
                putExtra(TunnelForegroundService.EXTRA_TOR_EXIT, preferences.torExitNodes)
                putExtra(TunnelForegroundService.EXTRA_TOR_EXCLUDE, preferences.torExcludeNodes)
                putExtra(TunnelForegroundService.EXTRA_TOR_NEW_CIRCUIT, preferences.torNewCircuitPeriodSec)
                putExtra(TunnelForegroundService.EXTRA_TOR_MAX_DIRTINESS, preferences.torMaxCircuitDirtinessSec)
                putExtra(TunnelForegroundService.EXTRA_DNS_NOLOG, preferences.dnsCryptRequireNoLog)
                putExtra(TunnelForegroundService.EXTRA_DNS_NOFILTER, preferences.dnsCryptRequireNoFilter)
                putExtra(TunnelForegroundService.EXTRA_DNS_FORCE_TCP, preferences.dnsCryptForceTcp)
                putExtra(TunnelForegroundService.EXTRA_DNS_DNSSEC, preferences.dnsCryptRequireDnssec)
            },
        )
    }

    fun stop() {
        context.startService(
            Intent(context, TunnelForegroundService::class.java).setAction(TunnelForegroundService.ACTION_STOP),
        )
    }

    fun newNym() {
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
