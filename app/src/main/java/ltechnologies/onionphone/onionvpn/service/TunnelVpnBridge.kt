package ltechnologies.onionphone.onionvpn.service

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.delay
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import timber.log.Timber

/**
 * Intent bridge + readiness waits toward [OnionVpnService].
 *
 * Keeps VPN establish/teardown polling out of the tunnel orchestrator body.
 */
internal class TunnelVpnBridge(
    private val context: Context,
) {
    fun startConnected(preferences: TunnelPreferences, ports: TunnelRuntimePorts, generation: Int) {
        context.startService(
            Intent(context, OnionVpnService::class.java).apply {
                action = OnionVpnService.ACTION_START
                putExtra(OnionVpnService.EXTRA_ROUTE_ALL, preferences.routeAllTrafficThroughTor)
                putExtra(OnionVpnService.EXTRA_KILL_SWITCH, preferences.killSwitchEnabled)
                putExtra(OnionVpnService.EXTRA_PROFILE_MODE, VpnProfileMode.Connected.name)
                putExtra(OnionVpnService.EXTRA_TOR_SOCKS_PORT, ports.torSocksPort)
                putExtra(OnionVpnService.EXTRA_DNSCRYPT_PORT, ports.dnsCryptListenPort)
                putExtra(OnionVpnService.EXTRA_GENERATION, generation)
                putExtra(OnionVpnService.EXTRA_DNS_MODE, preferences.dnsResolverMode.name)
            },
        )
    }

    fun startBlocking(preferences: TunnelPreferences, generation: Int) {
        context.startService(
            Intent(context, OnionVpnService::class.java).apply {
                action = OnionVpnService.ACTION_BLOCK
                putExtra(OnionVpnService.EXTRA_ROUTE_ALL, preferences.routeAllTrafficThroughTor)
                putExtra(OnionVpnService.EXTRA_KILL_SWITCH, true)
                putExtra(OnionVpnService.EXTRA_PROFILE_MODE, VpnProfileMode.Blocking.name)
                putExtra(OnionVpnService.EXTRA_GENERATION, generation)
            },
        )
    }

    fun destroy() {
        context.startService(
            Intent(context, OnionVpnService::class.java).setAction(OnionVpnService.ACTION_DESTROY),
        )
    }

    fun stop() {
        context.startService(
            Intent(context, OnionVpnService::class.java).setAction(OnionVpnService.ACTION_STOP),
        )
    }

    suspend fun waitForBlocking(generation: Int): Boolean {
        repeat(VPN_READY_POLLS) {
            val established = OnionVpnService.vpnEstablished.value
            val genOk = OnionVpnService.vpnGeneration.value == generation
            val modeOk = OnionVpnService.vpnProfileMode.value == VpnProfileMode.Blocking
            val noForwarder = OnionVpnService.hevSocksPort.value < 0
            if (established && genOk && modeOk && noForwarder) return true
            delay(VPN_READY_POLL_MS)
        }
        Timber.e(
            "Blocking VPN wait timeout gen=$generation established=${OnionVpnService.vpnEstablished.value} " +
                "mode=${OnionVpnService.vpnProfileMode.value}",
        )
        return false
    }

    suspend fun waitForConnected(generation: Int, ports: TunnelRuntimePorts): Boolean {
        repeat(VPN_READY_POLLS) {
            val established = OnionVpnService.vpnEstablished.value
            val genOk = OnionVpnService.vpnGeneration.value == generation
            val hevOk = OnionVpnService.hevSocksPort.value == ports.torSocksPort &&
                OnionVpnService.hevDnsCryptPort.value == ports.dnsCryptListenPort
            if (established && genOk && hevOk) return true
            delay(VPN_READY_POLL_MS)
        }
        Timber.e(
            "VPN wait timeout gen=$generation established=${OnionVpnService.vpnEstablished.value} " +
                "activeGen=${OnionVpnService.vpnGeneration.value} " +
                "hevSocks=${OnionVpnService.hevSocksPort.value} hevDns=${OnionVpnService.hevDnsCryptPort.value}",
        )
        return false
    }

    suspend fun waitUntilDown() {
        repeat(VPN_DOWN_POLLS) {
            if (!OnionVpnService.vpnEstablished.value && OnionVpnService.hevSocksPort.value < 0) return
            delay(VPN_READY_POLL_MS)
        }
        Timber.w("VPN still marked established after stop wait")
    }

    fun hevPortsMatch(ports: TunnelRuntimePorts, useDnsCrypt: Boolean): Boolean {
        val hevSocks = OnionVpnService.hevSocksPort.value
        val hevDns = OnionVpnService.hevDnsCryptPort.value
        return hevSocks == ports.torSocksPort &&
            (!useDnsCrypt || hevDns == ports.dnsCryptListenPort)
    }

    companion object {
        private const val VPN_READY_POLL_MS = 250L
        private const val VPN_READY_POLLS = 40
        private const val VPN_DOWN_POLLS = 40
    }
}
