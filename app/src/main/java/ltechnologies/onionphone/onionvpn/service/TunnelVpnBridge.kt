package ltechnologies.onionphone.onionvpn.service

import android.content.Context
import android.content.Intent
import kotlinx.coroutines.delay
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.dns.OnionAutomapAllocator
import ltechnologies.onionphone.onionvpn.ui.settings.TorCountryCatalog
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
                putExtra(OnionVpnService.EXTRA_KILL_SWITCH, true)
                putExtra(OnionVpnService.EXTRA_PROFILE_MODE, VpnProfileMode.Connected.name)
                putExtra(OnionVpnService.EXTRA_TOR_SOCKS_PORT, ports.torSocksPort)
                putExtra(OnionVpnService.EXTRA_DNSCRYPT_PORT, ports.dnsCryptListenPort)
                putExtra(OnionVpnService.EXTRA_TOR_DNS_PORT, ports.torDnsPort)
                putExtra(
                    OnionVpnService.EXTRA_SYNTHESIZE_ONION_AUTOMAP,
                    preferences.torEngine.capabilities.synthesizeOnionAutomap,
                )
                putExtra(OnionVpnService.EXTRA_GENERATION, generation)
                putExtra(OnionVpnService.EXTRA_DNS_MODE, preferences.dnsResolverMode.name)
                putExtra(OnionVpnService.EXTRA_VPN_APP_MODE, preferences.vpnAppRoutingMode.name)
                putExtra(
                    OnionVpnService.EXTRA_VPN_APP_PACKAGES,
                    preferences.vpnAppPackages.toTypedArray(),
                )
                putExtra(
                    OnionVpnService.EXTRA_ALLOW_ADB_CLEARNET_LEAK,
                    preferences.allowAdbClearnetLeak,
                )
                putExtra(
                    OnionVpnService.EXTRA_REQUIRE_OS_LOCKDOWN,
                    preferences.requireOsLockdown,
                )
                putExtra(OnionVpnService.EXTRA_TUN_DATA_PLANE, preferences.tunDataPlane.name)
                putExtra(OnionVpnService.EXTRA_TOR_ENGINE, preferences.torEngine.name)
                putExtra(OnionVpnService.EXTRA_BRIDGE_LINES, preferences.torBridges)
                // onionmasq setCountryCode: one ISO country (Arti ExitNodes semantics).
                val exitCodes = TorCountryCatalog.parseNodeCodes(preferences.torExitNodes)
                when {
                    exitCodes.size == 1 ->
                        putExtra(OnionVpnService.EXTRA_EXIT_COUNTRY, exitCodes.first().uppercase())
                    exitCodes.size > 1 -> {
                        val first = exitCodes.first()
                        Timber.w(
                            "Multiple ExitNodes (%d); onionmasq applies first only {%s}",
                            exitCodes.size,
                            first,
                        )
                        putExtra(OnionVpnService.EXTRA_EXIT_COUNTRY, first.uppercase())
                    }
                }
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
                putExtra(OnionVpnService.EXTRA_VPN_APP_MODE, preferences.vpnAppRoutingMode.name)
                putExtra(
                    OnionVpnService.EXTRA_VPN_APP_PACKAGES,
                    preferences.vpnAppPackages.toTypedArray(),
                )
                putExtra(
                    OnionVpnService.EXTRA_ALLOW_ADB_CLEARNET_LEAK,
                    preferences.allowAdbClearnetLeak,
                )
            },
        )
    }

    fun destroy() {
        OnionAutomapAllocator.clear()
        DnsHostnameCache.clear()
        // Same-process stop — startService(DESTROY) raced Always-On and left TunDnsMux alive.
        OnionVpnService.teardownInProcess(destroyService = true)
    }

    fun stop() {
        OnionAutomapAllocator.clear()
        DnsHostnameCache.clear()
        OnionVpnService.teardownInProcess(destroyService = false)
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

    suspend fun waitForConnected(
        generation: Int,
        ports: TunnelRuntimePorts,
        useDnsCrypt: Boolean = true,
    ): Boolean {
        repeat(VPN_READY_POLLS) {
            val established = OnionVpnService.vpnEstablished.value
            val genOk = OnionVpnService.vpnGeneration.value == generation
            if (established && genOk && hevPortsMatch(ports, useDnsCrypt)) return true
            delay(VPN_READY_POLL_MS)
        }
        Timber.e(
            "VPN wait timeout gen=$generation established=${OnionVpnService.vpnEstablished.value} " +
                "activeGen=${OnionVpnService.vpnGeneration.value} " +
                "socks=${OnionVpnService.hevSocksPort.value} dns=${OnionVpnService.hevDnsCryptPort.value} " +
                "plane=${OnionVpnService.vpnDataPlane.value}",
        )
        return false
    }

    suspend fun waitUntilDown() {
        repeat(VPN_DOWN_POLLS) {
            val down = !OnionVpnService.vpnEstablished.value &&
                OnionVpnService.hevSocksPort.value < 0 &&
                !OnionVpnService.tunForwarderAlive.value
            if (down) return
            delay(VPN_READY_POLL_MS)
        }
        Timber.w(
            "VPN still marked up after stop wait established=%s socks=%s forwarderAlive=%s",
            OnionVpnService.vpnEstablished.value,
            OnionVpnService.hevSocksPort.value,
            OnionVpnService.tunForwarderAlive.value,
        )
    }

    fun hevPortsMatch(ports: TunnelRuntimePorts, useDnsCrypt: Boolean): Boolean {
        val hevSocks = OnionVpnService.hevSocksPort.value
        val hevDns = OnionVpnService.hevDnsCryptPort.value
        return hevSocks == ports.torSocksPort &&
            (!useDnsCrypt || hevDns == ports.dnsCryptListenPort)
    }

    companion object {
        private const val VPN_READY_POLL_MS = 250L
        /** 40×250ms was tight after Private Space unlock (double Blocking establish). */
        private const val VPN_READY_POLLS = 80
        private const val VPN_DOWN_POLLS = 40
    }
}
