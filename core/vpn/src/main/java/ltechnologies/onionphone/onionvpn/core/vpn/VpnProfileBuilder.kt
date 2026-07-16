package ltechnologies.onionphone.onionvpn.core.vpn

import android.net.VpnService
import android.os.Build
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import timber.log.Timber

/**
 * Builds fail-closed VPN profiles (Mullvad + InviZible patterns):
 *
 * - Full-tunnel IPv4 routes; IPv6 omitted until end-to-end stack supports it (all-or-nothing rule).
 * - App self-excluded so Tor/DNSCrypt/hev loopback is not re-captured by the TUN.
 * - Public DNS /32 routes pinned into tunnel (defense-in-depth).
 * - [VpnProfileMode.Connected]: DNS → local DNSCrypt stub.
 * - [VpnProfileMode.Blocking]: dummy DNS [TunnelEndpoints.FALLBACK_BLOCKING_DNS], no forwarder.
 */
object VpnProfileBuilder {
    const val SESSION_NAME = "OnionVPN"

    val BLOCKED_PUBLIC_DNS = listOf(
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "1.0.0.1",
        "9.9.9.9",
        "149.112.112.112",
        "94.140.14.14",
        "94.140.15.15",
    )

    fun configure(
        service: VpnService,
        preferences: TunnelPreferences,
        mode: VpnProfileMode = VpnProfileMode.Connected,
        sessionName: String = SESSION_NAME,
    ): VpnService.Builder {
        val dnsServer = when (mode) {
            VpnProfileMode.Connected -> TunnelEndpoints.VPN_DNS_ADDRESS
            VpnProfileMode.Blocking -> TunnelEndpoints.FALLBACK_BLOCKING_DNS
        }

        val builder = service.Builder()
            .setSession(sessionName)
            .setMtu(TunnelEndpoints.VPN_MTU)
            .addAddress(TunnelEndpoints.VPN_CLIENT_ADDRESS, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(dnsServer)
            // Mullvad: blocking states keep routes, Connected uses non-blocking TUN for hev.
            .setBlocking(mode == VpnProfileMode.Blocking && preferences.killSwitchEnabled)

        BLOCKED_PUBLIC_DNS.forEach { resolver ->
            builder.addRoute(resolver, 32)
        }

        if (preferences.routeAllTrafficThroughTor) {
            builder.allowFamily(android.system.OsConstants.AF_INET)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        excludeOwnPackage(service, builder)

        return builder
    }

    /**
     * InviZible pattern: Tor/DNSCrypt/hev run in-process on loopback and must bypass the TUN.
     */
    private fun excludeOwnPackage(service: VpnService, builder: VpnService.Builder) {
        runCatching {
            builder.addDisallowedApplication(service.packageName)
        }.onFailure { error ->
            Timber.w(error, "Could not exclude own package from VPN")
        }
    }
}

interface TunForwarder {
    fun start(tunFd: android.os.ParcelFileDescriptor, socksHost: String, socksPort: Int, dnsCryptPort: Int)
    fun stop()
}
