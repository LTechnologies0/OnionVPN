package ltechnologies.onionphone.onionvpn.core.vpn.profile

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.system.OsConstants
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import timber.log.Timber

/**
 * Builds fail-closed VPN profiles (Mullvad + InviZible + Orbot):
 *
 * - Full-tunnel IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) — always; split-tunnel is refused
 * - [allowFamily] IPv4+IPv6 on API 29+ — always (TunnelPreferences.routeAllTrafficThroughTor
 *   is forced true; the preference is a legacy no-op for routes)
 * - Self-excluded so Tor/DNSCrypt/hev loopback is not re-captured
 * - Public DNS /32 routes pinned into tunnel
 * - Never [VpnService.Builder.allowBypass]
 * - [setBlocking] only in [VpnProfileMode.Blocking]: drop unread TUN packets (unroutable).
 *   Connected mode keeps [setBlocking] false so hev can drain Tor-routable streams.
 * - [setConfigureIntent] so Always-on VPN settings open the app (InviZible/Mullvad)
 */
object VpnProfileBuilder {
    const val SESSION_NAME = "OnionVPN"

    val BLOCKED_PUBLIC_DNS = listOf(
        // Google
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844",
        // Cloudflare (+ common DoH anycast)
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.2",
        "1.0.0.2",
        "1.1.1.3",
        "1.0.0.3",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2606:4700:4700::1112",
        "2606:4700:4700::1002",
        // Quad9
        "9.9.9.9",
        "149.112.112.112",
        "9.9.9.10",
        "149.112.112.10",
        "2620:fe::fe",
        "2620:fe::9",
        // AdGuard
        "94.140.14.14",
        "94.140.15.15",
        "94.140.14.15",
        "94.140.15.16",
        // OpenDNS
        "208.67.222.222",
        "208.67.220.220",
        // CleanBrowsing / Comodo / Level3
        "185.228.168.9",
        "185.228.169.9",
        "8.26.56.26",
        "8.20.247.20",
        "4.2.2.1",
        "4.2.2.2",
        // Mullvad / NextDNS / Control D (common DoH/DoT)
        "194.242.2.2",
        "194.242.2.3",
        "45.90.28.0",
        "45.90.30.0",
        "76.76.2.0",
        "76.76.10.0",
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
            .addAddress(TunnelEndpoints.VPN_CLIENT_ADDRESS_V6, 128)
            .addRoute("::", 0)
            .addDnsServer(dnsServer)
            .setBlocking(mode == VpnProfileMode.Blocking)

        BLOCKED_PUBLIC_DNS.forEach { resolver ->
            // IPv6 literals need prefix length 128; IPv4 /32.
            val prefix = if (resolver.contains(':')) 128 else 32
            runCatching { builder.addRoute(resolver, prefix) }
                .onFailure { Timber.w(it, "Skip DNS pin route $resolver") }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            // Always claim both families — apps must not fall back to clearnet IPv6/IPv4.
            builder.allowFamily(OsConstants.AF_INET)
            builder.allowFamily(OsConstants.AF_INET6)
        }

        builder.setConfigureIntent(configurePendingIntent(service))
        excludeOwnPackage(service, builder)

        return builder
    }

    /** InviZible/Mullvad: gear icon in system VPN settings opens the app. */
    private fun configurePendingIntent(service: VpnService): PendingIntent {
        val intent = Intent().setClassName(
            service.packageName,
            "ltechnologies.onionphone.onionvpn.MainActivity",
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                PendingIntent.FLAG_IMMUTABLE
            } else {
                0
            }
        return PendingIntent.getActivity(service, 0, intent, flags)
    }

    private fun excludeOwnPackage(service: VpnService, builder: VpnService.Builder) {
        try {
            builder.addDisallowedApplication(service.packageName)
        } catch (error: Exception) {
            Timber.e(error, "Could not exclude own package from VPN")
            throw IllegalStateException(
                "VPN self-exclusion failed — refusing to establish (Tor would loop into TUN)",
                error,
            )
        }
    }
}
