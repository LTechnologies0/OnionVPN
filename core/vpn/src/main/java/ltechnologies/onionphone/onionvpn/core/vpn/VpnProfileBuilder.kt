package ltechnologies.onionphone.onionvpn.core.vpn

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
 * - Full-tunnel IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`)
 * - Self-excluded so Tor/DNSCrypt/hev loopback is not re-captured
 * - Public DNS /32 routes pinned into tunnel
 * - Never [VpnService.Builder.allowBypass]
 * - [setConfigureIntent] so Always-on VPN settings open the app (InviZible/Mullvad)
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
            .addAddress(TunnelEndpoints.VPN_CLIENT_ADDRESS_V6, 128)
            .addRoute("::", 0)
            .addDnsServer(dnsServer)
            .setBlocking(mode == VpnProfileMode.Blocking && preferences.killSwitchEnabled)

        BLOCKED_PUBLIC_DNS.forEach { resolver ->
            builder.addRoute(resolver, 32)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
            if (preferences.routeAllTrafficThroughTor) {
                builder.allowFamily(OsConstants.AF_INET)
                builder.allowFamily(OsConstants.AF_INET6)
            }
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

interface TunForwarder {
    fun start(tunFd: android.os.ParcelFileDescriptor, socksHost: String, socksPort: Int, dnsCryptPort: Int)
    fun stop()
}
