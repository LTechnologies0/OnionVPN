package ltechnologies.onionphone.onionvpn.core.vpn.profile

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
import timber.log.Timber

/**
 * Builds fail-closed VPN profiles (Mullvad + InviZible + Orbot):
 *
 * - Full-tunnel IPv4 (`0.0.0.0/0`) and IPv6 (`::/0`) — always (no route split)
 * - Per-app allow/deny via [VpnAppRoutingMode] (Orbot); never mixes both lists
 * - Never [VpnService.Builder.allowFamily] without relying on it for capture: dual-stack
 *   addresses+routes already claim both families (allowFamily alone can fall through
 *   to clearnet — Android VpnService docs / anti-leak skill)
 * - Self-excluded so Tor/DNSCrypt/hev loopback is not re-captured
 * - Public DNS /32 routes pinned into tunnel
 * - Never [VpnService.Builder.allowBypass]
 * - Connected: [VpnService.Builder.setUnderlyingNetworks] `emptyArray()` fail-closed until
 *   [UnderlyingNetworkTracker] publishes a real `NOT_VPN` uplink (`null` ≠ empty)
 * - [setBlocking] only in [VpnProfileMode.Blocking]: drop unread TUN packets (unroutable).
 *   Connected mode keeps [setBlocking] false so hev can drain Tor-routable streams.
 * - [setConfigureIntent] so Always-on VPN settings open the app (InviZible/Mullvad)
 *
 * **INCLUDE × Android lockdown:** Builder cannot mix [addAllowedApplication] with
 * [addDisallowedApplication]. Under OS lockdown, apps omitted from an INCLUDE allow-list
 * get **no network** (Tor Browser offline) — Tor-over-Tor if forced onto the allow-list.
 * [includeConflictsWithLockdown] + OnionVpnService refuse Connected establish instead of
 * copying Orbot #774 (skip BYPASS in lockdown).
 */
object VpnProfileBuilder {
    const val SESSION_NAME = "OnionVPN"

    /**
     * INCLUDE with a non-empty allow-list cannot honestly BYPASS Tor-native apps under
     * Android Always-on lockdown (mutual exclusion on Builder lists).
     */
    fun includeConflictsWithLockdown(
        preferences: TunnelPreferences,
        lockdownEnabled: Boolean,
    ): Boolean {
        if (!lockdownEnabled) return false
        if (preferences.vpnAppRoutingMode != VpnAppRoutingMode.INCLUDE) return false
        return preferences.vpnAppPackages.any { it.isNotBlank() }
    }

    const val INCLUDE_LOCKDOWN_BLOCK_REASON =
        "INCLUDE per-app mode conflicts with Android VPN lockdown — " +
            "switch to ALL/EXCLUDE or disable lockdown (Tor-native BYPASS cannot use clearnet under lockdown)"

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

        // Dual-stack DNS: Android may query AAAA path to VPN DNS ULA.
        if (mode == VpnProfileMode.Connected) {
            runCatching { builder.addDnsServer(TunnelEndpoints.VPN_DNS_ADDRESS_V6) }
                .onFailure { Timber.w(it, "Skip VPN DNS v6 ${TunnelEndpoints.VPN_DNS_ADDRESS_V6}") }
        }

        BLOCKED_PUBLIC_DNS.forEach { resolver ->
            // IPv6 literals need prefix length 128; IPv4 /32.
            val prefix = if (resolver.contains(':')) 128 else 32
            runCatching { builder.addRoute(resolver, prefix) }
                .onFailure { Timber.w(it, "Skip DNS pin route $resolver") }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        // Pre-establish uplink bind (API 22+): empty = no carrier until tracker selects
        // NOT_VPN. Service.setUnderlyingNetworks only works after establish(); null would
        // mean system default (not fail-closed).
        if (mode == VpnProfileMode.Connected &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1
        ) {
            builder.setUnderlyingNetworks(emptyArray())
        }

        builder.setConfigureIntent(configurePendingIntent(service))
        applyAppRouting(service, builder, preferences)

        return builder
    }

    /**
     * Orbot-style app filter. Own package is never on the VPN (uplink loop).
     * INCLUDE with empty list → treat as ALL (fail open to full tunnel, not zero apps).
     *
     * Tor-native BYPASS packages: ALL/EXCLUDE/INCLUDE-empty use [addDisallowedApplication]
     * (Orbot, signature-pinned). INCLUDE non-empty omits them from the allow-list only —
     * Android forbids mixing allow + disallow on the same Builder. Callers must refuse
     * Connected when [includeConflictsWithLockdown] (lockdown + INCLUDE non-empty).
     */
    private fun applyAppRouting(
        service: VpnService,
        builder: VpnService.Builder,
        preferences: TunnelPreferences,
    ) {
        val own = service.packageName
        val packages = preferences.vpnAppPackages.filter { it.isNotBlank() && it != own }.toSet()
        when (preferences.vpnAppRoutingMode) {
            VpnAppRoutingMode.INCLUDE -> {
                if (packages.isEmpty()) {
                    Timber.w("INCLUDE list empty — falling back to ALL (+ self-exclude + BYPASS)")
                    excludeOwnPackage(service, builder)
                    disallowTorNativeBypass(service, builder)
                    return
                }
                // Under lockdown this path is unreachable (establish hard-gates first).
                // Omit BYPASS from allow-list (clearnet / own Tor) — do not also disallow.
                packages.filterNot { TorNativeAppUids.isBypassPackage(it) }.forEach { pkg ->
                    runCatching { builder.addAllowedApplication(pkg) }
                        .onFailure { Timber.w(it, "Skip allow VPN for $pkg") }
                }
                // Own package omitted from allow-list ⇒ not captured (no addDisallowed needed).
            }
            VpnAppRoutingMode.EXCLUDE -> {
                excludeOwnPackage(service, builder)
                disallowTorNativeBypass(service, builder)
                packages.filterNot { TorNativeAppUids.isBypassPackage(it) }.forEach { pkg ->
                    runCatching { builder.addDisallowedApplication(pkg) }
                        .onFailure { Timber.w(it, "Skip disallow VPN for $pkg") }
                }
            }
            VpnAppRoutingMode.ALL -> {
                excludeOwnPackage(service, builder)
                disallowTorNativeBypass(service, builder)
            }
        }
    }

    /** Orbot BYPASS_VPN_PACKAGES — Tor-over-Tor prevention on hev and all planes. */
    private fun disallowTorNativeBypass(service: VpnService, builder: VpnService.Builder) {
        TorNativeAppUids.installedBypassPackages(service).forEach { pkg ->
            runCatching { builder.addDisallowedApplication(pkg) }
                .onFailure { Timber.w(it, "Skip disallow Tor-native BYPASS for $pkg") }
        }
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
