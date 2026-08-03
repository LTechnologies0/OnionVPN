package ltechnologies.onionphone.onionvpn.core.model

/**
 * User-tunable tunnel preferences (Tor / DNSCrypt / firewall / kill-switch).
 *
 * Persisted by app [ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore];
 * applied at Tor/DNSCrypt start and VPN profile establish.
 */
data class TunnelPreferences(
    /**
     * Legacy flag — full default IPv4+IPv6 routes are always applied.
     * Kept for intent/prefs compatibility; UI no longer offers split-tunnel.
     */
    val routeAllTrafficThroughTor: Boolean = true,
    /**
     * App kill-switch is always on (constant). Blocking TUN before bootstrap and on
     * hard validation failure — no user off-switch (Whonix/Mullvad fail-closed).
     * Field kept for prefs/intent compatibility; always treated as true.
     */
    val killSwitchEnabled: Boolean = true,
    val dnsCryptServerName: String = "cloudflare",
    val dnsResolverMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    /**
     * Tor client engine. Default remains [TorEngine.LITTLE_T] until Arti reaches
     * feature parity (multi-SocksPort SessionGroups, classic control plane, PTs).
     * Changing this requires a tunnel restart.
     */
    val torEngine: TorEngine = TorEngine.LITTLE_T,
    val torBridges: String = "",
    val torEntryNodes: String = "",
    val torExitNodes: String = "",
    val torExcludeNodes: String = "",
    val torNewCircuitPeriodSec: Int = 30,
    /** Default 600s (10 min) — Tor man MaxCircuitDirtiness default. */
    val torMaxCircuitDirtinessSec: Int = 600,
    val dnsCryptRequireNoLog: Boolean = true,
    val dnsCryptRequireNoFilter: Boolean = false,
    val dnsCryptForceTcp: Boolean = true,
    /** Prefer DNSCrypt servers advertising DNSSEC in their stamp. */
    val dnsCryptRequireDnssec: Boolean = true,
    /**
     * Anonymized DNSCrypt (relay hop) when the pinned dnscrypt-proxy `.so` supports
     * `[anonymized_dns]` + relays catalog. Adds latency; default off.
     */
    val dnsCryptAnonymized: Boolean = false,
    /**
     * Prefer query padding when the `.so` supports it (privacy draft §8.4).
     * Harmless no-op on builds that ignore the knob.
     */
    val dnsCryptQueryPadding: Boolean = true,
    /** Block EDNS Client Subnet when the `.so` exposes the knob (default on). */
    val dnsCryptBlockEcs: Boolean = true,
    /**
     * When true, Connected establish fails unless Android Always-on VPN lockdown
     * is enabled for OnionVPN ([VpnService.isLockdownEnabled]).
     */
    val requireOsLockdown: Boolean = false,
    /** Interactive OpenSnitch-style firewall on the TUN path. */
    val firewallEnabled: Boolean = false,
    val firewallDefaultAction: FirewallDefaultAction = FirewallDefaultAction.ASK,
    /** Temporary allow/deny TTL in minutes. */
    val firewallTempMinutes: Int = 5,
    /**
     * Gate the UI with the Android device lock (PIN / biometric).
     * Tunnel / kill-switch keep running while locked.
     */
    val appLockEnabled: Boolean = true,
    /** When false, [android.view.WindowManager.LayoutParams.FLAG_SECURE] blocks screenshots. */
    val allowScreenshots: Boolean = false,
    /**
     * When true, opening the app prepares VPN permission (if needed) and starts
     * Tor + DNSCrypt + Connected TUN automatically.
     */
    val autoStartOnAppLaunch: Boolean = true,
    /**
     * When true, [android.content.Intent.ACTION_BOOT_COMPLETED] starts the tunnel
     * if VPN permission was already granted. Default off — user must opt in.
     */
    val autoStartOnBoot: Boolean = false,
    /**
     * When true, Moat / BridgeDB requests to bridges.torproject.org go through
     * Tor SOCKS. When false (default), clearnet HTTPS is used.
     */
    val moatRequestViaTor: Boolean = false,
    /**
     * Privacy kill-switch for diagnostics: when true, TRACE→ERROR pipeline logs,
     * Tor/Arti/DNSCrypt UI buffers, and the resource profiler are disabled.
     * Default when unset: ON for release (non-debuggable), OFF for debug builds
     * (see [ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore]).
     */
    val noLogsEnabled: Boolean = true,
    /**
     * Per-app VPN routing (Orbot). [VpnAppRoutingMode.ALL] = full tunnel.
     * Changing this requires VPN rebind (restart tunnel).
     */
    val vpnAppRoutingMode: VpnAppRoutingMode = VpnAppRoutingMode.ALL,
    /**
     * Package names for [VpnAppRoutingMode.INCLUDE] / [EXCLUDE].
     * Ignored when mode is [VpnAppRoutingMode.ALL]. Own package is never routed.
     */
    val vpnAppPackages: Set<String> = emptySet(),
    /**
     * When true, wireless ADB (`com.android.shell` / `adbd`) is excluded from the
     * VPN so network ADB can use clearnet. **Default false (fail-closed)** — ADB
     * must not bypass the tunnel unless the user opts in. USB ADB is unaffected.
     * Changing this requires VPN rebind (restart tunnel).
     */
    val allowAdbClearnetLeak: Boolean = false,
    /**
     * TUN forwarder stack. [TunDataPlane.ONIONMASQ] is forced when
     * [TorEngine.ARTI] and native onionmasq are present; otherwise HEV.
     */
    val tunDataPlane: TunDataPlane = TunDataPlane.HEV_SOCKS,
)
