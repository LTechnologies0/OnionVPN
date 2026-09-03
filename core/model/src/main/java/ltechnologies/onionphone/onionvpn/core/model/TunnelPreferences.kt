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
     * DataStore default: ON for release, OFF for debug
     * (see [ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore]).
     */
    val requireOsLockdown: Boolean = true,
    /**
     * Interactive OpenSnitch-style firewall on the TUN path.
     * DataStore default: ON for release, OFF for debug.
     */
    val firewallEnabled: Boolean = true,
    val firewallDefaultAction: FirewallDefaultAction = FirewallDefaultAction.ASK,
    /** Temporary allow/deny TTL in minutes. */
    val firewallTempMinutes: Int = 5,
    /**
     * Gate the UI with the Android device lock (PIN / biometric).
     * Tunnel / kill-switch keep running while locked.
     * DataStore default: ON for release, OFF for debug.
     */
    val appLockEnabled: Boolean = true,
    /** When false, [android.view.WindowManager.LayoutParams.FLAG_SECURE] blocks screenshots. */
    val allowScreenshots: Boolean = false,
    /**
     * When true, opening the app prepares VPN permission (if needed) and starts
     * Tor + DNSCrypt + Connected TUN automatically.
     * DataStore default: ON for release, OFF for debug.
     */
    val autoStartOnAppLaunch: Boolean = true,
    /**
     * When true, [android.content.Intent.ACTION_BOOT_COMPLETED] starts the tunnel
     * if VPN permission was already granted.
     * DataStore default: ON for release, OFF for debug.
     */
    val autoStartOnBoot: Boolean = true,
    /**
     * When true, Moat / BridgeDB requests to bridges.torproject.org go through
     * Tor SOCKS (default — avoids clearnet TLS MitM of bridge fetch). When false,
     * clearnet HTTPS is used (local MitM risk if a hostile CA is trusted).
     */
    val moatRequestViaTor: Boolean = true,
    /**
     * Privacy kill-switch for diagnostics: when true, TRACE→ERROR pipeline logs,
     * Tor/Arti/DNSCrypt UI buffers, and the resource profiler are disabled.
     * DataStore default: ON for release, OFF for debug.
     */
    val noLogsEnabled: Boolean = true,
    /**
     * Per-app VPN routing (Orbot). [VpnAppRoutingMode.ALL] = full tunnel.
     * DataStore default: ALL for release; EXCLUDE for debug (not “All apps” chip).
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
     * VPN so network ADB can use clearnet. **Forced false in release** (option hidden).
     * Debug DataStore default: true. USB ADB is unaffected.
     * Changing this requires VPN rebind (restart tunnel).
     */
    val allowAdbClearnetLeak: Boolean = false,
    /**
     * TUN forwarder stack. Arti defaults to [TunDataPlane.ONIONMASQ] when the native
     * library is present (Settings); [TunDataPlane.HEV_SOCKS] remains selectable for
     * Arti+arti-mobile. C Tor always uses HEV.
     */
    val tunDataPlane: TunDataPlane = TunDataPlane.HEV_SOCKS,
    /**
     * Optional OpenVPN-over-Tor: TCP OpenVPN client reaches the VPN server via
     * Tor SOCKS so destinations see the VPN egress IP (not a Tor exit).
     * Requires an imported `.ovpn` profile and a tunnel restart.
     */
    val openVpnOverTorEnabled: Boolean = false,
    /**
     * True when a profile was imported into app-private storage
     * (`files/openvpn/profile.ovpn`). Content is not held in prefs.
     */
    val openVpnProfileConfigured: Boolean = false,
    /**
     * Optional OpenVPN `auth-user-pass` credentials (Settings and/or extracted from
     * an inline `<auth-user-pass>` block at import). Empty = no auth file;
     * management Auth prompts get empty replies (cert-only / soft reconnect).
     */
    val openVpnAuthUser: String = "",
    val openVpnAuthPassword: String = "",
    /**
     * First-launch welcome dialog dismissed. False until the user taps Got it
     * (or re-opens tips from Settings). Release auto-start waits for this.
     */
    val welcomeCompleted: Boolean = false,
)
