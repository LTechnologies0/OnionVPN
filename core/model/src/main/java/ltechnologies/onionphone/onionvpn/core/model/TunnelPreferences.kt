package ltechnologies.onionphone.onionvpn.core.model

/**
 * User-tunable tunnel preferences (Tor / DNSCrypt / firewall / kill-switch).
 *
 * Persisted by app [ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore];
 * applied at Tor/DNSCrypt start and VPN profile establish.
 */
data class TunnelPreferences(
    /**
     * Legacy flag — full default routes + allowFamily are always applied.
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
    val torBridges: String = "",
    val torEntryNodes: String = "",
    val torExitNodes: String = "",
    val torExcludeNodes: String = "",
    val torNewCircuitPeriodSec: Int = 180,
    /** Default 600s (10 min) — closer to Tor Browser stability than aggressive rotation. */
    val torMaxCircuitDirtinessSec: Int = 600,
    val dnsCryptRequireNoLog: Boolean = true,
    val dnsCryptRequireNoFilter: Boolean = false,
    val dnsCryptForceTcp: Boolean = true,
    /** Prefer DNSCrypt servers advertising DNSSEC in their stamp. */
    val dnsCryptRequireDnssec: Boolean = true,
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
)
