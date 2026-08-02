package ltechnologies.onionphone.onionvpn.core.model

/**
 * Orbot-style per-app VPN routing via [android.net.VpnService.Builder]
 * [addAllowedApplication] / [addDisallowedApplication].
 *
 * Mutual exclusion: Android forbids mixing allow-list and deny-list on one Builder.
 * Own package is always kept off the VPN (Tor/DNSCrypt/hev uplink).
 */
enum class VpnAppRoutingMode {
    /** Every app except OnionVPN itself (default fail-closed full tunnel). */
    ALL,

    /** Only [TunnelPreferences.vpnAppPackages] use the VPN; others clearnet. */
    INCLUDE,

    /** [TunnelPreferences.vpnAppPackages] bypass VPN; everyone else Tor. */
    EXCLUDE,
}

/**
 * TUN data plane implementation.
 *
 * - [HEV_SOCKS]: Orbot-class hev-socks5-tunnel → SocksUidBridge → Tor SOCKS (shipped).
 * - [ONIONMASQ]: Tor Project onionmasq (smoltcp → Arti). Requires native lib + Arti engine;
 *   not bundled until jniLibs ship `libonionmasq.so` — selection fails closed to HEV.
 */
enum class TunDataPlane {
    HEV_SOCKS,
    ONIONMASQ,
    ;

    companion object {
        fun fromPreference(raw: String?): TunDataPlane =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: HEV_SOCKS
    }
}
