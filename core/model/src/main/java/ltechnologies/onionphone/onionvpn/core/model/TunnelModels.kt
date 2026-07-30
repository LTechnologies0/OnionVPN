package ltechnologies.onionphone.onionvpn.core.model

/**
 * Loopback endpoints shared by Tor, DNSCrypt, and the VPN interface.
 *
 * Architecture (Tor spec + InviZible + Mullvad):
 * Runtime ports are allocated per session via [TunnelPortAllocator] to avoid conflicts.
 * Defaults below are fallbacks for tests and documentation only.
 */
object TunnelEndpoints {
    const val LOOPBACK = "127.0.0.1"

    const val DEFAULT_TOR_SOCKS_PORT = 9050
    const val DEFAULT_TOR_DNS_PORT = 9053
    const val DEFAULT_DNSCRYPT_LISTEN_PORT = 5354

    const val TOR_SOCKS_PORT = DEFAULT_TOR_SOCKS_PORT
    const val TOR_DNS_PORT = DEFAULT_TOR_DNS_PORT
    const val DNSCRYPT_LISTEN_PORT = DEFAULT_DNSCRYPT_LISTEN_PORT

    const val VPN_CLIENT_ADDRESS = "10.8.0.2"
    const val VPN_DNS_ADDRESS = "10.8.0.1"

    /**
     * ULA IPv6 TUN address (Orbot/InviZible pattern).
     * Captures IPv6 into the TUN so it cannot leak clearnet; hev blackholes or
     * forwards over Tor SOCKS — never leaves via Wi‑Fi/cellular.
     */
    const val VPN_CLIENT_ADDRESS_V6 = "fd00:8:8:8::2"

    /** Fake-IP pool for hev mapdns (must not overlap VPN 10.8.0.0/24). */
    const val FAKE_DNS_NETWORK = "100.64.0.0"
    const val FAKE_DNS_NETMASK = "255.192.0.0"
    const val FAKE_DNS_CACHE_SIZE = 4096

    /**
     * Tor AutomapHostsOnResolve virtual IPv4 pool (`VirtualAddrNetwork 10.192.0.0/10`).
     * Apps receive these as A records for `.onion` / `.exit`; TCP must SOCKS5A the hostname.
     */
    const val VIRTUAL_ADDR_NETWORK = "10.192.0.0"
    const val VIRTUAL_ADDR_PREFIX_LEN = 10

    /** Mullvad-style dummy DNS when no resolver is available (RFC 5737 TEST-NET-1). */
    const val FALLBACK_BLOCKING_DNS = "192.0.2.1"

    /**
     * True for Tor Automap virtual IPv4 (`10.192.0.0/10` → `10.192.0.0`–`10.255.255.255`).
     * These must never be SOCKS CONNECT'd as literal IPs (no exit path).
     */
    fun isAutomapVirtualIpv4(hostAddress: String): Boolean {
        val ip = parseIpv4Literal(hostAddress) ?: return false
        return isAutomapVirtualIpv4(ip)
    }

    /** Bitmask check for Tor Automap `10.192.0.0/10` (no String alloc). */
    fun isAutomapVirtualIpv4(ipInt: Int): Boolean {
        val a = (ipInt ushr 24) and 0xff
        val b = (ipInt ushr 16) and 0xff
        return a == 10 && b in 192..255
    }

    fun parseIpv4Literal(hostAddress: String): Int? {
        var a = -1
        var b = -1
        var c = -1
        var d = -1
        var cur = 0
        var dots = 0
        for (ch in hostAddress) {
            when (ch) {
                '.' -> {
                    when (dots) {
                        0 -> a = cur
                        1 -> b = cur
                        2 -> c = cur
                        else -> return null
                    }
                    cur = 0
                    dots++
                }
                in '0'..'9' -> {
                    cur = cur * 10 + (ch - '0')
                    if (cur > 255) return null
                }
                else -> return null
            }
        }
        if (dots != 3) return null
        d = cur
        if (a < 0 || b < 0 || c < 0 || d < 0) return null
        return (a shl 24) or (b shl 16) or (c shl 8) or d
    }

    /** Tor special hostnames that must use DNSPort Automap + SOCKS5A, never DNSCrypt. */
    fun isOnionLikeHostname(hostname: String): Boolean {
        val h = hostname.trim().trimEnd('.').lowercase()
        return h.endsWith(".onion") || h.endsWith(".exit")
    }

    const val VPN_MTU = 1280

    /**
     * SOCKS5 credentials helpers for per-app IsolateSOCKSAuth (path-spec strong tokens).
     * username = u{uid}, password = p{uid}. Unknown UID uses a dedicated token.
     */
    const val SOCKS_UNKNOWN_USER = "uunknown"
    const val SOCKS_UNKNOWN_PASS = "punknown"

    /** @deprecated Static hev token — replaced by [socksUserForUid] / [socksPassForUid]. */
    const val SOCKS_ISOLATION_USER = "onionvpn"
    const val SOCKS_ISOLATION_PASS = "stream"

    fun socksUserForUid(uid: Int): String =
        if (uid < 0) SOCKS_UNKNOWN_USER else "u$uid"

    fun socksPassForUid(uid: Int): String =
        if (uid < 0) SOCKS_UNKNOWN_PASS else "p$uid"

    fun uidFromSocksUser(user: String): Int? {
        if (user == SOCKS_UNKNOWN_USER) return -1
        if (!user.startsWith("u")) return null
        return user.removePrefix("u").toIntOrNull()
    }

    /**
     * SOCKS5 credentials for DNSCrypt → separate SocksPort + IsolateSOCKSAuth
     * (Whonix: DNS resolver traffic must not share circuits with apps).
     */
    const val SOCKS_DNSCRYPT_USER = "dnscrypt"
    const val SOCKS_DNSCRYPT_PASS = "resolver"

    /** SOCKS auth for validation probes (SessionGroup_PROBE SocksPort). */
    const val SOCKS_PROBE_USER = "probe"
    const val SOCKS_PROBE_PASS = "check"

    /** Tor SessionGroup IDs — distinct families never share circuits (proposal 171). */
    const val SESSION_GROUP_APPS = 1
    const val SESSION_GROUP_DNS = 2
    const val SESSION_GROUP_DNSCRYPT = 3
    const val SESSION_GROUP_PROBE = 4

    /**
     * Stable PAC HTTP listen port (URL does not change across sessions).
     * Body of `/onionvpn.pac` always reflects the current ephemeral SocksPort /
     * HTTPTunnelPort (RFC 1928 SOCKS5 + Tor HTTP CONNECT).
     */
    const val PAC_LISTEN_PORT = 18_201
    const val PAC_PATH = "/onionvpn.pac"
    /** Fixed SOCKS5 listen for PAC clients — resolves via DNSCrypt, then Tor by IP. */
    const val PAC_BRIDGE_SOCKS_PORT = 18_202

    /** IsolateSOCKSAuth token for PAC bridge → Tor apps SocksPort. */
    const val SOCKS_PAC_USER = "pac"
    const val SOCKS_PAC_PASS = "dnscrypt"

    /**
     * Local SOCKS5 in front of Tor apps SocksPort: hev → [SocksUidBridge] → Tor `u{uid}`.
     * Fixed port so hev yaml stays simple across sessions.
     */
    const val SOCKS_UID_BRIDGE_PORT = 18_203

    fun pacUrl(): String = "http://$LOOPBACK:$PAC_LISTEN_PORT$PAC_PATH"

    fun pacSocksBridge(): String = "$LOOPBACK:$PAC_BRIDGE_SOCKS_PORT"
}

/**
 * How app DNS is resolved while the VPN is up.
 *
 * Both modes divert VPN DNS (UDP/53) to DNSCrypt whose upstream is Tor SOCKS
 * (no clearnet stub resolver). [FAKE_IP_SOCKS5A] is a legacy preference key —
 * hev mapdns FakeDNS is no longer in the data plane.
 */
enum class DnsResolverMode {
    DNSCRYPT_MUX,
    FAKE_IP_SOCKS5A,
}

/**
 * VPN profile applied by [ltechnologies.onionphone.onionvpn.core.vpn.profile.VpnProfileBuilder].
 *
 * - [Connected]: DNS → DNSCrypt stub, hev-socks5 forwards to Tor SOCKS.
 * - [Blocking]: dummy DNS, TUN kept up, forwarder stopped — kill switch (Mullvad error state).
 */
enum class VpnProfileMode {
    Connected,
    Blocking,
}

enum class TunnelPhase {
    Idle,
    StartingTor,
    StartingDnsCrypt,
    StartingVpn,
    Validating,
    Connected,
    /** Kill switch active after failure — TUN up, traffic dropped (Mullvad blocking_config). */
    Blocking,
    Stopping,
    Error,
}

enum class ValidationStatus {
    Pass,
    Fail,
    Skipped,
}

data class ValidationCheck(
    val id: String,
    val label: String,
    val status: ValidationStatus,
    val detail: String,
    /**
     * If false, advisory only (UI / logs) — never tear down Tor-routed traffic.
     * If true, still filtered by [ltechnologies.onionphone.onionvpn.core.validation.TunnelValidator.isHardKillSwitchFailure]
     * so flaky probes cannot blackhole a working Tor path.
     */
    val tripsKillSwitch: Boolean = true,
)

data class TunnelSnapshot(
    val phase: TunnelPhase = TunnelPhase.Idle,
    val killSwitchEnabled: Boolean = true,
    val torRunning: Boolean = false,
    val dnsCryptRunning: Boolean = false,
    val vpnEstablished: Boolean = false,
    val validations: List<ValidationCheck> = emptyList(),
    val lastError: String? = null,
    /**
     * Live Tor bandwidth text — aggregate across **all circuits**
     * (traffic/read|written deltas, then BW events, then UID TrafficStats).
     */
    val throughputText: String = "",
    /** Tor control-spec bootstrap 0–100. */
    val torBootstrapProgress: Int = 0,
    val torBootstrapSummary: String = "",
    val torControlConnected: Boolean = false,
    val torBuiltCircuits: Int = 0,
    val torCircuitEstablished: Boolean = false,
    val torVersion: String = "",
    val torStreamCount: Int = 0,
    val torNetworkLive: Boolean = false,
    val torDormant: Boolean = false,
    val torEntryGuards: String = "",
    val torLastCircEvent: String = "",
    /** Stable PAC URL while tunnel is up (`http://127.0.0.1:18201/onionvpn.pac`). */
    val pacUrl: String = "",
    /** Current apps SOCKS5 endpoint for manual proxy config. */
    val socksProxy: String = "",
    /** Current HTTP CONNECT (HTTPTunnelPort) endpoint. */
    val httpProxy: String = "",
) {
    val isBusy: Boolean
        get() = when (phase) {
            TunnelPhase.Idle,
            TunnelPhase.Connected,
            TunnelPhase.Error,
            TunnelPhase.Blocking,
            -> false
            else -> true
        }

    val isActive: Boolean
        get() = phase == TunnelPhase.Connected || phase == TunnelPhase.Blocking
}

sealed interface VpnEstablishResult {
    data class Success(val mode: VpnProfileMode) : VpnEstablishResult
    data class Failure(val reason: String) : VpnEstablishResult
}
