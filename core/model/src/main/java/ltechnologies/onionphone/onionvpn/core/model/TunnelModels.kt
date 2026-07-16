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

    /** Fake-IP pool for hev mapdns (must not overlap VPN 10.8.0.0/24). */
    const val FAKE_DNS_NETWORK = "100.64.0.0"
    const val FAKE_DNS_NETMASK = "255.192.0.0"
    const val FAKE_DNS_CACHE_SIZE = 4096

    /** Mullvad-style dummy DNS when no resolver is available (RFC 5737 TEST-NET-1). */
    const val FALLBACK_BLOCKING_DNS = "192.0.2.1"

    const val VPN_MTU = 1500
}

/**
 * How app DNS is resolved while the VPN is up.
 *
 * - [DNSCRYPT_MUX]: UDP/53 to VPN DNS is forwarded to DNSCrypt (upstream via Tor SOCKS).
 * - [FAKE_IP_SOCKS5A]: hev FakeDNS + hostname recovery over Tor SOCKS5A.
 */
enum class DnsResolverMode {
    DNSCRYPT_MUX,
    FAKE_IP_SOCKS5A,
}

/**
 * VPN profile applied by [ltechnologies.onionphone.onionvpn.core.vpn.VpnProfileBuilder].
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
)

data class TunnelSnapshot(
    val phase: TunnelPhase = TunnelPhase.Idle,
    val killSwitchEnabled: Boolean = true,
    val torRunning: Boolean = false,
    val dnsCryptRunning: Boolean = false,
    val vpnEstablished: Boolean = false,
    val validations: List<ValidationCheck> = emptyList(),
    val lastError: String? = null,
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

data class TunnelPreferences(
    val routeAllTrafficThroughTor: Boolean = true,
    val killSwitchEnabled: Boolean = true,
    val dnsCryptServerName: String = "cloudflare",
    val dnsResolverMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    val torBridges: String = "",
    val torEntryNodes: String = "",
    val torExitNodes: String = "",
    val torExcludeNodes: String = "",
    val torNewCircuitPeriodSec: Int = 30,
    val torMaxCircuitDirtinessSec: Int = 600,
    val dnsCryptRequireNoLog: Boolean = true,
    val dnsCryptRequireNoFilter: Boolean = false,
    val dnsCryptForceTcp: Boolean = true,
)

sealed interface VpnEstablishResult {
    data class Success(val mode: VpnProfileMode) : VpnEstablishResult
    data class Failure(val reason: String) : VpnEstablishResult
}
