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
     * Captures IPv6 into the TUN; TCP forwarded over Tor SOCKS (ATYP 0x04).
     */
    const val VPN_CLIENT_ADDRESS_V6 = "fd00:8:8:8::2"

    /**
     * VPN DNS over IPv6 (ULA sibling of [VPN_DNS_ADDRESS]). TunDnsMux diverts UDP/53
     * here to DNSCrypt (not fe80::53 Tor-sample — DNSCrypt-first).
     */
    const val VPN_DNS_ADDRESS_V6 = "fd00:8:8:8::1"

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

    /** Tor AutomapHostsOnResolve IPv6 pool — must NOT overlap TUN ULA `fd00:8:8:8::/64`. */
    const val VIRTUAL_ADDR_NETWORK_V6 = "fd12:4e4b:6f6e::"
    const val VIRTUAL_ADDR_PREFIX_LEN_V6 = 48

    /**
     * Tor Automap virtual IPv6 (`VirtualAddrNetworkIPv6 [fd12:4e4b:6f6e::]/48`).
     * Excludes the VPN client ULA prefix so TUN/LAN ULA are never treated as Automap.
     */
    fun isAutomapVirtualIpv6(hostAddress: String): Boolean {
        if (hostAddress.indexOf(':') < 0) return false
        return runCatching {
            val raw = java.net.InetAddress.getByName(hostAddress).address
            if (raw.size != 16) return@runCatching false
            // Exclude OnionVPN TUN ULA fd00:8:8:8::/64
            if (raw[0] == 0xfd.toByte() && raw[1] == 0x00.toByte() &&
                raw[2] == 0x08.toByte() && raw[3] == 0x08.toByte() &&
                raw[4] == 0x08.toByte() && raw[5] == 0x08.toByte()
            ) {
                return@runCatching false
            }
            // fd12:4e4b:6f6e::/48
            raw[0] == 0xfd.toByte() &&
                raw[1] == 0x12.toByte() &&
                raw[2] == 0x4e.toByte() &&
                raw[3] == 0x4b.toByte() &&
                raw[4] == 0x6f.toByte() &&
                raw[5] == 0x6e.toByte()
        }.getOrDefault(false)
    }

    fun isAutomapVirtual(hostAddress: String): Boolean =
        isAutomapVirtualIpv4(hostAddress) || isAutomapVirtualIpv6(hostAddress)

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

    /**
     * Tor Automap / SOCKS5A candidate: any `.onion` / `.exit` suffix (Tor man
     * AutomapHostsSuffixes). Malformed labels still go to Tor — never DNSCrypt —
     * so bogus queries do not leak. Use [isValidOnionHostname] / [isValidExitHostname]
     * when you need address-spec compliance.
     */
    fun isOnionLikeHostname(hostname: String): Boolean {
        val h = normalizeHostname(hostname)
        return h.endsWith(".onion") || h.endsWith(".exit")
    }

    /**
     * Tor address-spec onion v3: optional DNS labels + exactly 56 chars of base32
     * (`a-z2-7`) + `.onion`. Rejects short fakes like `adb.onion` / `abc.onion`.
     */
    fun isValidOnionHostname(hostname: String): Boolean {
        val h = normalizeHostname(hostname)
        if (!h.endsWith(".onion")) return false
        val withoutTld = h.removeSuffix(".onion")
        if (withoutTld.isEmpty()) return false
        val labels = withoutTld.split('.')
        val onionLabel = labels.last()
        if (!ONION_V3_LABEL.matches(onionLabel)) return false
        return labels.dropLast(1).all { isDnsLabel(it) }
    }

    /**
     * Tor address-spec `.exit`: `[destination.]hop.exit` where hop is a nickname
     * (1–19 alnum) or a 40-hex fingerprint.
     */
    fun isValidExitHostname(hostname: String): Boolean {
        val h = normalizeHostname(hostname)
        if (!h.endsWith(".exit")) return false
        val body = h.removeSuffix(".exit")
        if (body.isEmpty()) return false
        val parts = body.split('.')
        val hop = parts.last()
        val hopOk = EXIT_NICKNAME.matches(hop) || EXIT_FINGERPRINT.matches(hop)
        if (!hopOk) return false
        if (parts.size == 1) return true
        val destination = parts.dropLast(1).joinToString(".")
        return destination.isNotEmpty() &&
            (parseIpv4Literal(destination) != null || destination.split('.').all { isDnsLabel(it) })
    }

    fun normalizeHostname(hostname: String): String =
        hostname.trim().trimEnd('.').lowercase()

    private fun isDnsLabel(label: String): Boolean =
        label.isNotEmpty() &&
            label.length <= 63 &&
            label[0].isLetterOrDigit() &&
            label.last().isLetterOrDigit() &&
            label.all { it.isLetterOrDigit() || it == '-' }

    private val ONION_V3_LABEL = Regex("^[a-z2-7]{56}$")
    private val EXIT_NICKNAME = Regex("^[a-z0-9]{1,19}$")
    private val EXIT_FINGERPRINT = Regex("^[0-9a-f]{40}$")

    const val VPN_MTU = 1280

    /**
     * Public DuckDuckGo onion (v3, address-spec). Prefer this over fake `.onion`
     * labels in unit tests and docs.
     */
    const val WELL_KNOWN_ONION_DDG =
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

    /** Public Tor Project onion (v3). */
    const val WELL_KNOWN_ONION_TORPROJECT =
        "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"


    /**
     * SOCKS5 credentials helpers for per-app IsolateSOCKSAuth (path-spec strong tokens).
     * username = `u{uid}` or `u{uid}-n{epoch}` after NEWNYM (KeepAliveIsolateSOCKSAuth
     * sticky tokens must rotate — prop 368). Unknown UID uses a dedicated token.
     */
    const val SOCKS_UNKNOWN_USER = "uunknown"
    const val SOCKS_UNKNOWN_PASS = "punknown"

    /** @deprecated Static hev token — replaced by [socksUserForUid] / [socksPassForUid]. */
    const val SOCKS_ISOLATION_USER = "onionvpn"
    const val SOCKS_ISOLATION_PASS = "stream"

    /**
     * Global app SOCKS IsolationToken epoch. Bumped on NEWNYM (all planes) so
     * KeepAliveIsolateSOCKSAuth cannot reuse pre-NEWNYM identity.
     */
    @JvmField
    @Volatile
    var appSocksNymEpoch: Int = 0

    fun bumpAppSocksNymEpoch(): Int {
        val next = appSocksNymEpoch + 1
        appSocksNymEpoch = next
        return next
    }

    fun resetAppSocksNymEpoch() {
        appSocksNymEpoch = 0
    }

    fun socksUserForUid(uid: Int, epoch: Int = appSocksNymEpoch): String {
        if (uid < 0) return SOCKS_UNKNOWN_USER
        return if (epoch > 0) "u$uid-n$epoch" else "u$uid"
    }

    fun socksPassForUid(uid: Int, epoch: Int = appSocksNymEpoch): String {
        if (uid < 0) return SOCKS_UNKNOWN_PASS
        return if (epoch > 0) "p$uid-n$epoch" else "p$uid"
    }

    /** Parse `u{uid}`, `u{uid}-n{epoch}`, or unknown sentinel. */
    fun uidFromSocksUser(user: String): Int? {
        if (user == SOCKS_UNKNOWN_USER) return -1
        if (!user.startsWith("u")) return null
        val body = user.removePrefix("u")
        val uidPart = body.substringBefore("-n")
        return uidPart.toIntOrNull()
    }

    fun dnsCryptSocksUser(epoch: Int = appSocksNymEpoch): String =
        if (epoch > 0) "dnscrypt-n$epoch" else SOCKS_DNSCRYPT_USER


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

    /** IsolateSOCKSAuth fallback when PAC client UID is unknown. Prefer pac{uid}/p{uid}. */
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
 * Both preference values divert VPN DNS (UDP/53) through [TunDnsMux] → DNSCrypt /
 * Tor Automap. [FAKE_IP_SOCKS5A] is a legacy key only — hev mapdns is disabled
 * (it conflicted with Automap virtual IPs and the UID SOCKS bridge).
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
    /** Active Tor client engine (C Tor or Arti). */
    val torEngine: TorEngine = TorEngine.LITTLE_T,
    /** Tor control-spec bootstrap 0–100. */
    val torBootstrapProgress: Int = 0,
    val torBootstrapSummary: String = "",
    /**
     * True when the classic ControlSocket session is live (C Tor only).
     * Arti sets [torRuntimeReady] instead — do not enable Circuits/NEWNYM from this alone on Arti.
     */
    val torControlConnected: Boolean = false,
    /** SOCKS/DNS listeners ready (both engines). */
    val torRuntimeReady: Boolean = false,
    /** Classic control-plane ops available (circuits UI, live SETCONF). */
    val torControlPlaneAvailable: Boolean = false,
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
    /**
     * True while New Identity / Arti restart is in flight.
     * UI must disable NEWNYM mash; kill-switch probes are deferred separately.
     */
    val identityRefreshing: Boolean = false,
    /**
     * Epoch ms until New Identity is allowed again (C Tor ~10s defer / Arti / onionmasq gate).
     * 0 = no cooldown.
     */
    val newNymCooldownUntilMs: Long = 0L,
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

    /** Start/Stop primary button shows "active" chrome. */
    val isActive: Boolean
        get() = phase == TunnelPhase.Connected || phase == TunnelPhase.Blocking

    /** Phases where a fresh START is allowed (toddler-proof). */
    val canStart: Boolean
        get() = phase == TunnelPhase.Idle ||
            phase == TunnelPhase.Error ||
            phase == TunnelPhase.Blocking

    /** Phases where STOP is meaningful. */
    val canStop: Boolean
        get() = when (phase) {
            TunnelPhase.Idle, TunnelPhase.Stopping, TunnelPhase.Error -> false
            else -> true
        }

    /** New Identity only when fully connected, not refreshing, and past Tor rate limit. */
    val canNewNym: Boolean
        get() = phase == TunnelPhase.Connected &&
            !identityRefreshing &&
            (torRuntimeReady || torControlConnected) &&
            System.currentTimeMillis() >= newNymCooldownUntilMs
}

sealed interface VpnEstablishResult {
    data class Success(val mode: VpnProfileMode) : VpnEstablishResult
    data class Failure(val reason: String) : VpnEstablishResult
}
