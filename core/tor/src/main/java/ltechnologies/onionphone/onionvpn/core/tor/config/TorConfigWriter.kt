package ltechnologies.onionphone.onionvpn.core.tor.config

import java.io.File
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

/**
 * Package `config` — torrc generation only (no process I/O).
 *
 * Imported by: [ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager]
 * (pipeline step 2: write torrc) and unit tests / validation of runtime torrc text.
 */

/**
 * Builds OnionVPN client `torrc` text: multi-SocksPort isolation, ControlSocket cookie auth,
 * and MITM hardening.
 *
 * Isolation model (path-spec + Privacy Guides / Tor Browser / Whonix lessons):
 * 1. Apps — SessionGroup + IsolateSOCKSAuth + KeepAliveIsolateSOCKSAuth (per-UID tokens).
 *    No IsolateDestPort on apps: DestAddr+DestPort explode circuit count on mobile
 *    (Whonix ticket #3455; TBB uses SOCKS-auth isolation instead).
 * 2. DNSCrypt — own SessionGroup + KeepAliveIsolateSOCKSAuth
 * 3. Probes — dedicated SocksPort (never share circuits with user traffic)
 * 4. DNSPort — Automap / bootstrap SessionGroup
 *
 * @see <a href="https://spec.torproject.org/path-spec/stream-isolation.html">path-spec stream isolation</a>
 * @see <a href="https://spec.torproject.org/proposals/368-cdt-rethink.html">prop 368 CDT / KeepAliveIsolateSOCKSAuth</a>
 */
object TorConfigWriter {
    /**
     * Unix domain socket basename under [DataDirectory] for the control plane.
     * Paired with [COOKIE_FILE_NAME]; TCP ControlPort is disabled (`ControlPort 0`).
     */
    const val CONTROL_SOCKET_NAME = "control.sock"

    /**
     * CookieAuthentication file basename under [DataDirectory].
     * Hex contents authenticate [ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient].
     */
    const val COOKIE_FILE_NAME = "control_auth_cookie"
    const val GEOIP_FILE_NAME = "geoip"
    const val GEOIP6_FILE_NAME = "geoip6"

    /**
     * Full SOCKS isolation (DestAddr+DestPort) — probes / DNSCrypt only.
     * Apps use [SOCKS_ISOLATION_APPS] to avoid circuit storms.
     */
    const val SOCKS_ISOLATION_MAX =
        "IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort IsolateSOCKSAuth"

    /**
     * Apps SocksPort: UID tokens ([KeepAliveIsolateSOCKSAuth]) are the primary
     * isolation axis (Tor Browser model). Do **not** add IsolateDestAddr here —
     * same-UID multi-host pages (CDNs, Obtainium→api.github.com, …) would open
     * one circuit per destination and feel bandwidth-capped on mobile.
     */
    const val SOCKS_ISOLATION_APPS =
        "IsolateClientAddr IsolateClientProtocol IsolateSOCKSAuth"

    /**
     * @param dataDirectory absolute Tor DataDirectory path
     * @param socksPort apps/hev SocksPort
     * @param dnsCryptSocksPort DNSCrypt upstream SocksPort
     * @param probeSocksPort validation/leak-probe SocksPort
     * @param httpTunnelPort unused (HTTPTunnelPort forced 0 — PAC bridge only)
     * @param dnsPort Tor DNSPort (Automap)
     * @param preferences bridges, nodes, circuit dirtiness
     * @param nativeLibraryDir absolute path to extracted jniLibs (PT binaries); null skips auto-CTP
     */
    @Suppress("UNUSED_PARAMETER")
    fun write(
        dataDirectory: String,
        socksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
        dnsCryptSocksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT + 1,
        probeSocksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT + 2,
        httpTunnelPort: Int = TunnelEndpoints.TOR_SOCKS_PORT + 3,
        dnsPort: Int = TunnelEndpoints.TOR_DNS_PORT,
        preferences: TunnelPreferences = TunnelPreferences(),
        nativeLibraryDir: String? = null,
    ): String = buildString {
        appendLine("DataDirectory $dataDirectory")
        appendLine("ClientOnly 1")
        appendLine("AvoidDiskWrites 1")
        appendLine("DormantCanceledByStartup 1")
        // Idle timeout before Tor goes dormant on its own (battery). Controller can SIGNAL ACTIVE.
        appendLine("DormantClientTimeout 30 minutes")
        appendLine("SafeLogging 1")
        appendLine("Log notice stderr")

        appendLine("SocksPolicy accept 127.0.0.1")
        appendLine("SocksPolicy reject *")

        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$socksPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS} $SOCKS_ISOLATION_APPS " +
                "KeepAliveIsolateSOCKSAuth",
        )
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$dnsCryptSocksPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT} $SOCKS_ISOLATION_MAX " +
                "KeepAliveIsolateSOCKSAuth",
        )
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$probeSocksPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_PROBE} $SOCKS_ISOLATION_MAX",
        )
        appendLine(
            "DNSPort ${TunnelEndpoints.LOOPBACK}:$dnsPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNS} IsolateDestAddr",
        )
        appendLine("AutomapHostsOnResolve 1")
        appendLine("AutomapHostsSuffixes .onion,.exit")

        // hev CONNECTs by IPv4/IPv6 literal (DNSCrypt A/AAAA) or hostname (.onion).
        appendLine("SafeSocks 0")
        appendLine("TestSocks 0")
        appendLine("VirtualAddrNetwork 10.192.0.0/10")
        // Automap .onion AAAA into ULA for IPv6-preferring apps (Tor man VirtualAddrNetworkIPv6).
        appendLine("VirtualAddrNetworkIPv6 [FC00::]/7")
        appendLine("TransPort 0")
        // HTTPTunnelPort uses Tor name resolution (exit DNS) — conflicts with DNSCrypt policy.
        // Apps that need HTTP CONNECT must use the PAC DNSCrypt→Tor bridge instead.
        appendLine("HTTPTunnelPort 0")
        appendLine("ControlPort 0")
        appendLine("CookieAuthentication 1")
        appendLine("CookieAuthFile ${File(dataDirectory, COOKIE_FILE_NAME).absolutePath}")
        appendLine("ControlSocket ${File(dataDirectory, CONTROL_SOCKET_NAME).absolutePath}")

        val geoIp = File(dataDirectory, GEOIP_FILE_NAME)
        val geoIp6 = File(dataDirectory, GEOIP6_FILE_NAME)
        if (geoIp.isFile && geoIp.length() > 0L) {
            appendLine("GeoIPFile ${geoIp.absolutePath}")
        }
        if (geoIp6.isFile && geoIp6.length() > 0L) {
            appendLine("GeoIPv6File ${geoIp6.absolutePath}")
        }

        appendLine("ClientRejectInternalAddresses 1")
        appendLine("AllowNonRFC953Hostnames 0")
        appendLine("RefuseUnknownExits 1")
        appendLine("FetchUselessDescriptors 0")
        appendLine("DownloadExtraInfo 0")
        // Prefer IPv4 for OR (guards), but allow IPv6 OR when needed; exit dest may be IPv6.
        // With bridges, Tor's "auto" prefers the configured Bridge address (important for
        // WebTunnel placeholders) instead of Preferring learned IPv4 ORPorts.
        appendLine("ClientUseIPv4 1")
        appendLine("ClientUseIPv6 1")
        if (TorBridgeConfig.isConfigured(preferences.torBridges)) {
            appendLine("ClientPreferIPv6ORPort auto")
        } else {
            appendLine("ClientPreferIPv6ORPort 0")
        }

        appendLine("HardwareAccel 1")
        appendLine("VanguardsLiteEnabled 1")
        appendLine("ConfluxEnabled auto")
        appendLine("UseMicrodescriptors 1")

        appendLine("UseEntryGuards 1")
        // Tor defaults ~2 primary guards — single guard hurts Wi‑Fi↔cell handoffs (Privacy Guides:
        // guards stay for months; having two improves mobile resilience without DROPGUARDS).
        appendLine("NumEntryGuards 2")
        appendLine("NumPrimaryGuards 2")
        appendLine("NumDirectoryGuards 3")
        appendLine("EnforceDistinctSubnets 1")
        appendLine("StrictNodes 0")

        // Cap pending builds — Isolate* + high pending caused circuit storms on app fan-out.
        appendLine("MaxClientCircuitsPending 48")
        appendLine("CircuitBuildTimeout 60")
        appendLine("LearnCircuitBuildTimeout 1")
        appendLine("SocksTimeout 120")
        appendLine("CircuitStreamTimeout 0")

        appendLine("ConnectionPadding auto")
        appendLine("ReducedConnectionPadding 0")
        appendLine("CircuitPadding 1")
        appendLine("ReducedCircuitPadding 0")

        appendLine("WarnPlaintextPorts 23,109,110,143")
        appendLine("RejectPlaintextPorts 23,109")

        appendLine("NewCircuitPeriod ${preferences.torNewCircuitPeriodSec}")
        appendLine("MaxCircuitDirtiness ${preferences.torMaxCircuitDirtinessSec}")

        val bridgeBlock = TorBridgeConfig.torrcFragment(
            bridgeText = preferences.torBridges,
            nativeLibraryDir = nativeLibraryDir?.let { java.io.File(it) },
        )
        if (bridgeBlock.isNotEmpty()) {
            append(bridgeBlock)
        }

        preferences.torEntryNodes.trim().takeIf { it.isNotEmpty() }?.let {
            appendLine("EntryNodes $it")
            appendLine("StrictNodes 1")
        }
        preferences.torExitNodes.trim().takeIf { it.isNotEmpty() }?.let {
            appendLine("ExitNodes $it")
            appendLine("StrictNodes 1")
        }
        preferences.torExcludeNodes.trim().takeIf { it.isNotEmpty() }?.let {
            appendLine("ExcludeNodes $it")
            appendLine("StrictNodes 1")
        }
    }
}
