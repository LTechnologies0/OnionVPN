package ltechnologies.onionphone.onionvpn.core.tor

import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import java.io.File

/**
 * Tor client config aligned with:
 * - [path-spec stream isolation](https://spec.torproject.org/path-spec/stream-isolation.html)
 * - Tor manual `SocksPort` isolation flags
 * - Whonix multi-SocksPort practice
 * - Client-side MITM / local-network hardening (RejectInternalAddresses, SafeLogging, …)
 *
 * Isolation model (OnionVPN):
 * 1. **Apps/hev** — SessionGroup=1, IsolateDestAddr+Port (circuit per destination),
 *    IsolateSOCKSAuth (hev credentials). No KeepAliveIsolateSOCKSAuth: hev uses one
 *    static SOCKS token for all TUN streams, so KeepAlive would pin long-lived circuits
 *    without per-app tokens; MaxCircuitDirtiness rotates instead.
 * 2. **DNSCrypt** — SessionGroup=3, separate SocksPort + auth (DNS ≠ app circuit family).
 * 3. **Probes** — SessionGroup=4, dedicated SocksPort so exit-IP / SOCKS5A checks never
 *    share circuits with user traffic (proxy-address isolation in path-spec).
 * 4. **DNSPort** — SessionGroup=2 for Automap / bootstrap only.
 *
 * BGP / ISP note: Tor cannot rewrite public BGP. Integrity of directory consensus +
 * TLS/DNSCrypt end-to-end still required. Bridges mitigate ISP fingerprinting of Tor.
 */
object TorConfigWriter {
    const val CONTROL_SOCKET_NAME = "control.sock"
    const val COOKIE_FILE_NAME = "control_auth_cookie"

    /** Full isolation flags for maximal stream/circuit separation (path-spec + man). */
    const val SOCKS_ISOLATION_MAX =
        "IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort IsolateSOCKSAuth"

    fun write(
        dataDirectory: String,
        socksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
        dnsCryptSocksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT + 1,
        probeSocksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT + 2,
        dnsPort: Int = TunnelEndpoints.TOR_DNS_PORT,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): String = buildString {
        appendLine("DataDirectory $dataDirectory")
        appendLine("ClientOnly 1")
        appendLine("AvoidDiskWrites 1")
        appendLine("DormantCanceledByStartup 1")
        appendLine("SafeLogging 1")
        appendLine("Log notice stderr")

        appendLine("SocksPolicy accept 127.0.0.1")
        appendLine("SocksPolicy reject *")

        // Apps / hev — per-destination circuits; dirtiness rotates (no KeepAlive).
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$socksPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS} $SOCKS_ISOLATION_MAX",
        )
        // DNSCrypt upstream — own SessionGroup + KeepAlive (single logical DNS context).
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$dnsCryptSocksPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_DNSCRYPT} $SOCKS_ISOLATION_MAX " +
                "KeepAliveIsolateSOCKSAuth",
        )
        // Validation / leak probes — never share circuits with apps or DNSCrypt.
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

        val safeSocks = preferences.dnsResolverMode == DnsResolverMode.FAKE_IP_SOCKS5A
        appendLine("SafeSocks ${if (safeSocks) 1 else 0}")
        appendLine("TestSocks ${if (safeSocks) 1 else 0}")
        appendLine("VirtualAddrNetwork 10.192.0.0/10")
        appendLine("TransPort 0")
        appendLine("HTTPTunnelPort 0")
        // Control plane: Unix socket + cookie in DataDirectory (no TCP ControlPort).
        appendLine("ControlPort 0")
        appendLine("CookieAuthentication 1")
        appendLine("CookieAuthFile ${File(dataDirectory, COOKIE_FILE_NAME).absolutePath}")
        appendLine("ControlSocket ${File(dataDirectory, CONTROL_SOCKET_NAME).absolutePath}")

        // Local / private-network MITM: refuse SOCKS to RFC1918/link-local unless Automap.
        appendLine("ClientRejectInternalAddresses 1")
        appendLine("AllowNonRFC953Hostnames 0")
        appendLine("RefuseUnknownExits 1")
        appendLine("FetchUselessDescriptors 0")
        appendLine("DownloadExtraInfo 0")
        appendLine("ClientPreferIPv6ORPort 0")

        appendLine("HardwareAccel 1")
        appendLine("VanguardsLiteEnabled 1")
        appendLine("ConfluxEnabled auto")
        appendLine("UseMicrodescriptors 1")

        appendLine("UseEntryGuards 1")
        appendLine("NumEntryGuards 1")
        appendLine("NumPrimaryGuards 1")
        appendLine("NumDirectoryGuards 3")
        appendLine("EnforceDistinctSubnets 1")
        appendLine("StrictNodes 0")

        // IsolateDestAddr opens many circuits — raise pending budget (Tor man).
        appendLine("MaxClientCircuitsPending 128")
        appendLine("CircuitBuildTimeout 60")
        appendLine("LearnCircuitBuildTimeout 1")
        appendLine("SocksTimeout 120")

        appendLine("ConnectionPadding auto")
        appendLine("ReducedConnectionPadding 0")
        appendLine("CircuitPadding 1")
        appendLine("ReducedCircuitPadding 0")

        appendLine("WarnPlaintextPorts 23,109,110,143")
        appendLine("RejectPlaintextPorts 23,109")

        appendLine("NewCircuitPeriod ${preferences.torNewCircuitPeriodSec}")
        appendLine("MaxCircuitDirtiness ${preferences.torMaxCircuitDirtinessSec}")

        val bridges = preferences.torBridges.trim()
        if (bridges.isNotEmpty()) {
            appendLine("UseBridges 1")
            bridges.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .forEach { line ->
                    if (line.startsWith("Bridge ", ignoreCase = true) ||
                        line.startsWith("ClientTransportPlugin ", ignoreCase = true)
                    ) {
                        appendLine(line)
                    } else {
                        appendLine("Bridge $line")
                    }
                }
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
