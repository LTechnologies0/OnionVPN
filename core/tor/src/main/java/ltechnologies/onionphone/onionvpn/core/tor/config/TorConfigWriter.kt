package ltechnologies.onionphone.onionvpn.core.tor.config

import java.io.File
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
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
 * Isolation model:
 * 1. Apps/hev — SessionGroup apps, IsolateDestAddr+Port, no KeepAliveIsolateSOCKSAuth
 * 2. DNSCrypt — own SessionGroup + KeepAliveIsolateSOCKSAuth
 * 3. Probes — dedicated SocksPort (never share circuits with user traffic)
 * 4. DNSPort — Automap / bootstrap SessionGroup
 *
 * @see <a href="https://spec.torproject.org/path-spec/stream-isolation.html">path-spec stream isolation</a>
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

    /**
     * Maximal SOCKS isolation flags (path-spec + Tor man).
     * Applied to every SocksPort; apps omit KeepAliveIsolateSOCKSAuth separately.
     */
    const val SOCKS_ISOLATION_MAX =
        "IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort IsolateSOCKSAuth"

    /**
     * @param dataDirectory absolute Tor DataDirectory path
     * @param socksPort apps/hev SocksPort
     * @param dnsCryptSocksPort DNSCrypt upstream SocksPort
     * @param probeSocksPort validation/leak-probe SocksPort
     * @param dnsPort Tor DNSPort (Automap)
     * @param preferences bridges, nodes, circuit dirtiness, DNS mode (SafeSocks)
     */
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

        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$socksPort " +
                "SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS} $SOCKS_ISOLATION_MAX",
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

        val safeSocks = preferences.dnsResolverMode == DnsResolverMode.FAKE_IP_SOCKS5A
        appendLine("SafeSocks ${if (safeSocks) 1 else 0}")
        appendLine("TestSocks ${if (safeSocks) 1 else 0}")
        appendLine("VirtualAddrNetwork 10.192.0.0/10")
        appendLine("TransPort 0")
        appendLine("HTTPTunnelPort 0")
        appendLine("ControlPort 0")
        appendLine("CookieAuthentication 1")
        appendLine("CookieAuthFile ${File(dataDirectory, COOKIE_FILE_NAME).absolutePath}")
        appendLine("ControlSocket ${File(dataDirectory, CONTROL_SOCKET_NAME).absolutePath}")

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
