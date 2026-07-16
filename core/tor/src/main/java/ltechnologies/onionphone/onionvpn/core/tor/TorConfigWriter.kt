package ltechnologies.onionphone.onionvpn.core.tor

import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

/**
 * Tor configuration from Tor Project defaults + Whonix stream isolation + Orbot lockdown:
 *
 * - **Two SocksPorts** (Whonix): apps/hev vs DNSCrypt — no circuit correlation.
 * - IsolateDestAddr/Port + IsolateSOCKSAuth on each SocksPort.
 * - SocksPolicy accept 127.0.0.1 only (Orbot/Tor: no LAN SOCKS exposure).
 * - UseEntryGuards 1 (Tor Project OPSEC default).
 * - DNSPort SessionGroup separate from both SOCKS (proposal 171).
 */
object TorConfigWriter {
    fun write(
        dataDirectory: String,
        socksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
        dnsCryptSocksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT + 1,
        dnsPort: Int = TunnelEndpoints.TOR_DNS_PORT,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): String = buildString {
        appendLine("DataDirectory $dataDirectory")
        appendLine("ClientOnly 1")
        appendLine("AvoidDiskWrites 1")
        appendLine("DormantCanceledByStartup 1")

        // Loopback-only SOCKS — never bind on 0.0.0.0 (Orbot/Tor hardening).
        appendLine("SocksPolicy accept 127.0.0.1")
        appendLine("SocksPolicy reject *")

        // Whonix: dedicated SocksPort for application / hev traffic.
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$socksPort " +
                "SessionGroup=1 IsolateDestAddr IsolateDestPort " +
                "IsolateSOCKSAuth KeepaliveIsolateSOCKSAuth",
        )
        // Whonix: dedicated SocksPort for DNSCrypt upstream (different circuits).
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$dnsCryptSocksPort " +
                "SessionGroup=3 IsolateDestAddr IsolateDestPort " +
                "IsolateSOCKSAuth KeepaliveIsolateSOCKSAuth",
        )
        appendLine(
            "DNSPort ${TunnelEndpoints.LOOPBACK}:$dnsPort " +
                "SessionGroup=2 IsolateDestAddr",
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

        appendLine("ConnectionPadding auto")
        appendLine("ReducedConnectionPadding 0")
        appendLine("CircuitPadding 1")
        appendLine("ReducedCircuitPadding 0")

        // Surface cleartext protocols in logs (Whonix / Tor manual).
        appendLine("WarnPlaintextPorts 23,109,110,143")

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
