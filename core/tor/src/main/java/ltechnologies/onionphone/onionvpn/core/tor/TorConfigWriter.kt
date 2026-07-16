package ltechnologies.onionphone.onionvpn.core.tor

import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

/**
 * Tor configuration per spec.torproject.org (SOCKS extensions + proposal 171):
 *
 * - [SOCKSPort]: application TCP via SOCKS5 / SOCKS5A.
 * - [DNSPort]: bootstrap only for DNSCrypt internal lookups — never app DNS.
 * - [SessionGroup]: isolates DNSPort circuits from SOCKSPort (proposal 171).
 *
 * SafeSocks: enabled for FakeDNS/SOCKS5A (hostnames). Disabled for DNSCrypt mux
 * because DNSCrypt stamps and post-DNS TCP use literal IPs that SafeSocks rejects.
 */
object TorConfigWriter {
    fun write(
        dataDirectory: String,
        socksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
        dnsPort: Int = TunnelEndpoints.TOR_DNS_PORT,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): String = buildString {
        appendLine("DataDirectory $dataDirectory")
        appendLine("ClientOnly 1")
        appendLine(
            "SOCKSPort ${TunnelEndpoints.LOOPBACK}:$socksPort " +
                "SessionGroup=1 IsolateDestAddr IsolateDestPort",
        )
        appendLine("DNSPort ${TunnelEndpoints.LOOPBACK}:$dnsPort SessionGroup=2")
        appendLine("AutomapHostsOnResolve 1")
        // Mode B (DNSCRYPT_MUX): IP destinations via SOCKS — SafeSocks must be off.
        // Mode A (FAKE_IP_SOCKS5A): hostname recovery — SafeSocks stays on.
        val safeSocks = preferences.dnsResolverMode == DnsResolverMode.FAKE_IP_SOCKS5A
        appendLine("SafeSocks ${if (safeSocks) 1 else 0}")
        appendLine("TestSocks ${if (safeSocks) 1 else 0}")
        appendLine("VirtualAddrNetwork 10.192.0.0/10")
        appendLine("TransPort 0 IsolateDestAddr IsolateDestPort")
        appendLine("HTTPTunnelPort 0")
        appendLine("HardwareAccel 1")
        appendLine("VanguardsLiteEnabled 1")
        appendLine("ConfluxEnabled auto")
        appendLine("UseMicrodescriptors auto")
        appendLine("UseEntryGuards 0")
        appendLine("NumDirectoryGuards 500")
        appendLine("NumEntryGuards 500")
        appendLine("NumPrimaryGuards 500")
        appendLine("PathsNeededToBuildCircuits 0.95")
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
        }
    }
}
