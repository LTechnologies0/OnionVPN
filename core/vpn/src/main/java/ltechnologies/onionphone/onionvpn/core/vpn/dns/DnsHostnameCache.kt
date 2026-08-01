package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge

/**
 * Bidirectional DNS attribution filled by [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDnsMux].
 *
 * - IP → hostname: Automap SOCKS5A (`.onion` / `.exit`)
 * - hostname → IPv4: pin clearnet SOCKS CONNECTs to DNSCrypt A-records so Tor exits
 *   never re-resolve (AAAA / PreferIPv6 stalls → Speedtest SSL timeouts)
 *
 * Automap (`10.192.0.0/10`) entries are pinned on trim.
 */
object DnsHostnameCache {
    private val ipToHost = ConcurrentHashMap<String, String>(512)
    private val hostToIpv4 = ConcurrentHashMap<String, String>(512)
    private val sizeApprox = AtomicInteger(0)

    fun put(ip: String, hostname: String) {
        val host = TorNetPolicy.normalizeHostname(hostname)
        if (ip.isBlank() || host.isBlank() || host == "localhost") return
        if (!TorNetPolicy.isValidDnsHostname(host)) return
        if (!TorNetPolicy.isValidDnsAddressRecord(ip) && !TunnelEndpoints.isAutomapVirtual(ip)) return
        if (looksLikeIp(host)) return
        val previous = ipToHost.put(ip, host)
        if (previous != null && previous != host && TunnelEndpoints.isAutomapVirtual(ip)) {
            FirewallBridge.onAutomapRemap?.invoke(ip, previous, host)
        }
        // Prefer first IPv4 A for clearnet pin; ignore AAAA / Automap virtuals here.
        if (TunnelEndpoints.parseIpv4Literal(ip) != null && !TunnelEndpoints.isAutomapVirtual(ip)) {
            hostToIpv4.putIfAbsent(host, ip)
        }
        if (previous == null) {
            val n = sizeApprox.incrementAndGet()
            if (n > MAX_ENTRIES) trim()
        }
    }

    fun lookup(ip: String): String? = ipToHost[ip]

    /** DNSCrypt A-record for [hostname], if learned. */
    fun ipv4ForHostname(hostname: String): String? {
        val host = TorNetPolicy.normalizeHostname(hostname)
        if (host.isBlank()) return null
        return hostToIpv4[host]
    }

    fun clear() {
        ipToHost.clear()
        hostToIpv4.clear()
        sizeApprox.set(0)
    }

    fun size(): Int = ipToHost.size

    private fun trim() {
        trimNonAutomap(TRIM_BUDGET)
        if (sizeApprox.get() > MAX_ENTRIES) {
            trimNonAutomap(TRIM_BUDGET * 2)
        }
    }

    private fun trimNonAutomap(budget: Int) {
        var n = 0
        val it = ipToHost.keys.iterator()
        while (it.hasNext() && n < budget) {
            val key = it.next()
            if (TunnelEndpoints.isAutomapVirtual(key)) continue
            val host = ipToHost[key]
            it.remove()
            sizeApprox.decrementAndGet()
            if (host != null) {
                val pinned = hostToIpv4[host]
                if (pinned == key) hostToIpv4.remove(host, key)
            }
            n++
        }
    }

    private fun looksLikeIp(value: String): Boolean {
        if (value.indexOf(':') >= 0) return true // IPv6
        var dots = 0
        for (ch in value) {
            when {
                ch == '.' -> dots++
                ch !in '0'..'9' -> return false
            }
        }
        return dots == 3
    }

    private const val MAX_ENTRIES = 4_096
    private const val TRIM_BUDGET = 256
}
