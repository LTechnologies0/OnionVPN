package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * IP → hostname map filled by DNS snooping in [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDnsMux].
 *
 * Lookups are lock-free reads for the firewall ASK path. Entries are trimmed FIFO-ish when
 * [MAX_ENTRIES] is exceeded (budgeted key removal — never blocks TUN).
 */
object DnsHostnameCache {
    private val ipToHost = ConcurrentHashMap<String, String>(512)
    private val sizeApprox = AtomicInteger(0)

    fun put(ip: String, hostname: String) {
        val host = hostname.trim().trimEnd('.').lowercase()
        if (ip.isBlank() || host.isBlank() || host == "localhost") return
        if (looksLikeIp(host)) return
        val previous = ipToHost.put(ip, host)
        if (previous == null) {
            val n = sizeApprox.incrementAndGet()
            if (n > MAX_ENTRIES) trim()
        }
    }

    fun lookup(ip: String): String? = ipToHost[ip]

    fun clear() {
        ipToHost.clear()
        sizeApprox.set(0)
    }

    fun size(): Int = ipToHost.size

    private fun trim() {
        var n = 0
        val it = ipToHost.keys.iterator()
        while (it.hasNext() && n < TRIM_BUDGET) {
            it.next()
            it.remove()
            sizeApprox.decrementAndGet()
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
