package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicLong
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo

/**
 * Maps TUN TCP flows (esp. SYN) → app UID so [SocksUidBridge] can IsolateSOCKSAuth
 * after hev opens SOCKS CONNECT by destination only.
 *
 * Supports IPv4 (int key) and IPv6 (host|port key).
 */
object TcpFlowUidIndex {
    data class Entry(
        val srcIp: Int,
        val srcPort: Int,
        val dstIp: Int,
        val dstPort: Int,
        val uid: Int,
        val atMs: Long = System.currentTimeMillis(),
    )

    private val byDest = ConcurrentHashMap<Long, ConcurrentLinkedDeque<Entry>>()
    private val byDestV6 = ConcurrentHashMap<String, ConcurrentLinkedDeque<Entry>>()
    private val notes = AtomicLong(0)
    private val takes = AtomicLong(0)
    private val misses = AtomicLong(0)

    fun clear() {
        byDest.clear()
        byDestV6.clear()
    }

    fun note(info: IpPacketInfo, uid: Int) {
        if (!info.isTcp || uid < 0) return
        if (info.isIpv6) {
            noteV6(info.dstIp, info.dstPort, uid, info.srcPort)
            return
        }
        val key = destKey(info.dstIpInt, info.dstPort)
        val q = byDest.getOrPut(key) { ConcurrentLinkedDeque() }
        q.addLast(
            Entry(
                srcIp = info.srcIpInt,
                srcPort = info.srcPort,
                dstIp = info.dstIpInt,
                dstPort = info.dstPort,
                uid = uid,
            ),
        )
        notes.incrementAndGet()
        trim(q)
        if (byDest.size > MAX_DEST_KEYS) evictOldestKeys()
    }

    fun hasRecent(dstIp: Int, dstPort: Int, maxAgeMs: Long = ENTRY_TTL_MS): Boolean {
        val q = byDest[destKey(dstIp, dstPort)] ?: return false
        val now = System.currentTimeMillis()
        return q.any { now - it.atMs <= maxAgeMs }
    }

    fun hasRecentHost(host: String, dstPort: Int, maxAgeMs: Long = ENTRY_TTL_MS): Boolean {
        parseIpv4(host)?.let { return hasRecent(it, dstPort, maxAgeMs) }
        if (host.indexOf(':') < 0) return false
        val q = byDestV6["$host|$dstPort"] ?: return false
        val now = System.currentTimeMillis()
        return q.any { now - it.atMs <= maxAgeMs }
    }

    /**
     * Newest non-expired flow for this destination (hev CONNECT target).
     * Does not consume — parallel CONNECTs share the UID stamp.
     */
    fun peek(dstIp: Int, dstPort: Int): Entry? {
        val key = destKey(dstIp, dstPort)
        val q = byDest[key] ?: run {
            misses.incrementAndGet()
            return null
        }
        return peekNewest(q, key, byDest)
    }

    /** @deprecated Prefer [peek]. */
    fun take(dstIp: Int, dstPort: Int): Entry? {
        val q = byDest[destKey(dstIp, dstPort)] ?: run {
            misses.incrementAndGet()
            return null
        }
        val now = System.currentTimeMillis()
        while (true) {
            val e = q.pollLast() ?: break
            if (now - e.atMs <= ENTRY_TTL_MS) {
                takes.incrementAndGet()
                if (q.isEmpty()) byDest.remove(destKey(dstIp, dstPort), q)
                return e
            }
        }
        byDest.remove(destKey(dstIp, dstPort), q)
        misses.incrementAndGet()
        return null
    }

    fun peekIpv4Host(host: String, dstPort: Int): Entry? {
        val ip = parseIpv4(host) ?: return null
        return peek(ip, dstPort)
    }

    fun takeIpv4Host(host: String, dstPort: Int): Entry? {
        val ip = parseIpv4(host) ?: return null
        return take(ip, dstPort)
    }

    /** Peek by dotted IPv4 or literal IPv6 host (hev CONNECT target). */
    fun peekHost(host: String, dstPort: Int): Entry? {
        parseIpv4(host)?.let { return peek(it, dstPort) }
        if (host.indexOf(':') >= 0) return peekV6(host, dstPort)
        return null
    }

    fun stats(): String =
        "notes=${notes.get()} takes=${takes.get()} misses=${misses.get()} " +
            "keys=${byDest.size} v6keys=${byDestV6.size}"

    private fun noteV6(dstHost: String, dstPort: Int, uid: Int, srcPort: Int) {
        val key = "$dstHost|$dstPort"
        val q = byDestV6.getOrPut(key) { ConcurrentLinkedDeque() }
        q.addLast(
            Entry(
                srcIp = 0,
                srcPort = srcPort,
                dstIp = 0,
                dstPort = dstPort,
                uid = uid,
            ),
        )
        notes.incrementAndGet()
        trim(q)
        if (byDestV6.size > MAX_DEST_KEYS) evictOldestV6()
    }

    private fun peekV6(host: String, dstPort: Int): Entry? {
        val key = "$host|$dstPort"
        val q = byDestV6[key] ?: run {
            misses.incrementAndGet()
            return null
        }
        return peekNewest(q, key, byDestV6)
    }

    private fun <K> peekNewest(
        q: ConcurrentLinkedDeque<Entry>,
        key: K,
        map: ConcurrentHashMap<K, ConcurrentLinkedDeque<Entry>>,
    ): Entry? {
        val now = System.currentTimeMillis()
        while (true) {
            val e = q.peekLast() ?: break
            if (now - e.atMs <= ENTRY_TTL_MS) {
                takes.incrementAndGet()
                // Do not mutate deque on peek (pollLast+addLast races concurrent peekers).
                return e
            }
            q.pollLast()
        }
        if (q.isEmpty()) map.remove(key, q)
        misses.incrementAndGet()
        return null
    }

    private fun trim(q: ConcurrentLinkedDeque<Entry>) {
        while (q.size > MAX_PER_DEST) q.pollFirst()
        val now = System.currentTimeMillis()
        while (true) {
            val head = q.peekFirst() ?: break
            if (now - head.atMs <= ENTRY_TTL_MS) break
            q.pollFirst()
        }
    }

    private fun evictOldestKeys() {
        val now = System.currentTimeMillis()
        val it = byDest.entries.iterator()
        var removed = 0
        while (it.hasNext() && removed < 64) {
            val e = it.next()
            e.value.removeIf { entry -> now - entry.atMs > ENTRY_TTL_MS }
            if (e.value.isEmpty()) {
                it.remove()
                removed++
            }
        }
    }

    private fun evictOldestV6() {
        val now = System.currentTimeMillis()
        val it = byDestV6.entries.iterator()
        var removed = 0
        while (it.hasNext() && removed < 64) {
            val e = it.next()
            e.value.removeIf { entry -> now - entry.atMs > ENTRY_TTL_MS }
            if (e.value.isEmpty()) {
                it.remove()
                removed++
            }
        }
    }

    private fun destKey(dstIp: Int, dstPort: Int): Long =
        (dstIp.toLong() shl 16) or (dstPort.toLong() and 0xffffL)

    private fun parseIpv4(host: String): Int? {
        val p = host.split('.')
        if (p.size != 4) return null
        var ip = 0
        for (part in p) {
            val o = part.toIntOrNull() ?: return null
            if (o !in 0..255) return null
            ip = (ip shl 8) or o
        }
        return ip
    }

    private const val ENTRY_TTL_MS = 30_000L
    private const val MAX_PER_DEST = 16
    private const val MAX_DEST_KEYS = 4_096
}
