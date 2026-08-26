package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import timber.log.Timber

/**
 * Per-flow emit gate for TUN reject injection (ICMP / TCP RST).
 *
 * A single global 2ms CAS drop storms of distinct Happy-Eyeballs / QUIC flows —
 * only the first packet gets a reject and the rest hang. Per-flow spacing keeps
 * flood protection while still failing over each 5-tuple promptly.
 */
internal object TunRejectEmitGate {
    /** Min spacing between rejects for the *same* flow. */
    private const val PER_FLOW_INTERVAL_NS = 50_000_000L // 50ms

    /** Absolute floor between any two emits (TUN flood guard). */
    private const val GLOBAL_MIN_INTERVAL_NS = 200_000L // 0.2ms

    private const val MAX_FLOWS = 2_048
    private val lastByFlow = ConcurrentHashMap<Long, Long>(512)
    private val lastGlobalNs = AtomicLong(0)
    private val sweepCounter = AtomicInteger(0)
    private val emitted = AtomicLong(0)
    private val denied = AtomicLong(0)

    /**
     * @return true if a reject packet may be injected for this flow key now.
     */
    fun tryAcquire(flowKey: Long): Boolean {
        val now = System.nanoTime()
        val globalPrev = lastGlobalNs.get()
        if (now - globalPrev < GLOBAL_MIN_INTERVAL_NS) {
            noteDenied()
            return false
        }

        val flowPrev = lastByFlow[flowKey]
        if (flowPrev != null && now - flowPrev < PER_FLOW_INTERVAL_NS) {
            noteDenied()
            return false
        }

        if (!lastGlobalNs.compareAndSet(globalPrev, now)) {
            noteDenied()
            return false
        }
        lastByFlow[flowKey] = now

        if (lastByFlow.size > MAX_FLOWS &&
            (sweepCounter.incrementAndGet() and 0x3F) == 0
        ) {
            sweepStale(now)
        }
        val n = emitted.incrementAndGet()
        if ((n and 0xFFL) == 0L) {
            Timber.d(
                "TunRejectEmitGate emitted=%d denied=%d flows=%d",
                n,
                denied.get(),
                lastByFlow.size,
            )
        }
        return true
    }

    private fun noteDenied() {
        val n = denied.incrementAndGet()
        if ((n and 0x3FFL) == 0L) {
            Timber.v("TunRejectEmitGate denied=%d emitted=%d", n, emitted.get())
        }
    }

    fun flowKeyUdpV4(packet: ByteArray, length: Int): Long? {
        if (length < 28) return null
        if ((packet[0].toInt() ushr 4) and 0x0f != 4) return null
        if ((packet[9].toInt() and 0xff) != 17) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 4) return null
        val src = readInt(packet, 12).toLong() and 0xffff_ffffL
        val dst = readInt(packet, 16).toLong() and 0xffff_ffffL
        val sport = u16(packet, ihl).toLong()
        val dport = u16(packet, ihl + 2).toLong()
        return mix(4L, src, dst, sport, dport)
    }

    fun flowKeyUdpV6(packet: ByteArray, length: Int): Long? {
        if (length < 48) return null
        if ((packet[0].toInt() ushr 4) and 0x0f != 6) return null
        if ((packet[6].toInt() and 0xff) != 17) return null
        val sport = u16(packet, 40).toLong()
        val dport = u16(packet, 42).toLong()
        // Fold 128-bit addrs into 64-bit halves.
        val src = foldIpv6(packet, 8)
        val dst = foldIpv6(packet, 24)
        return mix(6L, src, dst, sport, dport)
    }

    fun flowKeyTcpV4(packet: ByteArray, length: Int): Long? {
        if (length < 40) return null
        if ((packet[0].toInt() ushr 4) and 0x0f != 4) return null
        if ((packet[9].toInt() and 0xff) != 6) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 4) return null
        val src = readInt(packet, 12).toLong() and 0xffff_ffffL
        val dst = readInt(packet, 16).toLong() and 0xffff_ffffL
        val sport = u16(packet, ihl).toLong()
        val dport = u16(packet, ihl + 2).toLong()
        return mix(14L, src, dst, sport, dport)
    }

    fun flowKeyTcpV6(packet: ByteArray, length: Int): Long? {
        if (length < 60) return null
        if ((packet[0].toInt() ushr 4) and 0x0f != 6) return null
        if ((packet[6].toInt() and 0xff) != 6) return null
        val sport = u16(packet, 40).toLong()
        val dport = u16(packet, 42).toLong()
        val src = foldIpv6(packet, 8)
        val dst = foldIpv6(packet, 24)
        return mix(16L, src, dst, sport, dport)
    }

    private fun sweepStale(now: Long) {
        val it = lastByFlow.entries.iterator()
        var n = 0
        while (it.hasNext() && n < 256) {
            val e = it.next()
            if (now - e.value > PER_FLOW_INTERVAL_NS * 8) {
                it.remove()
            }
            n++
        }
    }

    private fun mix(tag: Long, a: Long, b: Long, c: Long, d: Long): Long {
        var h = tag * 0x9E3779B97F4A7C15UL.toLong()
        h = h xor (a + 0xBF58476D1CE4E5B9UL.toLong())
        h = h * 0x94D049BB133111EBUL.toLong()
        h = h xor (b + c.shl(16) + d)
        return h
    }

    private fun foldIpv6(packet: ByteArray, off: Int): Long {
        var x = 0L
        for (i in 0 until 8) {
            x = (x shl 8) or (packet[off + i].toLong() and 0xff)
        }
        var y = 0L
        for (i in 8 until 16) {
            y = (y shl 8) or (packet[off + i].toLong() and 0xff)
        }
        return x xor y
    }

    private fun readInt(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xff) shl 24) or
            ((buf[off + 1].toInt() and 0xff) shl 16) or
            ((buf[off + 2].toInt() and 0xff) shl 8) or
            (buf[off + 3].toInt() and 0xff)

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xff) shl 8) or (buf[off + 1].toInt() and 0xff)
}
