package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.util.concurrent.atomic.AtomicLong

/**
 * Inject ICMP/ICMPv6 "port unreachable" into the TUN when we blackhole UDP
 * (QUIC/HTTP3, STUN, …). Silent drops make Chromium wait a long QUIC timeout
 * before falling back to TCP; an unreachable error triggers that fallback fast.
 */
internal object IcmpUnreachable {
    private const val PROTO_ICMP = 1
    private const val PROTO_UDP = 17
    private const val PROTO_ICMPV6 = 58
    private const val ICMP_DEST_UNREACH = 3
    private const val ICMP_PORT_UNREACH = 3
    private const val ICMPV6_DEST_UNREACH = 1
    private const val ICMPV6_PORT_UNREACH = 4

    /** Min spacing between ICMP replies (DoS / TUN flood guard). */
    private const val MIN_INTERVAL_NS = 2_000_000L // 2ms
    private val lastEmitNs = AtomicLong(0)

    /**
     * @return IPv4 or IPv6 ICMP packet, or null if not applicable / rate-limited.
     */
    fun buildForBlackholedUdp(original: ByteArray, length: Int): ByteArray? {
        if (length < 28) return null
        val now = System.nanoTime()
        val prev = lastEmitNs.get()
        if (now - prev < MIN_INTERVAL_NS) return null
        if (!lastEmitNs.compareAndSet(prev, now)) return null

        val version = (original[0].toInt() ushr 4) and 0x0f
        return when (version) {
            4 -> buildIpv4PortUnreachable(original, length)
            6 -> buildIpv6PortUnreachable(original, length)
            else -> null
        }
    }

    fun buildIpv4PortUnreachable(original: ByteArray, length: Int): ByteArray? {
        if (length < 28) return null
        if ((original[0].toInt() ushr 4) and 0x0f != 4) return null
        if ((original[9].toInt() and 0xff) != PROTO_UDP) return null
        val ihl = (original[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 8) return null

        // ICMP payload = original IP header + first 8 bytes of UDP (RFC 792).
        val quoteLen = (ihl + 8).coerceAtMost(length)
        val icmpLen = 8 + quoteLen
        val total = 20 + icmpLen
        val out = ByteArray(total)

        // Swap src/dst for the reply IP header.
        out[0] = 0x45
        out[1] = 0
        out[2] = (total ushr 8).toByte()
        out[3] = (total and 0xff).toByte()
        out[6] = 0x40 // DF
        out[8] = 64
        out[9] = PROTO_ICMP.toByte()
        // src = original dst, dst = original src
        System.arraycopy(original, 16, out, 12, 4)
        System.arraycopy(original, 12, out, 16, 4)
        val ipSum = ipChecksum(out, 0, 20)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xff).toByte()

        val icmpOff = 20
        out[icmpOff] = ICMP_DEST_UNREACH.toByte()
        out[icmpOff + 1] = ICMP_PORT_UNREACH.toByte()
        // checksum 0 for now; unused bytes 4–7 = 0
        System.arraycopy(original, 0, out, icmpOff + 8, quoteLen)
        val icmpSum = ipChecksum(out, icmpOff, icmpLen)
        out[icmpOff + 2] = (icmpSum ushr 8).toByte()
        out[icmpOff + 3] = (icmpSum and 0xff).toByte()
        return out
    }

    fun buildIpv6PortUnreachable(original: ByteArray, length: Int): ByteArray? {
        if (length < 48) return null
        if ((original[0].toInt() ushr 4) and 0x0f != 6) return null
        if ((original[6].toInt() and 0xff) != PROTO_UDP) return null

        // ICMPv6 payload = as much of original as fits (min IP+UDP headers).
        val quoteLen = length.coerceAtMost(1232) // leave room under typical MTU
        val icmpLen = 8 + quoteLen
        val total = 40 + icmpLen
        val out = ByteArray(total)

        out[0] = 0x60
        // payload length
        out[4] = (icmpLen ushr 8).toByte()
        out[5] = (icmpLen and 0xff).toByte()
        out[6] = PROTO_ICMPV6.toByte()
        out[7] = 64
        // src = original dst (24..39), dst = original src (8..23)
        System.arraycopy(original, 24, out, 8, 16)
        System.arraycopy(original, 8, out, 24, 16)

        val icmpOff = 40
        out[icmpOff] = ICMPV6_DEST_UNREACH.toByte()
        out[icmpOff + 1] = ICMPV6_PORT_UNREACH.toByte()
        System.arraycopy(original, 0, out, icmpOff + 8, quoteLen)
        val sum = icmpv6Checksum(out, icmpOff, icmpLen)
        out[icmpOff + 2] = (sum ushr 8).toByte()
        out[icmpOff + 3] = (sum and 0xff).toByte()
        return out
    }

    private fun ipChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }

    /** ICMPv6 checksum includes IPv6 pseudo-header (RFC 4443). */
    private fun icmpv6Checksum(packet: ByteArray, icmpOff: Int, icmpLen: Int): Int {
        var sum = 0
        // Pseudo: src(16) + dst(16) at offsets 8..39 of the reply packet.
        var p = 8
        while (p < 40) {
            sum += ((packet[p].toInt() and 0xff) shl 8) or (packet[p + 1].toInt() and 0xff)
            p += 2
        }
        // Upper 32-bit length
        sum += (icmpLen ushr 16) and 0xffff
        sum += icmpLen and 0xffff
        sum += PROTO_ICMPV6
        val c0 = packet[icmpOff + 2]
        val c1 = packet[icmpOff + 3]
        packet[icmpOff + 2] = 0
        packet[icmpOff + 3] = 0
        var i = icmpOff
        val end = icmpOff + icmpLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xff) shl 8) or (packet[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (packet[i].toInt() and 0xff) shl 8
        packet[icmpOff + 2] = c0
        packet[icmpOff + 3] = c1
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }
}
