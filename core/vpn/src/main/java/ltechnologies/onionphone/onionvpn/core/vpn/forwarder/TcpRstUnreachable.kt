package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

/**
 * Inject TCP RST(+ACK) into the TUN when we blackhole clearnet IPv6 TCP (or other
 * non-torrifiable TCP). Silent drops stall Happy Eyeballs for a full TCP timeout
 * before the app falls back to IPv4 — RST fails that race immediately.
 *
 * Rate-limiting is per-flow via [TunRejectEmitGate] so concurrent SYNs still get
 * an RST per distinct 5-tuple instead of a global silent blackhole.
 */
internal object TcpRstUnreachable {
    private const val PROTO_TCP = 6

    fun buildForBlackholedTcp(original: ByteArray, length: Int): ByteArray? {
        if (length < 40) return null
        val version = (original[0].toInt() ushr 4) and 0x0f
        val key = when (version) {
            4 -> TunRejectEmitGate.flowKeyTcpV4(original, length)
            6 -> TunRejectEmitGate.flowKeyTcpV6(original, length)
            else -> null
        } ?: return null
        if (!TunRejectEmitGate.tryAcquire(key)) return null

        return when (version) {
            4 -> buildIpv4Rst(original, length)
            6 -> buildIpv6Rst(original, length)
            else -> null
        }
    }

    fun buildIpv4Rst(original: ByteArray, length: Int): ByteArray? {
        if ((original[0].toInt() ushr 4) and 0x0f != 4) return null
        if ((original[9].toInt() and 0xff) != PROTO_TCP) return null
        val ihl = (original[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 20) return null
        // Never RST our own RST floods.
        val flags = original[ihl + 13].toInt() and 0xff
        if (flags and TcpPacketBuilder.FLAG_RST != 0) return null

        val srcIp = readInt(original, 12)
        val dstIp = readInt(original, 16)
        val srcPort = u16(original, ihl)
        val dstPort = u16(original, ihl + 2)
        val seq = readInt(original, ihl + 4)
        val ack = readInt(original, ihl + 8)
        val dataOff = ((original[ihl + 12].toInt() ushr 4) and 0x0f) * 4
        val payloadLen = (length - ihl - dataOff).coerceAtLeast(0)
        val syn = flags and TcpPacketBuilder.FLAG_SYN != 0
        val hasAck = flags and TcpPacketBuilder.FLAG_ACK != 0

        // RFC 793: RST seq/ack swap based on whether the segment carried ACK.
        val rstSeq: Int
        val rstAck: Int
        val rstFlags: Int
        if (hasAck) {
            rstSeq = ack
            rstAck = 0
            rstFlags = TcpPacketBuilder.FLAG_RST
        } else {
            rstSeq = 0
            rstAck = seq + payloadLen + (if (syn) 1 else 0)
            rstFlags = TcpPacketBuilder.FLAG_RST or TcpPacketBuilder.FLAG_ACK
        }

        return TcpPacketBuilder.build(
            srcIp = dstIp,
            dstIp = srcIp,
            srcPort = dstPort,
            dstPort = srcPort,
            seq = rstSeq,
            ack = rstAck,
            flags = rstFlags,
        )
    }

    fun buildIpv6Rst(original: ByteArray, length: Int): ByteArray? {
        if ((original[0].toInt() ushr 4) and 0x0f != 6) return null
        if ((original[6].toInt() and 0xff) != PROTO_TCP) return null
        if (length < 40 + 20) return null
        val t = 40
        val flags = original[t + 13].toInt() and 0xff
        if (flags and TcpPacketBuilder.FLAG_RST != 0) return null

        val srcPort = u16(original, t)
        val dstPort = u16(original, t + 2)
        val seq = readInt(original, t + 4)
        val ack = readInt(original, t + 8)
        val dataOff = ((original[t + 12].toInt() ushr 4) and 0x0f) * 4
        val payloadLen = (length - 40 - dataOff).coerceAtLeast(0)
        val syn = flags and TcpPacketBuilder.FLAG_SYN != 0
        val hasAck = flags and TcpPacketBuilder.FLAG_ACK != 0

        val rstSeq: Int
        val rstAck: Int
        val rstFlags: Int
        if (hasAck) {
            rstSeq = ack
            rstAck = 0
            rstFlags = TcpPacketBuilder.FLAG_RST
        } else {
            rstSeq = 0
            rstAck = seq + payloadLen + (if (syn) 1 else 0)
            rstFlags = TcpPacketBuilder.FLAG_RST or TcpPacketBuilder.FLAG_ACK
        }

        val tcpLen = 20
        val total = 40 + tcpLen
        val out = ByteArray(total)
        out[0] = 0x60
        out[4] = (tcpLen ushr 8).toByte()
        out[5] = (tcpLen and 0xff).toByte()
        out[6] = PROTO_TCP.toByte()
        out[7] = 64
        // src = original dst, dst = original src
        System.arraycopy(original, 24, out, 8, 16)
        System.arraycopy(original, 8, out, 24, 16)

        val ot = 40
        out[ot] = (dstPort ushr 8).toByte()
        out[ot + 1] = (dstPort and 0xff).toByte()
        out[ot + 2] = (srcPort ushr 8).toByte()
        out[ot + 3] = (srcPort and 0xff).toByte()
        writeInt(out, ot + 4, rstSeq)
        writeInt(out, ot + 8, rstAck)
        out[ot + 12] = 0x50
        out[ot + 13] = rstFlags.toByte()
        out[ot + 14] = 0xff.toByte()
        out[ot + 15] = 0xff.toByte()
        val sum = tcpChecksumIpv6(out, ot, tcpLen)
        out[ot + 16] = (sum ushr 8).toByte()
        out[ot + 17] = (sum and 0xff).toByte()
        return out
    }

    private fun writeInt(buf: ByteArray, off: Int, v: Int) {
        buf[off] = (v ushr 24).toByte()
        buf[off + 1] = (v ushr 16).toByte()
        buf[off + 2] = (v ushr 8).toByte()
        buf[off + 3] = v.toByte()
    }

    private fun readInt(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xff) shl 24) or
            ((buf[off + 1].toInt() and 0xff) shl 16) or
            ((buf[off + 2].toInt() and 0xff) shl 8) or
            (buf[off + 3].toInt() and 0xff)

    private fun u16(buf: ByteArray, off: Int): Int =
        ((buf[off].toInt() and 0xff) shl 8) or (buf[off + 1].toInt() and 0xff)

    private fun checksum(buf: ByteArray, offset: Int, length: Int): Int {
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

    private fun tcpChecksumIpv6(packet: ByteArray, tcpOff: Int, tcpLen: Int): Int {
        var sum = 0
        var p = 8
        while (p < 40) {
            sum += ((packet[p].toInt() and 0xff) shl 8) or (packet[p + 1].toInt() and 0xff)
            p += 2
        }
        sum += (tcpLen ushr 16) and 0xffff
        sum += tcpLen and 0xffff
        sum += PROTO_TCP
        val c0 = packet[tcpOff + 16]
        val c1 = packet[tcpOff + 17]
        packet[tcpOff + 16] = 0
        packet[tcpOff + 17] = 0
        var i = tcpOff
        val end = tcpOff + tcpLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xff) shl 8) or (packet[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (packet[i].toInt() and 0xff) shl 8
        packet[tcpOff + 16] = c0
        packet[tcpOff + 17] = c1
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }
}
