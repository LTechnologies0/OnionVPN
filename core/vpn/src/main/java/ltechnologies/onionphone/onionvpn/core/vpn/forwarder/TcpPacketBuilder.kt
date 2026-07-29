package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Build IPv4 TCP packets for TUN injection (minimal userspace TCP). */
internal object TcpPacketBuilder {
    private const val IP_HEADER = 20
    private const val TCP_HEADER = 20

    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    fun build(
        srcIp: Int,
        dstIp: Int,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
        ack: Int,
        flags: Int,
        window: Int = 65535,
        payload: ByteArray = Empty,
        payloadOffset: Int = 0,
        payloadLength: Int = 0,
    ): ByteArray {
        val tcpLen = TCP_HEADER + payloadLength
        val total = IP_HEADER + tcpLen
        val packet = ByteArray(total)
        // IPv4
        packet[0] = 0x45
        packet[1] = 0
        packet[2] = (total ushr 8).toByte()
        packet[3] = total.toByte()
        packet[4] = 0
        packet[5] = 0
        packet[6] = 0x40 // DF
        packet[7] = 0
        packet[8] = 64
        packet[9] = 6 // TCP
        writeInt(packet, 12, srcIp)
        writeInt(packet, 16, dstIp)
        val ipSum = checksum(packet, 0, IP_HEADER)
        packet[10] = (ipSum ushr 8).toByte()
        packet[11] = ipSum.toByte()

        // TCP
        val t = IP_HEADER
        packet[t] = (srcPort ushr 8).toByte()
        packet[t + 1] = srcPort.toByte()
        packet[t + 2] = (dstPort ushr 8).toByte()
        packet[t + 3] = dstPort.toByte()
        writeInt(packet, t + 4, seq)
        writeInt(packet, t + 8, ack)
        packet[t + 12] = 0x50 // data offset 5 (20 bytes)
        packet[t + 13] = flags.toByte()
        packet[t + 14] = (window ushr 8).toByte()
        packet[t + 15] = window.toByte()
        // checksum 0 for now
        packet[t + 16] = 0
        packet[t + 17] = 0
        packet[t + 18] = 0
        packet[t + 19] = 0
        if (payloadLength > 0) {
            System.arraycopy(payload, payloadOffset, packet, t + TCP_HEADER, payloadLength)
        }
        val tcpSum = tcpChecksum(srcIp, dstIp, packet, t, tcpLen)
        packet[t + 16] = (tcpSum ushr 8).toByte()
        packet[t + 17] = tcpSum.toByte()
        return packet
    }

    fun parseTcpMeta(packet: ByteArray, length: Int): TcpMeta? {
        if (length < 40) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (packet[9].toInt() and 0xff != 6) return null
        if (length < ihl + 20) return null
        val dataOff = ((packet[ihl + 12].toInt() ushr 4) and 0x0f) * 4
        val payloadOff = ihl + dataOff
        val payloadLen = (length - payloadOff).coerceAtLeast(0)
        return TcpMeta(
            srcIp = readInt(packet, 12),
            dstIp = readInt(packet, 16),
            srcPort = u16(packet, ihl),
            dstPort = u16(packet, ihl + 2),
            seq = readInt(packet, ihl + 4),
            ack = readInt(packet, ihl + 8),
            flags = packet[ihl + 13].toInt() and 0xff,
            payloadOffset = payloadOff,
            payloadLength = payloadLen,
        )
    }

    data class TcpMeta(
        val srcIp: Int,
        val dstIp: Int,
        val srcPort: Int,
        val dstPort: Int,
        val seq: Int,
        val ack: Int,
        val flags: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
    ) {
        val syn: Boolean get() = flags and FLAG_SYN != 0
        val ackFlag: Boolean get() = flags and FLAG_ACK != 0
        val fin: Boolean get() = flags and FLAG_FIN != 0
        val rst: Boolean get() = flags and FLAG_RST != 0
        val synOnly: Boolean get() = syn && !ackFlag
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
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return (sum.inv() and 0xffff).toInt()
    }

    private fun tcpChecksum(srcIp: Int, dstIp: Int, packet: ByteArray, tcpOff: Int, tcpLen: Int): Int {
        val pseudo = ByteBuffer.allocate(12 + tcpLen).order(ByteOrder.BIG_ENDIAN)
        pseudo.putInt(srcIp)
        pseudo.putInt(dstIp)
        pseudo.put(0)
        pseudo.put(6)
        pseudo.putShort(tcpLen.toShort())
        pseudo.put(packet, tcpOff, tcpLen)
        return checksum(pseudo.array(), 0, pseudo.capacity())
    }

    private val Empty = ByteArray(0)
}
