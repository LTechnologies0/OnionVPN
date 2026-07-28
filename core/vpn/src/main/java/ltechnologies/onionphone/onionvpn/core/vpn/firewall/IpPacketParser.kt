package ltechnologies.onionphone.onionvpn.core.vpn.firewall

/**
 * Parsed IPv4 5-tuple from a raw TUN IP packet.
 * IPs are kept as ints on the hot path; string forms are lazy (prompts / journal).
 * IPv6 is ignored for interactive firewall MVP (kill-switch still blackholes IPv6).
 */
data class IpPacketInfo(
    val protocol: Int,
    val srcIpInt: Int,
    val dstIpInt: Int,
    val srcPort: Int,
    val dstPort: Int,
    val isTcpSyn: Boolean,
    val isTcp: Boolean,
    val isUdp: Boolean,
) {
    val srcIp: String get() = IpPacketParser.formatIpv4(srcIpInt)
    val dstIp: String get() = IpPacketParser.formatIpv4(dstIpInt)
}

object IpPacketParser {
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun parse(packet: ByteArray, length: Int): IpPacketInfo? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl + 4) return null
        val protocol = packet[9].toInt() and 0xff
        val srcIpInt = ipv4Int(packet, 12)
        val dstIpInt = ipv4Int(packet, 16)
        return when (protocol) {
            PROTO_TCP -> {
                if (length < ihl + 14) return null
                val srcPort = u16(packet, ihl)
                val dstPort = u16(packet, ihl + 2)
                val flags = packet[ihl + 13].toInt() and 0xff
                val syn = flags and 0x02 != 0
                val ack = flags and 0x10 != 0
                IpPacketInfo(
                    protocol = PROTO_TCP,
                    srcIpInt = srcIpInt,
                    dstIpInt = dstIpInt,
                    srcPort = srcPort,
                    dstPort = dstPort,
                    isTcpSyn = syn && !ack,
                    isTcp = true,
                    isUdp = false,
                )
            }
            PROTO_UDP -> {
                if (length < ihl + 8) return null
                IpPacketInfo(
                    protocol = PROTO_UDP,
                    srcIpInt = srcIpInt,
                    dstIpInt = dstIpInt,
                    srcPort = u16(packet, ihl),
                    dstPort = u16(packet, ihl + 2),
                    isTcpSyn = false,
                    isTcp = false,
                    isUdp = true,
                )
            }
            else -> null
        }
    }

    fun protocolLabel(protocol: Int): String = when (protocol) {
        PROTO_TCP -> "TCP"
        PROTO_UDP -> "UDP"
        else -> "IP/$protocol"
    }

    fun formatIpv4(ip: Int): String =
        "${(ip ushr 24) and 0xff}.${(ip ushr 16) and 0xff}." +
            "${(ip ushr 8) and 0xff}.${ip and 0xff}"

    fun ipv4Bytes(ip: Int, out: ByteArray = ByteArray(4)): ByteArray {
        out[0] = (ip ushr 24).toByte()
        out[1] = (ip ushr 16).toByte()
        out[2] = (ip ushr 8).toByte()
        out[3] = ip.toByte()
        return out
    }

    private fun ipv4Int(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
}
