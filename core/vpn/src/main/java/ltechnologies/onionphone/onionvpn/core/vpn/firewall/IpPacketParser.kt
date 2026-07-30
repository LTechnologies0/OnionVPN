package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import java.net.InetAddress

/**
 * Parsed IP 5-tuple from a raw TUN packet (IPv4 or IPv6).
 * IPv4 keeps ints on the hot path; IPv6 uses [dstHost]/[srcHost] string forms.
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
    val ipVersion: Int = 4,
    private val srcHostOverride: String? = null,
    private val dstHostOverride: String? = null,
) {
    val isIpv6: Boolean get() = ipVersion == 6
    val srcIp: String get() = srcHostOverride ?: IpPacketParser.formatIpv4(srcIpInt)
    val dstIp: String get() = dstHostOverride ?: IpPacketParser.formatIpv4(dstIpInt)
}

object IpPacketParser {
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    fun parse(packet: ByteArray, length: Int): IpPacketInfo? {
        if (length < 20) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        return when (version) {
            4 -> parseV4(packet, length)
            6 -> parseV6(packet, length)
            else -> null
        }
    }

    private fun parseV4(packet: ByteArray, length: Int): IpPacketInfo? {
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
                    ipVersion = 4,
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
                    ipVersion = 4,
                )
            }
            else -> null
        }
    }

    /**
     * IPv6 without extension headers (TUN apps typically send TCP/UDP directly).
     * Next-header at offset 6; TCP/UDP header starts at 40.
     */
    private fun parseV6(packet: ByteArray, length: Int): IpPacketInfo? {
        if (length < 40) return null
        val next = packet[6].toInt() and 0xff
        val srcHost = formatIpv6(packet, 8) ?: return null
        val dstHost = formatIpv6(packet, 24) ?: return null
        return when (next) {
            PROTO_TCP -> {
                if (length < 40 + 14) return null
                val flags = packet[40 + 13].toInt() and 0xff
                val syn = flags and 0x02 != 0
                val ack = flags and 0x10 != 0
                IpPacketInfo(
                    protocol = PROTO_TCP,
                    srcIpInt = 0,
                    dstIpInt = 0,
                    srcPort = u16(packet, 40),
                    dstPort = u16(packet, 40 + 2),
                    isTcpSyn = syn && !ack,
                    isTcp = true,
                    isUdp = false,
                    ipVersion = 6,
                    srcHostOverride = srcHost,
                    dstHostOverride = dstHost,
                )
            }
            PROTO_UDP -> {
                if (length < 40 + 8) return null
                IpPacketInfo(
                    protocol = PROTO_UDP,
                    srcIpInt = 0,
                    dstIpInt = 0,
                    srcPort = u16(packet, 40),
                    dstPort = u16(packet, 40 + 2),
                    isTcpSyn = false,
                    isTcp = false,
                    isUdp = true,
                    ipVersion = 6,
                    srcHostOverride = srcHost,
                    dstHostOverride = dstHost,
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

    fun formatIpv6(packet: ByteArray, offset: Int): String? {
        if (packet.size < offset + 16) return null
        return runCatching {
            InetAddress.getByAddress(packet.copyOfRange(offset, offset + 16)).hostAddress
        }.getOrNull()?.substringBefore('%')
    }

    fun ipv4Bytes(ip: Int, out: ByteArray): ByteArray {
        require(out.size >= 4) { "out must be ≥4 bytes" }
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
