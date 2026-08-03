package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class LeakPacketFilterTest {
    @Before
    fun reset() {
        LeakPacketFilter.resetStats()
    }

    @Test
    fun dnsUdp53_anyResolver_isDivert() {
        val pkt = ipv4Udp(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 53_000,
            dstPort = 53,
            payload = byteArrayOf(0x12, 0x34),
        )
        assertTrue(LeakPacketFilter.isDnsUdpPort53(pkt, pkt.size))
        assertEquals(
            LeakPacketFilter.UdpDisposition.DivertDns,
            LeakPacketFilter.classifyUdp(pkt, pkt.size),
        )
        assertFalse(LeakPacketFilter.shouldBlackholeUdp(pkt, pkt.size))
    }

    @Test
    fun dnsUdp53_ipv6_isDivertNotBlackhole() {
        val pkt = ipv6Udp(
            src = byteArrayOf(
                0xfd.toByte(), 0x00, 0x08, 0x08, 0x08, 0x08, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x02,
            ),
            dst = byteArrayOf(
                0xfd.toByte(), 0x00, 0x08, 0x08, 0x08, 0x08, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x01,
            ),
            srcPort = 53_000,
            dstPort = 53,
            payload = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
        )
        assertTrue(LeakPacketFilter.isIpv6DnsUdpPort53(pkt, pkt.size))
        assertTrue(LeakPacketFilter.isDnsUdpPort53(pkt, pkt.size))
        assertEquals(
            LeakPacketFilter.UdpDisposition.DivertDns,
            LeakPacketFilter.classifyUdp(pkt, pkt.size),
        )
        assertFalse(LeakPacketFilter.shouldBlackholeUdp(pkt, pkt.size))
        assertFalse(LeakPacketFilter.shouldDropEarly(pkt, pkt.size))
    }

    @Test
    fun quicOn443_isBlackholeQuic() {
        // Long-header QUIC (bit7 set)
        val payload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x00, 0x01, 0x08)
        val pkt = ipv4Udp(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 40_000,
            dstPort = 443,
            payload = payload,
        )
        assertEquals(
            LeakPacketFilter.UdpDisposition.Blackhole,
            LeakPacketFilter.classifyUdp(pkt, pkt.size),
        )
        assertEquals(
            LeakPacketFilter.BlackholeReason.QuicHttp3,
            LeakPacketFilter.classifyBlackholeReason(pkt, pkt.size),
        )
    }

    @Test
    fun stunMagicCookie_isBlackholeStun() {
        val payload = ByteArray(20)
        payload[0] = 0x00
        payload[1] = 0x01
        payload[4] = 0x21
        payload[5] = 0x12
        payload[6] = 0xA4.toByte()
        payload[7] = 0x42
        val pkt = ipv4Udp(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(74, 125, 24, 1),
            srcPort = 50_000,
            dstPort = 19_302,
            payload = payload,
        )
        assertEquals(
            LeakPacketFilter.BlackholeReason.StunWebrtc,
            LeakPacketFilter.classifyBlackholeReason(pkt, pkt.size),
        )
    }

    @Test
    fun tcpHttps_isTorrifiable() {
        val pkt = ipv4TcpSyn(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 40_000,
            dstPort = 443,
        )
        assertTrue(LeakPacketFilter.isTorrifiableIpv4Tcp(pkt, pkt.size))
        assertFalse(LeakPacketFilter.shouldDropEarly(pkt, pkt.size))
        assertEquals(null, LeakPacketFilter.blackholeBeforeTorTcp(pkt, pkt.size))
    }

    @Test
    fun privateLanTcp_blackholesBeforeTor() {
        val pkt = ipv4TcpSyn(
            srcIp = byteArrayOf(10, 8, 0, 2),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
            srcPort = 40_000,
            dstPort = 443,
        )
        assertTrue(LeakPacketFilter.shouldDropEarly(pkt, pkt.size))
        assertEquals(
            LeakPacketFilter.BlackholeReason.PrivateLan,
            LeakPacketFilter.blackholeBeforeTorTcp(pkt, pkt.size),
        )
        assertEquals(
            LeakPacketFilter.BlackholeReason.PrivateLan,
            LeakPacketFilter.classifyBlackholeReason(pkt, pkt.size),
        )
    }

    @Test
    fun privateLanUdp53_notDroppedEarly_forDivert() {
        val pkt = ipv4Udp(
            srcIp = byteArrayOf(10, 8, 0, 2),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
            srcPort = 53_000,
            dstPort = 53,
            payload = byteArrayOf(0x12, 0x34),
        )
        assertFalse(LeakPacketFilter.shouldDropEarly(pkt, pkt.size))
        assertTrue(LeakPacketFilter.isDnsUdpPort53(pkt, pkt.size))
        // UDP/53 is DivertDns — blackholeBeforeTorTcp must not force PrivateLan
        assertTrue(
            LeakPacketFilter.blackholeBeforeTorTcp(pkt, pkt.size) !=
                LeakPacketFilter.BlackholeReason.PrivateLan,
        )
    }

    @Test
    fun tcpDns53_notTorrifiable_forceDnsCryptUdp() {
        val pkt = ipv4TcpSyn(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 40_000,
            dstPort = 53,
        )
        assertFalse(LeakPacketFilter.isTorrifiableIpv4Tcp(pkt, pkt.size))
        assertEquals(
            LeakPacketFilter.BlackholeReason.TcpDns,
            LeakPacketFilter.classifyBlackholeReason(pkt, pkt.size),
        )
    }

    @Test
    fun icmp_droppedEarly() {
        val pkt = ByteArray(20)
        pkt[0] = 0x45
        pkt[9] = 1 // ICMP
        pkt[16] = 8
        pkt[17] = 8
        pkt[18] = 8
        pkt[19] = 8
        assertTrue(LeakPacketFilter.shouldDropEarly(pkt, pkt.size))
        assertEquals(
            LeakPacketFilter.BlackholeReason.Icmp,
            LeakPacketFilter.classifyBlackholeReason(pkt, pkt.size),
        )
    }

    private fun ipv4Udp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val ihl = 20
        val udpLen = 8 + payload.size
        val total = ihl + udpLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        pkt[2] = (total ushr 8).toByte()
        pkt[3] = (total and 0xff).toByte()
        pkt[9] = 17
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        pkt[ihl] = (srcPort ushr 8).toByte()
        pkt[ihl + 1] = (srcPort and 0xff).toByte()
        pkt[ihl + 2] = (dstPort ushr 8).toByte()
        pkt[ihl + 3] = (dstPort and 0xff).toByte()
        pkt[ihl + 4] = (udpLen ushr 8).toByte()
        pkt[ihl + 5] = (udpLen and 0xff).toByte()
        System.arraycopy(payload, 0, pkt, ihl + 8, payload.size)
        return pkt
    }

    private fun ipv6Udp(
        src: ByteArray,
        dst: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        require(src.size == 16 && dst.size == 16)
        val udpLen = 8 + payload.size
        val pkt = ByteArray(40 + udpLen)
        pkt[0] = 0x60
        pkt[4] = (udpLen ushr 8).toByte()
        pkt[5] = (udpLen and 0xff).toByte()
        pkt[6] = 17 // UDP
        pkt[7] = 64 // hop limit
        System.arraycopy(src, 0, pkt, 8, 16)
        System.arraycopy(dst, 0, pkt, 24, 16)
        pkt[40] = (srcPort ushr 8).toByte()
        pkt[41] = (srcPort and 0xff).toByte()
        pkt[42] = (dstPort ushr 8).toByte()
        pkt[43] = (dstPort and 0xff).toByte()
        pkt[44] = (udpLen ushr 8).toByte()
        pkt[45] = (udpLen and 0xff).toByte()
        System.arraycopy(payload, 0, pkt, 48, payload.size)
        return pkt
    }

    private fun ipv4TcpSyn(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
    ): ByteArray {
        val ihl = 20
        val tcpLen = 20
        val total = ihl + tcpLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        pkt[2] = (total ushr 8).toByte()
        pkt[3] = (total and 0xff).toByte()
        pkt[9] = 6
        System.arraycopy(srcIp, 0, pkt, 12, 4)
        System.arraycopy(dstIp, 0, pkt, 16, 4)
        pkt[ihl] = (srcPort ushr 8).toByte()
        pkt[ihl + 1] = (srcPort and 0xff).toByte()
        pkt[ihl + 2] = (dstPort ushr 8).toByte()
        pkt[ihl + 3] = (dstPort and 0xff).toByte()
        pkt[ihl + 12] = 0x50 // data offset
        pkt[ihl + 13] = 0x02 // SYN
        return pkt
    }
}
