package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpPacketParserTest {
    @Test
    fun parseTcpSyn_rfc5737_passes() {
        // IPv4 + TCP SYN to 192.0.2.1:443 from 10.8.0.2:12345
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte()
        packet[9] = 6
        packet[12] = 10
        packet[13] = 8
        packet[14] = 0
        packet[15] = 2
        packet[16] = 192.toByte()
        packet[17] = 0
        packet[18] = 2
        packet[19] = 1
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = 0x01
        packet[23] = 0xBB.toByte()
        packet[33] = 0x02

        val info = IpPacketParser.parse(packet, packet.size)
        assertNotNull(info)
        assertEquals("10.8.0.2", info!!.srcIp)
        assertEquals(0x0A080002, info.srcIpInt)
        assertEquals(12345, info.srcPort)
        assertEquals("192.0.2.1", info.dstIp)
        assertEquals(443, info.dstPort)
        assertTrue(info.isTcp)
        assertTrue(info.isTcpSyn)
        assertEquals("TCP", IpPacketParser.protocolLabel(info.protocol))
    }

    @Test
    fun parseUdpDns_passes() {
        val packet = ByteArray(28)
        packet[0] = 0x45.toByte()
        packet[9] = 17
        packet[12] = 10
        packet[13] = 8
        packet[14] = 0
        packet[15] = 2
        // VPN DNS 10.8.0.1
        packet[16] = 10
        packet[17] = 8
        packet[18] = 0
        packet[19] = 1
        packet[20] = 0xC0.toByte()
        packet[21] = 0x00
        packet[22] = 0x00
        packet[23] = 53

        val info = IpPacketParser.parse(packet, packet.size)
        assertNotNull(info)
        assertTrue(info!!.isUdp)
        assertFalse(info.isTcpSyn)
        assertEquals(53, info.dstPort)
        assertEquals("10.8.0.1", info.dstIp)
    }

    @Test
    fun rejectTruncatedIpv4_fails() {
        val packet = ByteArray(19)
        packet[0] = 0x45.toByte()
        assertNull(IpPacketParser.parse(packet, packet.size))
    }

    @Test
    fun rejectBadTotalLength_fails() {
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte()
        packet[2] = 0
        packet[3] = 80 // claims 80 bytes
        packet[9] = 6
        packet[19] = 1
        packet[23] = 80
        assertNull(IpPacketParser.parse(packet, 40))
    }

    @Test
    fun rejectNonTcpUdpIpv6_fails() {
        val packet = ByteArray(40)
        packet[0] = 0x60.toByte()
        // next-header = 0 (hop-by-hop) → not TCP/UDP
        assertNull(IpPacketParser.parse(packet, packet.size))
    }

    @Test
    fun rejectDstPortZero_fails() {
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte()
        packet[9] = 6
        packet[16] = 192.toByte()
        packet[17] = 0
        packet[18] = 2
        packet[19] = 1
        // dst port 0
        packet[22] = 0
        packet[23] = 0
        packet[33] = 0x02
        assertNull(IpPacketParser.parse(packet, packet.size))
    }
}
