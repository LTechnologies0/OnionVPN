package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpPacketParserTest {
    @Test
    fun parseTcpSyn() {
        // Minimal IPv4 + TCP SYN to 1.2.3.4:443 from 10.8.0.2:12345
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte() // v4, ihl=5
        packet[9] = 6 // TCP
        // src 10.8.0.2
        packet[12] = 10
        packet[13] = 8
        packet[14] = 0
        packet[15] = 2
        // dst 1.2.3.4
        packet[16] = 1
        packet[17] = 2
        packet[18] = 3
        packet[19] = 4
        // src port 12345
        packet[20] = 0x30
        packet[21] = 0x39
        // dst port 443
        packet[22] = 0x01
        packet[23] = 0xBB.toByte()
        packet[33] = 0x02 // SYN

        val info = IpPacketParser.parse(packet, packet.size)
        assertNotNull(info)
        assertEquals("10.8.0.2", info!!.srcIp)
        assertEquals(12345, info.srcPort)
        assertEquals("1.2.3.4", info.dstIp)
        assertEquals(443, info.dstPort)
        assertTrue(info.isTcp)
        assertTrue(info.isTcpSyn)
        assertEquals("TCP", IpPacketParser.protocolLabel(info.protocol))
    }

    @Test
    fun parseUdp() {
        val packet = ByteArray(28)
        packet[0] = 0x45.toByte()
        packet[9] = 17
        packet[12] = 10
        packet[13] = 8
        packet[14] = 0
        packet[15] = 2
        packet[16] = 8
        packet[17] = 8
        packet[18] = 8
        packet[19] = 8
        packet[20] = 0xC0.toByte()
        packet[21] = 0x00
        packet[22] = 0x00
        packet[23] = 53

        val info = IpPacketParser.parse(packet, packet.size)
        assertNotNull(info)
        assertTrue(info!!.isUdp)
        assertFalse(info.isTcpSyn)
        assertEquals(53, info.dstPort)
        assertEquals("8.8.8.8", info.dstIp)
    }

    @Test
    fun rejectIpv6() {
        val packet = ByteArray(40)
        packet[0] = 0x60.toByte()
        assertNull(IpPacketParser.parse(packet, packet.size))
    }
}
