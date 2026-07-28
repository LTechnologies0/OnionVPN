package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApplicationLayerDetectorTest {

    @Test
    fun tcpSyn443LabeledHttps() {
        val packet = tcpSynPacket(dstPort = 443)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("HTTPS", dpi.label)
        assertEquals(ApplicationLayerDetector.Kind.HTTPS, dpi.kind)
    }

    @Test
    fun tcpSyn80LabeledHttp() {
        val packet = tcpSynPacket(dstPort = 80)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("HTTP", dpi.label)
    }

    @Test
    fun udpDnsQueryDetectedWithQname() {
        // IPv4 + UDP/53 + minimal DNS query for example.com A
        val dns = byteArrayOf(
            0x12, 0x34.toByte(), // id
            0x01, 0x00, // flags RD
            0x00, 0x01, // qd=1
            0x00, 0x00, // an
            0x00, 0x00, // ns
            0x00, 0x00, // ar
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            0x00, 0x01, // A
            0x00, 0x01, // IN
        )
        val packet = udpPacket(dstPort = 53, payload = dns)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("DNS", dpi.label)
        assertEquals(ApplicationLayerDetector.Kind.DNS, dpi.kind)
        assertNotNull(dpi.detail)
        assertTrue(dpi.detail!!.contains("example.com"))
    }

    @Test
    fun httpGetPayloadDetected() {
        val http = "GET /index.html HTTP/1.1\r\nHost: example.org\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)
        val packet = tcpDataPacket(dstPort = 80, payload = http, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("HTTP", dpi.label)
        assertTrue(dpi.detail!!.contains("Host example.org") || dpi.detail!!.contains("GET"))
    }

    @Test
    fun tlsClientHelloLabeledHttpsOn443() {
        // Minimal TLS record header + ClientHello type (no full SNI required)
        val payload = ByteArray(48)
        payload[0] = 0x16 // handshake
        payload[1] = 0x03
        payload[2] = 0x01
        payload[3] = 0x00
        payload[4] = 43 // record length
        payload[5] = 0x01 // client_hello
        payload[6] = 0x00
        payload[7] = 0x00
        payload[8] = 39
        val packet = tcpDataPacket(dstPort = 443, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("HTTPS", dpi.label)
        assertEquals(ApplicationLayerDetector.Kind.HTTPS, dpi.kind)
    }

    @Test
    fun udp443QuicLongHeader() {
        val payload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x01, 0x01)
        val packet = udpPacket(dstPort = 443, payload = payload)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("QUIC", dpi.label)
    }

    @Test
    fun tcp853LabeledDot() {
        val packet = tcpSynPacket(dstPort = 853)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("DoT", dpi.label)
    }

    private fun tcpSynPacket(dstPort: Int): ByteArray {
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte()
        packet[9] = 6
        packet[12] = 10
        packet[13] = 8
        packet[14] = 0
        packet[15] = 2
        packet[16] = 1
        packet[17] = 2
        packet[18] = 3
        packet[19] = 4
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = (dstPort ushr 8).toByte()
        packet[23] = dstPort.toByte()
        packet[32] = 0x50 // data offset 5 (20 bytes)
        packet[33] = 0x02 // SYN
        return packet
    }

    private fun tcpDataPacket(dstPort: Int, payload: ByteArray, syn: Boolean): ByteArray {
        val header = 40
        val packet = ByteArray(header + payload.size)
        packet[0] = 0x45.toByte()
        packet[9] = 6
        packet[12] = 10
        packet[13] = 8
        packet[14] = 0
        packet[15] = 2
        packet[16] = 1
        packet[17] = 2
        packet[18] = 3
        packet[19] = 4
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = (dstPort ushr 8).toByte()
        packet[23] = dstPort.toByte()
        packet[32] = 0x50
        packet[33] = if (syn) 0x02 else 0x18 // PSH+ACK
        System.arraycopy(payload, 0, packet, header, payload.size)
        return packet
    }

    private fun udpPacket(dstPort: Int, payload: ByteArray): ByteArray {
        val header = 28
        val packet = ByteArray(header + payload.size)
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
        packet[22] = (dstPort ushr 8).toByte()
        packet[23] = dstPort.toByte()
        val udpLen = 8 + payload.size
        packet[24] = (udpLen ushr 8).toByte()
        packet[25] = udpLen.toByte()
        System.arraycopy(payload, 0, packet, header, payload.size)
        return packet
    }
}
