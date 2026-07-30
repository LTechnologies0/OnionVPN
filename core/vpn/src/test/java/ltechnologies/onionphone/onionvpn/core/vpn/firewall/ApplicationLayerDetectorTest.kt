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
    fun tcpSyn22LabeledSsh() {
        val packet = tcpSynPacket(dstPort = 22)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("SSH", dpi.label)
    }

    @Test
    fun tcpSyn25LabeledSmtp() {
        val packet = tcpSynPacket(dstPort = 25)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("SMTP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun tcpSyn3389LabeledRdp() {
        val packet = tcpSynPacket(dstPort = 3389)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("RDP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun udpDnsQueryDetectedWithQname() {
        val dns = byteArrayOf(
            0x12, 0x34.toByte(),
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            0x00, 0x01,
            0x00, 0x01,
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
    fun mdnsPortLabeled() {
        val packet = udpPacket(dstPort = 5353, payload = ByteArray(12))
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("mDNS", ApplicationLayerDetector.classify(packet, packet.size, info).label)
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
    fun dohHttpDetected() {
        val http = "POST /dns-query HTTP/1.1\r\nHost: dns.google\r\nContent-Type: application/dns-message\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)
        val packet = tcpDataPacket(dstPort = 443, payload = http, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("DoH", dpi.label)
        assertEquals(ApplicationLayerDetector.Kind.DOH, dpi.kind)
    }

    @Test
    fun websocketUpgradeDetected() {
        val http = "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nSec-WebSocket-Key: x\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)
        val packet = tcpDataPacket(dstPort = 80, payload = http, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("WebSocket", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun http2PrefaceDetected() {
        val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val packet = tcpDataPacket(dstPort = 80, payload = preface, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("HTTP/2", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun sshBannerDetected() {
        val banner = "SSH-2.0-OpenSSH_9.0\r\n".toByteArray(Charsets.US_ASCII)
        val packet = tcpDataPacket(dstPort = 22, payload = banner, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("SSH", dpi.label)
        assertTrue(dpi.detail!!.contains("OpenSSH"))
    }

    @Test
    fun tlsClientHelloLabeledHttpsOn443() {
        val payload = ByteArray(48)
        payload[0] = 0x16
        payload[1] = 0x03
        payload[2] = 0x01
        payload[3] = 0x00
        payload[4] = 43
        payload[5] = 0x01
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
    fun tlsOn993LabeledImaps() {
        val payload = ByteArray(48)
        payload[0] = 0x16
        payload[1] = 0x03
        payload[2] = 0x01
        payload[3] = 0x00
        payload[4] = 43
        payload[5] = 0x01
        val packet = tcpDataPacket(dstPort = 993, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("IMAPS", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun udp443QuicLabeledHttp3() {
        val payload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x01, 0x01)
        val packet = udpPacket(dstPort = 443, payload = payload)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("HTTP/3", dpi.label)
        assertEquals(ApplicationLayerDetector.Kind.QUIC, dpi.kind)
    }

    @Test
    fun stunMagicCookieDetected() {
        val payload = ByteArray(20)
        payload[0] = 0x00
        payload[1] = 0x01 // binding request
        payload[4] = 0x21
        payload[5] = 0x12
        payload[6] = 0xA4.toByte()
        payload[7] = 0x42
        val packet = udpPacket(dstPort = 3478, payload = payload)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("STUN", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun wireGuardHandshakeDetected() {
        val payload = ByteArray(148)
        payload[0] = 1 // initiation
        val packet = udpPacket(dstPort = 51820, payload = payload)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("WireGuard", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun mqttConnectDetected() {
        // Fixed header 0x10, remaining len, name len=4 "MQTT", level, flags, keepalive
        val payload = byteArrayOf(
            0x10, 0x0C,
            0x00, 0x04,
            'M'.code.toByte(), 'Q'.code.toByte(), 'T'.code.toByte(), 'T'.code.toByte(),
            0x04, 0x02, 0x00, 0x3C,
            0x00, 0x00,
        )
        val packet = tcpDataPacket(dstPort = 1883, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("MQTT", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun sipInviteDetected() {
        val sip = "INVITE sip:bob@example.com SIP/2.0\r\n".toByteArray(Charsets.US_ASCII)
        val packet = udpPacket(dstPort = 5060, payload = sip)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("SIP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun socks5GreetingDetected() {
        val payload = byteArrayOf(0x05, 0x01, 0x00)
        val packet = tcpDataPacket(dstPort = 1080, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("SOCKS5", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun rdpTpktDetected() {
        val payload = byteArrayOf(
            0x03, 0x00, 0x00, 0x2B,
            0x26, 0xE0.toByte(), 0x00, 0x00,
            0x00, 0x00, 0x00,
        )
        val packet = tcpDataPacket(dstPort = 3389, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("RDP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun vncBannerDetected() {
        val payload = "RFB 003.008\n".toByteArray(Charsets.US_ASCII)
        val packet = tcpDataPacket(dstPort = 5900, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("VNC", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun bitTorrentHandshakeDetected() {
        val payload = ByteArray(68)
        payload[0] = 19
        val proto = "BitTorrent protocol".toByteArray(Charsets.US_ASCII)
        System.arraycopy(proto, 0, payload, 1, proto.size)
        val packet = tcpDataPacket(dstPort = 6881, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("BitTorrent", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun tcp853LabeledDot() {
        val packet = tcpSynPacket(dstPort = 853)
        val info = IpPacketParser.parse(packet, packet.size)!!
        val dpi = ApplicationLayerDetector.classify(packet, packet.size, info)
        assertEquals("DoT", dpi.label)
    }

    @Test
    fun dtlsRecordDetected() {
        val payload = ByteArray(13)
        payload[0] = 0x16
        payload[1] = 0xFE.toByte()
        payload[2] = 0xFD.toByte()
        val packet = udpPacket(dstPort = 4433, payload = payload)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("DTLS", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun catalogCoversHundredPlusKinds() {
        val kinds = ApplicationLayerDetector.Kind.entries.size
        // Original ~40 + 100 additions (minus UNKNOWN overlap).
        assertTrue("expected ≥110 kinds, got $kinds", kinds >= 110)
    }

    @Test
    fun tcpSyn389LabeledLdap() {
        val packet = tcpSynPacket(dstPort = 389)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("LDAP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun smbMagicDetected() {
        val payload = byteArrayOf(0xFF.toByte(), 'S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte()) +
            ByteArray(32)
        val packet = tcpDataPacket(dstPort = 445, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("SMB", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun amqpHeaderDetected() {
        val payload = "AMQP\u0000\u0001\u0000\u0000".toByteArray()
        val packet = tcpDataPacket(dstPort = 5672, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("AMQP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun coapVersion1Detected() {
        // Ver=1, T=0 CON, TKL=0, code 0.01 GET
        val payload = byteArrayOf(0x40, 0x01, 0x00, 0x01)
        val packet = udpPacket(dstPort = 5683, payload = payload)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("CoAP", ApplicationLayerDetector.classify(packet, packet.size, info).label)
    }

    @Test
    fun bitcoinMagicDetected() {
        val payload = byteArrayOf(
            0xF9.toByte(), 0xBE.toByte(), 0xB4.toByte(), 0xD9.toByte(),
        ) + ByteArray(20)
        val packet = tcpDataPacket(dstPort = 8333, payload = payload, syn = false)
        val info = IpPacketParser.parse(packet, packet.size)!!
        assertEquals("Bitcoin", ApplicationLayerDetector.classify(packet, packet.size, info).label)
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
        packet[32] = 0x50
        packet[33] = 0x02
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
        packet[33] = if (syn) 0x02 else 0x18
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
