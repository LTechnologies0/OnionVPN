package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SocksDnsBootstrapRelayTest {
    @Test
    fun isInetAQuery_detectsA() {
        assertTrue(SocksDnsBootstrapRelay.isInetAQuery(EXAMPLE_A_QUERY))
        // Flip QTYPE to AAAA (28)
        val aaaa = EXAMPLE_A_QUERY.copyOf()
        aaaa[aaaa.size - 4] = 0
        aaaa[aaaa.size - 3] = 28
        assertFalse(SocksDnsBootstrapRelay.isInetAQuery(aaaa))
    }

    @Test
    fun tcpBootstrap_usesHostnameResolver_forForceTcpPath() {
        val port = freePort()
        val hits = AtomicInteger(0)
        val relay = SocksDnsBootstrapRelay(
            listenPort = port,
            socksPort = 1, // unused when native resolve succeeds
            bindUdp = false,
            bindTcp = true,
            useSocksResolve = false,
            hostnameResolver = { host ->
                hits.incrementAndGet()
                assertEquals("example.com", host)
                "203.0.113.10"
            },
        )
        relay.start()
        try {
            assertTrue(relay.probeOnceTcp(timeoutMs = 3_000))
            Socket().use { sock ->
                sock.connect(InetSocketAddress(TunnelEndpoints.LOOPBACK, port), 2_000)
                sock.soTimeout = 3_000
                val out = DataOutputStream(sock.getOutputStream())
                out.writeShort(EXAMPLE_A_QUERY.size)
                out.write(EXAMPLE_A_QUERY)
                out.flush()
                val inp = DataInputStream(sock.getInputStream())
                val len = inp.readUnsignedShort()
                val resp = ByteArray(len)
                inp.readFully(resp)
                assertTrue(resp.size >= 12)
                assertEquals(EXAMPLE_A_QUERY[0], resp[0])
                assertEquals(EXAMPLE_A_QUERY[1], resp[1])
                // QR bit set
                assertTrue((resp[2].toInt() and 0x80) != 0)
                val parsed = DnsPacketParser.parse(resp, 0, resp.size)
                assertEquals(listOf("203.0.113.10"), parsed!!.aRecords)
            }
            assertTrue(hits.get() >= 1)
        } finally {
            relay.stop()
        }
    }

    private fun freePort(): Int {
        java.net.ServerSocket(0).use { return it.localPort }
    }

    companion object {
        private val EXAMPLE_A_QUERY = byteArrayOf(
            0x00, 0x01,
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
    }
}
