package ltechnologies.onionphone.onionvpn.core.vpn.pac

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DnsCryptResolverTest {
    @Test
    fun resolvesARecordFromStub() {
        val executor = Executors.newSingleThreadExecutor()
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { stub ->
            val port = stub.localPort
            executor.execute {
                val buf = ByteArray(512)
                val packet = DatagramPacket(buf, buf.size)
                stub.soTimeout = 5_000
                stub.receive(packet)
                // Echo a minimal A answer: copy header, set QR+RA, ANCOUNT=1, append A rr.
                val qLen = packet.length
                val resp = ByteArray(qLen + 16)
                System.arraycopy(buf, 0, resp, 0, qLen)
                resp[2] = (resp[2].toInt() or 0x80).toByte() // QR
                resp[3] = (resp[3].toInt() or 0x80).toByte() // RA
                resp[6] = 0
                resp[7] = 1 // ANCOUNT
                var p = qLen
                resp[p++] = 0xC0.toByte()
                resp[p++] = 0x0C // pointer to QNAME
                resp[p++] = 0
                resp[p++] = 1 // A
                resp[p++] = 0
                resp[p++] = 1 // IN
                resp[p++] = 0
                resp[p++] = 0
                resp[p++] = 0
                resp[p++] = 60 // TTL
                resp[p++] = 0
                resp[p++] = 4
                // Globally routable (not TEST-NET) — resolver blackholes documentation/LAN.
                resp[p++] = 93.toByte()
                resp[p++] = 184.toByte()
                resp[p++] = 216.toByte()
                resp[p++] = 34
                stub.send(DatagramPacket(resp, p, packet.address, packet.port))
            }
            val addr = DnsCryptResolver.resolveIpv4("example.com", "127.0.0.1", port)
            assertEquals("93.184.216.34", addr.hostAddress)
        }
        executor.shutdownNow()
        executor.awaitTermination(2, TimeUnit.SECONDS)
        assertTrue(true)
    }

    @Test(expected = java.net.UnknownHostException::class)
    fun rejectsPrivateLanARecord() {
        val executor = Executors.newSingleThreadExecutor()
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { stub ->
            val port = stub.localPort
            executor.execute {
                val buf = ByteArray(512)
                val packet = DatagramPacket(buf, buf.size)
                stub.soTimeout = 5_000
                stub.receive(packet)
                val qLen = packet.length
                val resp = ByteArray(qLen + 16)
                System.arraycopy(buf, 0, resp, 0, qLen)
                resp[2] = (resp[2].toInt() or 0x80).toByte()
                resp[3] = (resp[3].toInt() or 0x80).toByte()
                resp[6] = 0
                resp[7] = 1
                var p = qLen
                resp[p++] = 0xC0.toByte()
                resp[p++] = 0x0C
                resp[p++] = 0
                resp[p++] = 1
                resp[p++] = 0
                resp[p++] = 1
                resp[p++] = 0
                resp[p++] = 0
                resp[p++] = 0
                resp[p++] = 60
                resp[p++] = 0
                resp[p++] = 4
                resp[p++] = 192.toByte()
                resp[p++] = 168.toByte()
                resp[p++] = 1
                resp[p++] = 1
                stub.send(DatagramPacket(resp, p, packet.address, packet.port))
            }
            try {
                DnsCryptResolver.resolveIpv4("evil.example", "127.0.0.1", port, timeoutMs = 3_000)
            } finally {
                executor.shutdownNow()
                executor.awaitTermination(2, TimeUnit.SECONDS)
            }
        }
    }

    @Test(expected = java.net.UnknownHostException::class)
    fun rejectsLoopbackLiteral() {
        DnsCryptResolver.resolveIpv4("127.0.0.1", "127.0.0.1", 53)
    }
}
