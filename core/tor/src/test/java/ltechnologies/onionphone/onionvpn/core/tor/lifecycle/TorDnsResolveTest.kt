package ltechnologies.onionphone.onionvpn.core.tor.lifecycle

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TorDnsResolveTest {
    @Test
    fun resolveA_parsesAnswerFromLocalStub() {
        val sock = DatagramSocket(0)
        val port = sock.localPort
        val executor = Executors.newSingleThreadExecutor()
        val answered = AtomicInteger(0)
        executor.execute {
            val buf = ByteArray(512)
            val req = DatagramPacket(buf, buf.size)
            sock.soTimeout = 5_000
            sock.receive(req)
            val id0 = buf[0]
            val id1 = buf[1]
            // Minimal A response: copy header id, QR=1 AA=1, 1 question 1 answer
            val nameEnd = findNameEnd(buf, 12)
            val qLen = nameEnd - 12 + 4 // name + type/class
            val resp = ByteArray(12 + qLen + 2 + 2 + 2 + 4 + 2 + 4)
            // header
            resp[0] = id0
            resp[1] = id1
            resp[2] = 0x81.toByte() // QR + RD + RA-ish
            resp[3] = 0x80.toByte()
            resp[4] = 0
            resp[5] = 1 // QD
            resp[6] = 0
            resp[7] = 1 // AN
            System.arraycopy(buf, 12, resp, 12, qLen)
            var o = 12 + qLen
            // pointer to name at offset 12
            resp[o++] = 0xC0.toByte()
            resp[o++] = 12
            resp[o++] = 0
            resp[o++] = 1 // A
            resp[o++] = 0
            resp[o++] = 1 // IN
            resp[o++] = 0
            resp[o++] = 0
            resp[o++] = 0
            resp[o++] = 60 // TTL
            resp[o++] = 0
            resp[o++] = 4
            resp[o++] = 192.toByte()
            resp[o++] = 0
            resp[o++] = 2
            resp[o++] = 1
            sock.send(
                DatagramPacket(resp, o, req.address, req.port),
            )
            answered.incrementAndGet()
            sock.close()
        }
        try {
            val ip = TorDnsResolve.resolveA(
                hostname = "example.com",
                dnsPort = port,
                timeoutMs = 3_000,
                dnsHost = "127.0.0.1",
            )
            assertEquals("192.0.2.1", ip)
            assertTrue(answered.get() >= 1)
        } finally {
            runCatching { sock.close() }
            executor.shutdownNow()
            executor.awaitTermination(2, TimeUnit.SECONDS)
        }
    }

    private fun findNameEnd(buf: ByteArray, start: Int): Int {
        var i = start
        while (i < buf.size) {
            val len = buf[i].toInt() and 0xff
            if (len == 0) return i + 1
            i += 1 + len
        }
        return buf.size
    }
}
