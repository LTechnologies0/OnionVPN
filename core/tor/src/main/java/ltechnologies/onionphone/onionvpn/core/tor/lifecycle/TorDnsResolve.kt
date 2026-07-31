package ltechnologies.onionphone.onionvpn.core.tor.lifecycle

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ThreadLocalRandom
import kotlin.math.min

/**
 * Minimal DNS A resolver aimed at Arti's DNSPort — app-layer equivalent of
 * control-spec `RESOLVE` when no ControlSocket exists.
 *
 * Builds a standard UDP query and parses the first A answer. Used only as a
 * Tor-side resolve path (never clearnet DNS).
 */
object TorDnsResolve {
    fun resolveA(
        hostname: String,
        dnsPort: Int,
        timeoutMs: Int = 15_000,
        dnsHost: String = "127.0.0.1",
    ): String {
        val host = hostname.trim().trimEnd('.').lowercase()
        require(host.isNotEmpty()) { "empty hostname" }
        require(!host.contains(' ')) { "invalid hostname" }
        val query = buildQuery(host)
        DatagramSocket().use { sock ->
            sock.soTimeout = timeoutMs.coerceIn(500, 60_000)
            sock.send(
                DatagramPacket(
                    query,
                    query.size,
                    InetAddress.getByName(dnsHost),
                    dnsPort,
                ),
            )
            val buf = ByteArray(512)
            val resp = DatagramPacket(buf, buf.size)
            sock.receive(resp)
            return parseFirstA(buf, resp.length)
                ?: throw IllegalStateException("DNSPort returned no A for $host")
        }
    }

    private fun buildQuery(hostname: String): ByteArray {
        val id = ThreadLocalRandom.current().nextInt(0, 0xFFFF)
        val labels = hostname.split('.').filter { it.isNotEmpty() }
        val nameLen = labels.sumOf { 1 + it.length } + 1
        val packet = ByteArray(12 + nameLen + 4)
        val bb = ByteBuffer.wrap(packet)
        bb.putShort(id.toShort())
        bb.putShort(0x0100) // RD
        bb.putShort(1) // QDCOUNT
        bb.putShort(0)
        bb.putShort(0)
        bb.putShort(0)
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "bad DNS label: $label" }
            bb.put(bytes.size.toByte())
            bb.put(bytes)
        }
        bb.put(0)
        bb.putShort(1) // TYPE A
        bb.putShort(1) // CLASS IN
        return packet
    }

    private fun parseFirstA(data: ByteArray, length: Int): String? {
        if (length < 12) return null
        val bb = ByteBuffer.wrap(data, 0, length)
        bb.position(4)
        val qd = bb.short.toInt() and 0xffff
        val an = bb.short.toInt() and 0xffff
        bb.short // NS
        bb.short // AR
        // Skip questions
        repeat(qd) {
            skipName(bb)
            if (bb.remaining() < 4) return null
            bb.short
            bb.short
        }
        repeat(an) {
            skipName(bb)
            if (bb.remaining() < 10) return null
            val type = bb.short.toInt() and 0xffff
            bb.short // class
            bb.int // ttl
            val rdLen = bb.short.toInt() and 0xffff
            if (bb.remaining() < rdLen) return null
            if (type == 1 && rdLen == 4) {
                val a = bb.get().toInt() and 0xff
                val b = bb.get().toInt() and 0xff
                val c = bb.get().toInt() and 0xff
                val d = bb.get().toInt() and 0xff
                return "$a.$b.$c.$d"
            }
            bb.position(min(bb.limit(), bb.position() + rdLen))
        }
        return null
    }

    private fun skipName(bb: ByteBuffer) {
        while (bb.hasRemaining()) {
            val len = bb.get().toInt() and 0xff
            when {
                len == 0 -> return
                len and 0xC0 == 0xC0 -> {
                    // pointer — consume second byte and done
                    if (!bb.hasRemaining()) return
                    bb.get()
                    return
                }
                else -> {
                    if (bb.remaining() < len) {
                        bb.position(bb.limit())
                        return
                    }
                    bb.position(bb.position() + len)
                }
            }
        }
    }
}
