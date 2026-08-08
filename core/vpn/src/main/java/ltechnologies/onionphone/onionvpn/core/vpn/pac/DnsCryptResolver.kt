package ltechnologies.onionphone.onionvpn.core.vpn.pac

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicInteger
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import timber.log.Timber

/**
 * Minimal DNS A lookup against the local DNSCrypt stub (UDP/53 on loopback).
 * Used by the PAC SOCKS bridge so name resolution never hits Tor DNSPort/exit DNS.
 *
 * Rejects private/loopback/CGNAT A answers (DNS rebinding / LAN SSRF via PAC).
 */
object DnsCryptResolver {
    private val queryId = AtomicInteger(1)

    fun resolveIpv4(
        hostname: String,
        dnsCryptHost: String,
        dnsCryptPort: Int,
        timeoutMs: Int = 8_000,
    ): InetAddress {
        val host = TorNetPolicy.normalizeHostname(hostname)
        if (host.isEmpty()) throw IllegalArgumentException("empty hostname")
        // Literal IPv4 — never CONNECT to blackholed destinations via PAC.
        TunnelEndpoints.parseIpv4Literal(host)?.let { ipInt ->
            if (TorNetPolicy.mustBlackholeIpv4Destination(ipInt)) {
                throw UnknownHostException("DNSCrypt: blackholed literal $host")
            }
            return InetAddress.getByName(host)
        }
        if (!TorNetPolicy.isValidClearnetHostname(host)) {
            throw IllegalArgumentException("invalid clearnet hostname: $host")
        }
        val qid = queryId.getAndIncrement() and 0xffff
        val query = buildQuery(qid, host)
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { socket ->
            socket.soTimeout = timeoutMs
            socket.send(
                DatagramPacket(
                    query,
                    query.size,
                    InetAddress.getByName(dnsCryptHost),
                    dnsCryptPort,
                ),
            )
            val buf = ByteArray(2048)
            val resp = DatagramPacket(buf, buf.size)
            socket.receive(resp)
            return parseARecord(buf, resp.length, qid)
                ?: throw UnknownHostException("DNSCrypt: no routable A for $host")
        }
    }

    private fun buildQuery(id: Int, hostname: String): ByteArray {
        val out = ByteArrayOutputStream()
        val d = DataOutputStream(out)
        d.writeShort(id)
        d.writeShort(0x0100) // RD
        d.writeShort(1) // QDCOUNT
        d.writeShort(0)
        d.writeShort(0)
        d.writeShort(0)
        for (label in hostname.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "bad DNS label" }
            d.writeByte(bytes.size)
            d.write(bytes)
        }
        d.writeByte(0)
        d.writeShort(1) // A
        d.writeShort(1) // IN
        d.flush()
        return out.toByteArray()
    }

    private fun parseARecord(buf: ByteArray, length: Int, expectId: Int): InetAddress? {
        if (length < 12) return null
        val input = DataInputStream(ByteArrayInputStream(buf, 0, length))
        val id = input.readUnsignedShort()
        if (id != expectId) {
            Timber.d("DNSCrypt reply id mismatch expect=$expectId got=$id — reject")
            return null
        }
        input.readUnsignedShort() // flags
        val qd = input.readUnsignedShort().coerceAtMost(TorNetPolicy.MAX_DNS_QDCOUNT)
        val an = input.readUnsignedShort().coerceAtMost(TorNetPolicy.MAX_DNS_ANSWERS)
        input.readUnsignedShort() // NS
        input.readUnsignedShort() // AR
        repeat(qd) { skipName(input); input.skipBytes(4) }
        repeat(an) {
            skipName(input)
            val type = input.readUnsignedShort()
            input.readUnsignedShort() // class
            input.readInt() // TTL
            val rdLen = input.readUnsignedShort()
            if (type == 1 && rdLen == 4) {
                val addr = ByteArray(4)
                input.readFully(addr)
                val ipInt = ((addr[0].toInt() and 0xff) shl 24) or
                    ((addr[1].toInt() and 0xff) shl 16) or
                    ((addr[2].toInt() and 0xff) shl 8) or
                    (addr[3].toInt() and 0xff)
                if (TorNetPolicy.mustBlackholeIpv4Destination(ipInt)) {
                    Timber.d(
                        "DNSCrypt A blackholed %d.%d.%d.%d — skip (rebinding/LAN)",
                        addr[0].toInt() and 0xff,
                        addr[1].toInt() and 0xff,
                        addr[2].toInt() and 0xff,
                        addr[3].toInt() and 0xff,
                    )
                } else {
                    return InetAddress.getByAddress(addr)
                }
            } else {
                input.skipBytes(rdLen)
            }
        }
        return null
    }

    private fun skipName(input: DataInputStream) {
        var jumps = 0
        while (true) {
            val len = input.readUnsignedByte()
            when {
                len == 0 -> return
                len and 0xC0 == 0xC0 -> {
                    input.readUnsignedByte()
                    return
                }
                else -> {
                    if (++jumps > 16) throw java.io.IOException("DNS name jump limit")
                    input.skipBytes(len)
                }
            }
        }
    }
}
