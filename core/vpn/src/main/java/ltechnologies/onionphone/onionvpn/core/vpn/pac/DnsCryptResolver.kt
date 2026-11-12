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

    /**
     * @param allowLanRoutable when true (hev Via LAN only), accept RFC1918 A answers.
     *   PAC must keep false — private A via PAC is rebinding/SSRF.
     */
    fun resolveIpv4(
        hostname: String,
        dnsCryptHost: String,
        dnsCryptPort: Int,
        timeoutMs: Int = 8_000,
        allowLanRoutable: Boolean = false,
    ): InetAddress {
        val host = TorNetPolicy.normalizeHostname(hostname)
        if (host.isEmpty()) throw IllegalArgumentException("empty hostname")
        // Literal IPv4 — PAC blackholes all private; hev may allow RFC1918 for Via LAN.
        TunnelEndpoints.parseIpv4Literal(host)?.let { ipInt ->
            val refuse = if (allowLanRoutable) {
                TorNetPolicy.mustRefuseSocksConnectIpv4(ipInt)
            } else {
                TorNetPolicy.mustBlackholeIpv4Destination(ipInt)
            }
            if (refuse) {
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
            socket.send(
                DatagramPacket(
                    query,
                    query.size,
                    InetAddress.getByName(dnsCryptHost),
                    dnsCryptPort,
                ),
            )
            val buf = ByteArray(2048)
            val deadline = System.currentTimeMillis() + timeoutMs.coerceAtLeast(500)
            var lastMismatch = false
            while (System.currentTimeMillis() < deadline) {
                val remaining = (deadline - System.currentTimeMillis()).toInt().coerceAtLeast(1)
                socket.soTimeout = remaining
                val resp = DatagramPacket(buf, buf.size)
                try {
                    socket.receive(resp)
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
                if (resp.length < 12) continue
                val gotId = ((buf[0].toInt() and 0xff) shl 8) or (buf[1].toInt() and 0xff)
                if (gotId != qid) {
                    lastMismatch = true
                    Timber.d("DNSCrypt reply id mismatch expect=$qid got=$gotId — skip stale")
                    continue
                }
                val flags = ((buf[2].toInt() and 0xff) shl 8) or (buf[3].toInt() and 0xff)
                if (flags and 0x8000 == 0) continue // QR
                // QNAME must echo the request (stale loopback replies).
                val parsed = ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsPacketParser
                    .parse(buf, 0, resp.length)
                val rn = parsed?.qname?.lowercase()?.trimEnd('.')
                if (!rn.isNullOrEmpty() && rn != host) {
                    Timber.d("DNSCrypt QNAME mismatch expect=$host got=$rn — skip")
                    continue
                }
                return parseARecord(buf, resp.length, qid, allowLanRoutable)
                    ?: throw UnknownHostException("DNSCrypt: no routable A for $host")
            }
            val why = if (lastMismatch) "id mismatch/timeout" else "timeout"
            throw UnknownHostException("DNSCrypt: $why for $host")
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

    private fun parseARecord(
        buf: ByteArray,
        length: Int,
        expectId: Int,
        allowLanRoutable: Boolean = false,
    ): InetAddress? {
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
        // Prefer globally routable A over RFC1918 when allowLanRoutable (W4-02: rebinding
        // private-first must not pin Via LAN). Fall back to first acceptable LAN A.
        var lanFallback: InetAddress? = null
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
                // Automap virtuals are onion-only — never accept as clearnet DNSCrypt A.
                if (TunnelEndpoints.isAutomapVirtualIpv4(ipInt)) {
                    Timber.d("DNSCrypt A in Automap range — reject (hijack)")
                    return@repeat
                }
                val refuse = if (allowLanRoutable) {
                    TorNetPolicy.mustRefuseSocksConnectIpv4(ipInt)
                } else {
                    TorNetPolicy.mustBlackholeIpv4Destination(ipInt)
                }
                if (refuse) {
                    Timber.d("DNSCrypt A blackholed — skip (rebinding/private)")
                } else if (allowLanRoutable && TorNetPolicy.isLanRoutableIpv4(ipInt)) {
                    if (lanFallback == null) {
                        lanFallback = InetAddress.getByAddress(addr.copyOf())
                    }
                } else {
                    return InetAddress.getByAddress(addr)
                }
            } else {
                input.skipBytes(rdLen)
            }
        }
        return lanFallback
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
