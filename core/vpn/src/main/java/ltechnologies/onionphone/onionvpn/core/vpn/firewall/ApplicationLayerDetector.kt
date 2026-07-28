package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsPacketParser
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Lightweight DPI for firewall UX: classify TCP/UDP flows as DNS / HTTP / HTTPS / TLS / …
 *
 * Hot path must stay cheap — call only on cold ASK/DENY/journal paths, never on every packet.
 *
 * Detection order:
 * 1. Payload signatures (DNS wire, HTTP methods, TLS ClientHello / record, QUIC)
 * 2. Well-known port heuristics when the first packet has no payload (TCP SYN)
 */
object ApplicationLayerDetector {

    data class Result(
        /** Short label for notifications (DNS, HTTP, HTTPS, TLS, DoT, QUIC, TCP, UDP). */
        val label: String,
        /** Optional detail: QNAME, Host, SNI, HTTP method+path. */
        val detail: String? = null,
        val kind: Kind = Kind.UNKNOWN,
    )

    enum class Kind {
        DNS,
        HTTP,
        HTTPS,
        TLS,
        DOT,
        QUIC,
        UNKNOWN,
    }

    fun classify(packet: ByteArray, length: Int, info: IpPacketInfo): Result {
        val payloadOff = transportPayloadOffset(packet, length, info)
        val payloadLen = if (payloadOff != null) length - payloadOff else 0

        if (payloadOff != null && payloadLen > 0) {
            payloadClassify(packet, payloadOff, payloadLen, info)?.let { return it }
        }
        return portHeuristic(info)
    }

    private fun payloadClassify(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (looksLikeDns(packet, offset, len, info)) {
            val parsed = DnsPacketParser.parse(packet, offset, len)
            val qname = parsed?.qname?.takeIf { it.isNotBlank() }
            val detail = when {
                qname != null && parsed?.isResponse == true -> "DNS response $qname"
                qname != null -> "DNS query $qname"
                else -> null
            }
            return Result(label = "DNS", detail = detail, kind = Kind.DNS)
        }

        if (info.isTcp && looksLikeHttp(packet, offset, len)) {
            val preview = httpPreview(packet, offset, len)
            return Result(label = "HTTP", detail = preview, kind = Kind.HTTP)
        }

        if (info.isTcp && looksLikeTls(packet, offset, len)) {
            val sni = extractTlsSni(packet, offset, len)
            val https = info.dstPort == 443 || info.dstPort == 8443
            return Result(
                label = if (https) "HTTPS" else "TLS",
                detail = sni?.let { "SNI $it" },
                kind = if (https) Kind.HTTPS else Kind.TLS,
            )
        }

        if (info.isUdp && looksLikeQuic(packet, offset, len, info)) {
            return Result(label = "QUIC", detail = "UDP/${info.dstPort}", kind = Kind.QUIC)
        }

        return null
    }

    private fun portHeuristic(info: IpPacketInfo): Result = when {
        info.dstPort == 53 || info.srcPort == 53 ->
            Result(label = "DNS", detail = null, kind = Kind.DNS)
        info.dstPort == 853 ->
            Result(label = "DoT", detail = "TLS DNS :853", kind = Kind.DOT)
        info.isTcp && (info.dstPort == 80 || info.dstPort == 8080 || info.dstPort == 8000) ->
            Result(label = "HTTP", detail = "port ${info.dstPort}", kind = Kind.HTTP)
        info.isTcp && (info.dstPort == 443 || info.dstPort == 8443) ->
            Result(label = "HTTPS", detail = "port ${info.dstPort}", kind = Kind.HTTPS)
        info.isUdp && (info.dstPort == 443 || info.dstPort == 80) ->
            Result(label = "QUIC", detail = "port ${info.dstPort}", kind = Kind.QUIC)
        info.isTcp ->
            Result(label = "TCP", detail = null, kind = Kind.UNKNOWN)
        info.isUdp ->
            Result(label = "UDP", detail = null, kind = Kind.UNKNOWN)
        else ->
            Result(
                label = IpPacketParser.protocolLabel(info.protocol),
                detail = null,
                kind = Kind.UNKNOWN,
            )
    }

    /**
     * DNS wire format: 12-byte header, QDCOUNT ≥ 1 for queries, sane flag bits.
     * Port 53 strongly preferred; also accept clear DNS shape on other ports (DoH-less plain DNS).
     */
    private fun looksLikeDns(packet: ByteArray, offset: Int, len: Int, info: IpPacketInfo): Boolean {
        if (len < 12) return false
        val onDnsPort = info.dstPort == 53 || info.srcPort == 53
        val flags = ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)
        val opcode = (flags ushr 11) and 0x0f
        if (opcode > 2) return false
        val qd = ((packet[offset + 4].toInt() and 0xff) shl 8) or
            (packet[offset + 5].toInt() and 0xff)
        val an = ((packet[offset + 6].toInt() and 0xff) shl 8) or
            (packet[offset + 7].toInt() and 0xff)
        val ns = ((packet[offset + 8].toInt() and 0xff) shl 8) or
            (packet[offset + 9].toInt() and 0xff)
        val ar = ((packet[offset + 10].toInt() and 0xff) shl 8) or
            (packet[offset + 11].toInt() and 0xff)
        if (qd > 16 || an > 64 || ns > 64 || ar > 64) return false
        if (qd == 0 && an == 0) return false
        val parsed = DnsPacketParser.parse(packet, offset, len)
        if (parsed?.qname != null) return true
        return onDnsPort && qd >= 1
    }

    private fun looksLikeHttp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val methods = arrayOf(
            "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ",
            "HTTP/1.",
        )
        for (m in methods) {
            if (startsWithAscii(packet, offset, len, m)) return true
        }
        return false
    }

    private fun httpPreview(packet: ByteArray, offset: Int, len: Int): String? {
        val max = minOf(len, 256)
        val text = String(packet, offset, max, StandardCharsets.US_ASCII)
        val firstLine = text.lineSequence().firstOrNull()?.trim().orEmpty()
        if (firstLine.isEmpty()) return null
        val host = Regex("""(?im)^Host:\s*(\S+)""")
            .find(text)?.groupValues?.getOrNull(1)
        val line = firstLine.take(80)
        return if (host != null) "$line · Host $host" else line
    }

    /** TLS record: content-type 0x14–0x17, version 0x03 0x01–0x04. */
    private fun looksLikeTls(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        val type = packet[offset].toInt() and 0xff
        if (type !in 0x14..0x17) return false
        val major = packet[offset + 1].toInt() and 0xff
        val minor = packet[offset + 2].toInt() and 0xff
        return major == 0x03 && minor <= 0x04
    }

    /**
     * Best-effort SNI from a TLS ClientHello (handshake type 0x01).
     * Returns null if truncated / encrypted / not a ClientHello.
     */
    fun extractTlsSni(packet: ByteArray, offset: Int, len: Int): String? {
        if (len < 9) return null
        if ((packet[offset].toInt() and 0xff) != 0x16) return null // handshake record
        val recordLen = ((packet[offset + 3].toInt() and 0xff) shl 8) or
            (packet[offset + 4].toInt() and 0xff)
        if (recordLen < 4 || 5 + recordLen > len) {
            // Allow truncated first segment — parse what we have.
        }
        var p = offset + 5
        val end = offset + minOf(len, 5 + maxOf(recordLen, 0))
        if (p >= end) return null
        if ((packet[p].toInt() and 0xff) != 0x01) return null // client_hello
        p += 1
        if (p + 3 > end) return null
        val helloLen = ((packet[p].toInt() and 0xff) shl 16) or
            ((packet[p + 1].toInt() and 0xff) shl 8) or
            (packet[p + 2].toInt() and 0xff)
        p += 3
        val helloEnd = minOf(end, p + helloLen)
        if (p + 2 + 32 + 1 > helloEnd) return null
        p += 2 // client_version
        p += 32 // random
        if (p >= helloEnd) return null
        val sessionLen = packet[p].toInt() and 0xff
        p += 1 + sessionLen
        if (p + 2 > helloEnd) return null
        val cipherLen = ((packet[p].toInt() and 0xff) shl 8) or (packet[p + 1].toInt() and 0xff)
        p += 2 + cipherLen
        if (p + 1 > helloEnd) return null
        val compLen = packet[p].toInt() and 0xff
        p += 1 + compLen
        if (p + 2 > helloEnd) return null
        val extLen = ((packet[p].toInt() and 0xff) shl 8) or (packet[p + 1].toInt() and 0xff)
        p += 2
        val extEnd = minOf(helloEnd, p + extLen)
        while (p + 4 <= extEnd) {
            val type = ((packet[p].toInt() and 0xff) shl 8) or (packet[p + 1].toInt() and 0xff)
            val elen = ((packet[p + 2].toInt() and 0xff) shl 8) or (packet[p + 3].toInt() and 0xff)
            p += 4
            if (p + elen > extEnd) break
            if (type == 0x0000 && elen >= 5) { // server_name
                // list_len(2) name_type(1) name_len(2) name
                var q = p + 2
                if (q + 3 > p + elen) break
                val nameType = packet[q].toInt() and 0xff
                q += 1
                val nameLen = ((packet[q].toInt() and 0xff) shl 8) or (packet[q + 1].toInt() and 0xff)
                q += 2
                if (nameType == 0 && q + nameLen <= p + elen && nameLen in 1..253) {
                    return String(packet, q, nameLen, StandardCharsets.US_ASCII)
                        .lowercase(Locale.US)
                }
            }
            p += elen
        }
        return null
    }

    /** QUIC long-header packets set the high bit of the first byte (RFC 9000). */
    private fun looksLikeQuic(packet: ByteArray, offset: Int, len: Int, info: IpPacketInfo): Boolean {
        if (len < 5) return false
        if (info.dstPort != 443 && info.dstPort != 80) return false
        val b0 = packet[offset].toInt() and 0xff
        return (b0 and 0x80) != 0
    }

    private fun transportPayloadOffset(
        packet: ByteArray,
        length: Int,
        info: IpPacketInfo,
    ): Int? {
        if (length < 20) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl) return null
        return when {
            info.isTcp -> {
                if (length < ihl + 20) return null
                val dataOff = ((packet[ihl + 12].toInt() and 0xff) ushr 4) * 4
                if (dataOff < 20) return null
                val off = ihl + dataOff
                if (off > length) null else off
            }
            info.isUdp -> {
                val off = ihl + 8
                if (off > length) null else off
            }
            else -> null
        }
    }

    private fun startsWithAscii(packet: ByteArray, offset: Int, len: Int, prefix: String): Boolean {
        if (len < prefix.length) return false
        for (i in prefix.indices) {
            if ((packet[offset + i].toInt() and 0xff).toChar() != prefix[i]) return false
        }
        return true
    }
}
