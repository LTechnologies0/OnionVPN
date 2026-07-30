package ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi

import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import java.nio.charset.StandardCharsets
import java.util.Locale

/** Nested DPI signature probes (branch predicates for the payload graph). */
internal object DpiSignatures {
    fun looksLikeDns(packet: ByteArray, offset: Int, len: Int, info: IpPacketInfo): Boolean {
        if (len < 12) return false
        val onDnsPort = info.dstPort == 53 || info.srcPort == 53 ||
            info.dstPort == 5353 || info.dstPort == 5355
        // DNS-over-TCP starts with 2-byte length prefix.
        var off = offset
        var dnsLen = len
        if (info.isTcp && len >= 14) {
            val prefixed = ((packet[offset].toInt() and 0xff) shl 8) or
                (packet[offset + 1].toInt() and 0xff)
            if (prefixed in 12..len - 2 && prefixed + 2 <= len) {
                off = offset + 2
                dnsLen = prefixed
            }
        }
        val flags = ((packet[off + 2].toInt() and 0xff) shl 8) or
            (packet[off + 3].toInt() and 0xff)
        val opcode = (flags ushr 11) and 0x0f
        if (opcode > 2) return false
        val qd = DpiBytes.u16(packet, off + 4)
        val an = DpiBytes.u16(packet, off + 6)
        val ns = DpiBytes.u16(packet, off + 8)
        val ar = DpiBytes.u16(packet, off + 10)
        if (qd > 16 || an > 64 || ns > 64 || ar > 64) return false
        if (qd == 0 && an == 0) return false
        val parsed = DnsPacketParser.parse(packet, off, dnsLen)
        if (parsed?.qname != null) return true
        return onDnsPort && qd >= 1
    }

    fun looksLikeHttp2Preface(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

    fun looksLikeHttp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        for (m in HTTP_METHODS) {
            if (DpiBytes.startsWithAscii(packet, offset, len, m)) return true
        }
        return false
    }

    fun httpPreview(text: String): String? {
        val firstLine = text.lineSequence().firstOrNull()?.trim().orEmpty()
        if (firstLine.isEmpty()) return null
        val host = Regex("""(?im)^Host:\s*(\S+)""")
            .find(text)?.groupValues?.getOrNull(1)
        val line = firstLine.take(80)
        return if (host != null) "$line · Host $host" else line
    }

    fun looksLikeTls(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        val type = packet[offset].toInt() and 0xff
        if (type !in 0x14..0x17) return false
        val major = packet[offset + 1].toInt() and 0xff
        val minor = packet[offset + 2].toInt() and 0xff
        return major == 0x03 && minor <= 0x04
    }

    fun looksLikeDtls(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 13) return false
        val type = packet[offset].toInt() and 0xff
        if (type !in 0x14..0x17) return false
        val major = packet[offset + 1].toInt() and 0xff
        val minor = packet[offset + 2].toInt() and 0xff
        // DTLS 1.0 = FE FF, 1.2 = FE FD, 1.3 = FE FC
        return major == 0xFE && minor in 0xFC..0xFF
    }

    fun extractTlsSni(packet: ByteArray, offset: Int, len: Int): String? {
        if (len < 9) return null
        if ((packet[offset].toInt() and 0xff) != 0x16) return null
        val recordLen = DpiBytes.u16(packet, offset + 3)
        var p = offset + 5
        val end = offset + minOf(len, 5 + maxOf(recordLen, 0))
        if (p >= end) return null
        if ((packet[p].toInt() and 0xff) != 0x01) return null
        p += 1
        if (p + 3 > end) return null
        val helloLen = ((packet[p].toInt() and 0xff) shl 16) or
            ((packet[p + 1].toInt() and 0xff) shl 8) or
            (packet[p + 2].toInt() and 0xff)
        p += 3
        val helloEnd = minOf(end, p + helloLen)
        if (p + 2 + 32 + 1 > helloEnd) return null
        p += 2
        p += 32
        if (p >= helloEnd) return null
        val sessionLen = packet[p].toInt() and 0xff
        p += 1 + sessionLen
        if (p + 2 > helloEnd) return null
        val cipherLen = DpiBytes.u16(packet, p)
        p += 2 + cipherLen
        if (p + 1 > helloEnd) return null
        val compLen = packet[p].toInt() and 0xff
        p += 1 + compLen
        if (p + 2 > helloEnd) return null
        val extLen = DpiBytes.u16(packet, p)
        p += 2
        val extEnd = minOf(helloEnd, p + extLen)
        while (p + 4 <= extEnd) {
            val type = DpiBytes.u16(packet, p)
            val elen = DpiBytes.u16(packet, p + 2)
            p += 4
            if (p + elen > extEnd) break
            if (type == 0x0000 && elen >= 5) {
                var q = p + 2
                if (q + 3 > p + elen) break
                val nameType = packet[q].toInt() and 0xff
                q += 1
                val nameLen = DpiBytes.u16(packet, q)
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

    fun looksLikeQuic(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        val b0 = packet[offset].toInt() and 0xff
        // Long header (bit7=1) or short header with fixed bit (bit6=1) — RFC 9000.
        return (b0 and 0x80) != 0 || (b0 and 0x40) != 0
    }

    fun looksLikeSsh(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "SSH-")

    fun looksLikeFtp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (DpiBytes.startsWithAscii(packet, offset, len, "USER ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "PASS ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "QUIT")
        ) {
            return true
        }
        // Server greeting "220 "
        return len >= 4 &&
            (packet[offset].toInt() and 0xff) == '2'.code &&
            (packet[offset + 1].toInt() and 0xff) == '2'.code &&
            (packet[offset + 2].toInt() and 0xff) == '0'.code &&
            (packet[offset + 3].toInt() and 0xff) == ' '.code
    }

    fun looksLikeSmtp(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in SMTP_PREFIXES) {
            if (DpiBytes.startsWithAscii(packet, offset, len, p)) return true
        }
        return len >= 4 &&
            (packet[offset].toInt() and 0xff) == '2'.code &&
            (packet[offset + 1].toInt() and 0xff) == '2'.code &&
            (packet[offset + 2].toInt() and 0xff) == '0'.code &&
            (packet[offset + 3].toInt() and 0xff) == ' '.code &&
            DpiBytes.asciiContains(packet, offset, minOf(len, 64), "ESMTP")
    }

    fun looksLikeImap(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "* OK") ||
            DpiBytes.startsWithAscii(packet, offset, len, "* PREAUTH") ||
            DpiBytes.asciiStartsWithTagCommand(packet, offset, len, "LOGIN") ||
            DpiBytes.asciiStartsWithTagCommand(packet, offset, len, "AUTHENTICATE")

    fun looksLikePop3(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "+OK") ||
            DpiBytes.startsWithAscii(packet, offset, len, "-ERR") ||
            DpiBytes.startsWithAscii(packet, offset, len, "USER ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "PASS ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "STAT") ||
            DpiBytes.startsWithAscii(packet, offset, len, "RETR ")

    fun looksLikeSip(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in SIP_PREFIXES) {
            if (DpiBytes.startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    fun looksLikeRtsp(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in RTSP_PREFIXES) {
            if (DpiBytes.startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    fun looksLikeSsdp(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "M-SEARCH ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "NOTIFY ")

    fun looksLikeXmpp(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "<?xml") ||
            DpiBytes.startsWithAscii(packet, offset, len, "<stream:stream") ||
            DpiBytes.startsWithAscii(packet, offset, len, "<stream:")

    fun looksLikeIrc(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in IRC_PREFIXES) {
            if (DpiBytes.startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    fun looksLikeRedis(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 3) return false
        val c0 = packet[offset].toInt() and 0xff
        // RESP: *n\r\n  or +OK / -ERR / $ / :
        if (c0 == '*'.code || c0 == '+'.code || c0 == '-'.code ||
            c0 == '$'.code || c0 == ':'.code
        ) {
            // Prefer clear Redis verbs in the first chunk.
            return DpiBytes.asciiContains(packet, offset, minOf(len, 64), "\r\n") &&
                (
                    DpiBytes.asciiContains(packet, offset, minOf(len, 64), "PING") ||
                        DpiBytes.asciiContains(packet, offset, minOf(len, 64), "AUTH") ||
                        DpiBytes.asciiContains(packet, offset, minOf(len, 64), "INFO") ||
                        DpiBytes.asciiContains(packet, offset, minOf(len, 64), "HELLO") ||
                        c0 == '*'.code
                    )
        }
        return false
    }

    fun looksLikeBitTorrent(packet: ByteArray, offset: Int, len: Int): Boolean =
        len >= 20 &&
            (packet[offset].toInt() and 0xff) == 19 &&
            DpiBytes.startsWithAscii(packet, offset + 1, len - 1, "BitTorrent protocol")

    fun looksLikeSocks(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 2) return false
        val ver = packet[offset].toInt() and 0xff
        return when (ver) {
            5 -> {
                // VER NMETHODS METHODS…
                val n = packet[offset + 1].toInt() and 0xff
                n in 1..16 && len >= 2 + n
            }
            4 -> len >= 8 && (packet[offset + 1].toInt() and 0xff) in 1..2
            else -> false
        }
    }

    fun looksLikeRdp(packet: ByteArray, offset: Int, len: Int): Boolean {
        // TPKT version 3 + X.224 Connection Request (CR length / type 0xE0)
        if (len < 7) return false
        if ((packet[offset].toInt() and 0xff) != 3) return false
        if ((packet[offset + 1].toInt() and 0xff) != 0) return false
        val tpktLen = DpiBytes.u16(packet, offset + 2)
        if (tpktLen < 7 || tpktLen > len + 64) return false
        val li = packet[offset + 4].toInt() and 0xff
        val code = packet[offset + 5].toInt() and 0xff
        return li >= 6 && (code == 0xE0 || code == 0xD0)
    }

    fun looksLikeVnc(packet: ByteArray, offset: Int, len: Int): Boolean =
        DpiBytes.startsWithAscii(packet, offset, len, "RFB ")

    fun looksLikePostgres(packet: ByteArray, offset: Int, len: Int): Boolean {
        // StartupMessage: int32 len + int32 protocol (3<<16|0) = 196608
        if (len < 8) return false
        val msgLen = ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)
        if (msgLen < 8 || msgLen > 10_000) return false
        val proto = ((packet[offset + 4].toInt() and 0xff) shl 24) or
            ((packet[offset + 5].toInt() and 0xff) shl 16) or
            ((packet[offset + 6].toInt() and 0xff) shl 8) or
            (packet[offset + 7].toInt() and 0xff)
        return proto == 196608 || proto == 80877103 // SSLRequest
    }

    fun looksLikeMysql(packet: ByteArray, offset: Int, len: Int): Boolean {
        // Server greeting: 3-byte len + seq 0 + protocol version 10 + version string
        if (len < 10) return false
        val payloadLen = (packet[offset].toInt() and 0xff) or
            ((packet[offset + 1].toInt() and 0xff) shl 8) or
            ((packet[offset + 2].toInt() and 0xff) shl 16)
        val seq = packet[offset + 3].toInt() and 0xff
        val proto = packet[offset + 4].toInt() and 0xff
        return seq == 0 && proto == 10 && payloadLen in 20..1024
    }

    fun looksLikeMqtt(packet: ByteArray, offset: Int, len: Int): Boolean {
        // CONNECT: type=1 (0x10), remaining length, protocol name MQTT / MQIsdp
        if (len < 10) return false
        if ((packet[offset].toInt() and 0xff) != 0x10) return false
        // Skip remaining length (1–4 bytes varint)
        var p = offset + 1
        var mul = 1
        var rem = 0
        repeat(4) {
            if (p >= offset + len) return false
            val b = packet[p].toInt() and 0xff
            p++
            rem += (b and 0x7f) * mul
            mul *= 128
            if (b and 0x80 == 0) {
                if (p + 2 > offset + len) return false
                val nameLen = DpiBytes.u16(packet, p)
                p += 2
                if (p + nameLen > offset + len || nameLen !in 4..6) return false
                val name = String(packet, p, nameLen, StandardCharsets.US_ASCII)
                return name == "MQTT" || name == "MQIsdp"
            }
        }
        return false
    }

    fun looksLikeStun(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 20) return false
        // First two bits must be 0; magic cookie at bytes 4..7
        if ((packet[offset].toInt() and 0xC0) != 0) return false
        return (packet[offset + 4].toInt() and 0xff) == 0x21 &&
            (packet[offset + 5].toInt() and 0xff) == 0x12 &&
            (packet[offset + 6].toInt() and 0xff) == 0xA4 &&
            (packet[offset + 7].toInt() and 0xff) == 0x42
    }

    fun looksLikeWireGuard(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val type = packet[offset].toInt() and 0xff
        // Types 1..4 with reserved zeros; handshake initiation is 148 bytes.
        if (type !in 1..4) return false
        if ((packet[offset + 1].toInt() and 0xff) != 0 ||
            (packet[offset + 2].toInt() and 0xff) != 0 ||
            (packet[offset + 3].toInt() and 0xff) != 0
        ) {
            return false
        }
        return when (type) {
            1 -> len == 148
            2 -> len == 92
            3 -> len == 64
            4 -> len >= 32
            else -> false
        }
    }

    fun looksLikeOpenVpn(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 2) return false
        val opcode = (packet[offset].toInt() and 0xff) shr 3
        // P_CONTROL_HARD_RESET_CLIENT_V2 = 7, V3 = 10, etc.
        return opcode in 1..10 && len >= 14
    }

    fun looksLikeNtp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Boolean {
        if (len < 48) return false
        if (info.dstPort != 123 && info.srcPort != 123) return false
        val liVnMode = packet[offset].toInt() and 0xff
        val version = (liVnMode ushr 3) and 0x07
        val mode = liVnMode and 0x07
        return version in 1..4 && mode in 1..5
    }

    fun looksLikeDhcp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Boolean {
        if (len < 240) return false
        if (info.dstPort != 67 && info.dstPort != 68 &&
            info.srcPort != 67 && info.srcPort != 68
        ) {
            return false
        }
        val op = packet[offset].toInt() and 0xff
        if (op != 1 && op != 2) return false
        // Magic cookie
        return (packet[offset + 236].toInt() and 0xff) == 0x63 &&
            (packet[offset + 237].toInt() and 0xff) == 0x82 &&
            (packet[offset + 238].toInt() and 0xff) == 0x53 &&
            (packet[offset + 239].toInt() and 0xff) == 0x63
    }

    fun looksLikeTftp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Boolean {
        if (len < 4) return false
        if (info.dstPort != 69 && info.srcPort != 69) return false
        val opcode = DpiBytes.u16(packet, offset)
        return opcode in 1..5
    }

    /** Telnet IAC (RFC 854) — command stream starts with 0xFF. */
    fun looksLikeTelnet(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 3) return false
        return (packet[offset].toInt() and 0xff) == 0xFF &&
            (packet[offset + 1].toInt() and 0xff) in 0xF0..0xFE
    }

    /** LDAP BER SEQUENCE (RFC 4511) — tag 0x30 + reasonable length. */
    fun looksLikeLdap(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 6) return false
        if ((packet[offset].toInt() and 0xff) != 0x30) return false
        val lenByte = packet[offset + 1].toInt() and 0xff
        return when {
            lenByte < 0x80 -> lenByte + 2 <= len && lenByte >= 4
            lenByte == 0x81 && len >= 3 -> {
                val l = packet[offset + 2].toInt() and 0xff
                l + 3 <= len && l >= 4
            }
            lenByte == 0x82 && len >= 4 -> {
                val l = DpiBytes.u16(packet, offset + 2)
                l + 4 <= len && l in 4..4096
            }
            else -> false
        }
    }

    /** SMB1 `\xFFSMB` or SMB2 `\xFESMB` / `\xFDSMB`. */
    fun looksLikeSmb(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val b0 = packet[offset].toInt() and 0xff
        return (b0 == 0xFF || b0 == 0xFE || b0 == 0xFD) &&
            DpiBytes.startsWithAscii(packet, offset + 1, len - 1, "SMB")
    }

    /** Kerberos AS-REQ / TGS-REQ APPLICATION tags (RFC 4120). */
    fun looksLikeKerberos(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val tag = packet[offset].toInt() and 0xff
        // APPLICATION 10 AS-REQ, 12 TGS-REQ, 11 AS-REP, 13 TGS-REP
        return tag in setOf(0x6A, 0x6B, 0x6C, 0x6D)
    }

    /** SNMPv1/v2c BER SEQUENCE + version INTEGER (RFC 3411 family). */
    fun looksLikeSnmp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 8) return false
        if ((packet[offset].toInt() and 0xff) != 0x30) return false
        // Quickly find version INTEGER 0/1/3 after length
        var p = offset + 1
        val lb = packet[p].toInt() and 0xff
        p += when {
            lb < 0x80 -> 1
            lb == 0x81 -> 2
            lb == 0x82 -> 3
            else -> return false
        }
        if (p + 3 > offset + len) return false
        if ((packet[p].toInt() and 0xff) != 0x02) return false // INTEGER
        val il = packet[p + 1].toInt() and 0xff
        if (il !in 1..4 || p + 2 + il > offset + len) return false
        val ver = packet[p + 2].toInt() and 0xff
        return ver in 0..3
    }

    /** Memcached ASCII (get/set/stats) or binary magic 0x80/0x81. */
    fun looksLikeMemcached(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val m = packet[offset].toInt() and 0xff
        if (m == 0x80 || m == 0x81) return true
        for (p in MEMCACHED_PREFIXES) {
            if (DpiBytes.startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    /** AMQP protocol header "AMQP" (OASIS AMQP 1.0). */
    fun looksLikeAmqp(packet: ByteArray, offset: Int, len: Int): Boolean =
        len >= 8 && DpiBytes.startsWithAscii(packet, offset, len, "AMQP")

    /** CoAP (RFC 7252): Ver=1 in bits 7..6 of first byte. */
    fun looksLikeCoap(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val b0 = packet[offset].toInt() and 0xff
        val ver = (b0 ushr 6) and 0x03
        if (ver != 1) return false
        val code = packet[offset + 1].toInt() and 0xff
        val cls = code ushr 5
        val detail = code and 0x1f
        return cls <= 5 && detail <= 31
    }

    /** MSSQL TDS PRELOGIN (type 0x12) or LOGIN7 (0x10). */
    fun looksLikeMssql(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 8) return false
        val type = packet[offset].toInt() and 0xff
        if (type !in setOf(0x12, 0x10, 0x04, 0x01)) return false
        val status = packet[offset + 1].toInt() and 0xff
        val pktLen = DpiBytes.u16(packet, offset + 2)
        return status <= 0x01 && pktLen in 8..len + 64
    }

    /** MongoDB wire protocol: msgLen + requestID + responseTo + opCode. */
    fun looksLikeMongodb(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 16) return false
        val msgLen = (packet[offset].toInt() and 0xff) or
            ((packet[offset + 1].toInt() and 0xff) shl 8) or
            ((packet[offset + 2].toInt() and 0xff) shl 16) or
            ((packet[offset + 3].toInt() and 0xff) shl 24)
        if (msgLen !in 16..48 * 1024 || msgLen > len + 1024) return false
        val op = (packet[offset + 12].toInt() and 0xff) or
            ((packet[offset + 13].toInt() and 0xff) shl 8) or
            ((packet[offset + 14].toInt() and 0xff) shl 16) or
            ((packet[offset + 15].toInt() and 0xff) shl 24)
        // OP_REPLY=1, OP_MSG=2013, OP_QUERY=2004, OP_COMPRESSED=2012, etc.
        return op in setOf(1, 2001, 2002, 2004, 2005, 2006, 2007, 2010, 2011, 2012, 2013)
    }

    /** Git pkt-line / smart HTTP: "xxxx# service=" or "git-" */
    fun looksLikeGit(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 8) return false
        if (DpiBytes.startsWithAscii(packet, offset, len, "git-")) return true
        // 4 hex length prefix then command
        fun isHex(c: Int) =
            c in '0'.code..'9'.code || c in 'a'.code..'f'.code || c in 'A'.code..'F'.code
        if (!(0..3).all { isHex(packet[offset + it].toInt() and 0xff) }) return false
        return DpiBytes.asciiContains(packet, offset, minOf(len, 64), "git-upload-pack") ||
            DpiBytes.asciiContains(packet, offset, minOf(len, 64), "git-receive-pack") ||
            DpiBytes.asciiContains(packet, offset, minOf(len, 64), "# service=")
    }

    /** NNTP (RFC 3977) banners / commands. */
    fun looksLikeNntp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (DpiBytes.startsWithAscii(packet, offset, len, "200 ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "201 ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "MODE ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "GROUP ") ||
            DpiBytes.startsWithAscii(packet, offset, len, "ARTICLE")
        ) {
            return true
        }
        return false
    }

    /** RADIUS Access-Request (RFC 2865): code 1..5, length match. */
    fun looksLikeRadius(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 20) return false
        val code = packet[offset].toInt() and 0xff
        if (code !in 1..13) return false
        val rLen = DpiBytes.u16(packet, offset + 2)
        return rLen in 20..4096 && rLen <= len + 64
    }

    /** Modbus TCP MBAP (unit id + PDU). */
    fun looksLikeModbus(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 8) return false
        val proto = DpiBytes.u16(packet, offset + 2)
        if (proto != 0) return false
        val length = DpiBytes.u16(packet, offset + 4)
        return length in 2..256 && length + 6 <= len + 32
    }

    /** RTMP handshake: version byte 0x03 then typically 1536-byte random (Adobe RTMP). */
    fun looksLikeRtmp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 9) return false
        if ((packet[offset].toInt() and 0xff) != 0x03) return false
        // Full C0+C1 is 1537 bytes; accept partial first segment on common port.
        return len >= 1537 || len >= 64
    }

    /** IKEv2 header (RFC 7296): next payload, version 2.0, exchange type. */
    fun looksLikeIke(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 28) return false
        val version = packet[offset + 17].toInt() and 0xff
        // Major=2 → 0x20
        if (version != 0x20 && version != 0x10) return false
        val exchange = packet[offset + 18].toInt() and 0xff
        return exchange in 1..44
    }

    /** L2TP (RFC 2661): flags T=1 for control, version=2. */
    fun looksLikeL2tp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 6) return false
        val flags = DpiBytes.u16(packet, offset)
        val ver = flags and 0x0F
        return ver == 2
    }

    /** Cassandra native protocol: version 3/4/5 in first byte, opcode. */
    fun looksLikeCassandra(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 9) return false
        val ver = packet[offset].toInt() and 0xff
        // request 0x03..0x05, response 0x83..0x85
        if (ver !in 0x03..0x05 && ver !in 0x83..0x85) return false
        val opcode = packet[offset + 4].toInt() and 0xff
        return opcode in 0x00..0x10
    }

    /** Kafka request: size + apiKey + apiVersion (small ints). */
    fun looksLikeKafka(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 12) return false
        val size = ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)
        if (size !in 8..1_000_000) return false
        val apiKey = DpiBytes.u16(packet, offset + 4)
        val apiVer = DpiBytes.u16(packet, offset + 6)
        return apiKey <= 70 && apiVer <= 20
    }

    /** Redis already covered; Beanstalkd ASCII. */
    fun looksLikeBeanstalkd(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in BEANSTALK_PREFIXES) {
            if (DpiBytes.startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    /** Minecraft Java handshake (VarInt packet id 0 in first payload after length). */
    fun looksLikeMinecraft(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        // Packet length VarInt then packet id 0x00 (handshake)
        var p = offset
        var value = 0
        var shift = 0
        repeat(3) {
            if (p >= offset + len) return false
            val b = packet[p++].toInt() and 0xff
            value = value or ((b and 0x7f) shl shift)
            if (b and 0x80 == 0) {
                if (value !in 1..512) return false
                if (p >= offset + len) return false
                return (packet[p].toInt() and 0xff) == 0x00
            }
            shift += 7
        }
        return false
    }

    /** Bitcoin P2P magic mainnet F9 BE B4 D9. */
    fun looksLikeBitcoin(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 16) return false
        return (packet[offset].toInt() and 0xff) == 0xF9 &&
            (packet[offset + 1].toInt() and 0xff) == 0xBE &&
            (packet[offset + 2].toInt() and 0xff) == 0xB4 &&
            (packet[offset + 3].toInt() and 0xff) == 0xD9
    }

    /** Whois / Finger / Gopher: short ASCII client queries. */
    fun looksLikeWhois(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 2 || len > 256) return false
        // domain\r\n style
        return DpiBytes.asciiContains(packet, offset, len, "\r\n") &&
            !DpiBytes.startsWithAscii(packet, offset, len, "GET ") &&
            !DpiBytes.startsWithAscii(packet, offset, len, "HTTP/")
    }

    val HTTP_METHODS = arrayOf(
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ",
        "HTTP/1.", "HTTP/2",
    )
    val SMTP_PREFIXES = arrayOf(
        "EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "DATA\r\n", "QUIT\r\n", "STARTTLS",
    )
    val SIP_PREFIXES = arrayOf(
        "INVITE ", "REGISTER ", "OPTIONS ", "BYE ", "ACK ", "CANCEL ", "SUBSCRIBE ",
        "NOTIFY ", "SIP/2.0",
    )
    val RTSP_PREFIXES = arrayOf(
        "OPTIONS ", "DESCRIBE ", "SETUP ", "PLAY ", "TEARDOWN ", "PAUSE ", "RTSP/1.0",
    )
    val IRC_PREFIXES = arrayOf(
        "NICK ", "USER ", "JOIN ", "PRIVMSG ", "NOTICE ", "PING ", "PONG ", "CAP ",
    )
    val MEMCACHED_PREFIXES = arrayOf(
        "get ", "gets ", "set ", "add ", "replace ", "delete ", "stats", "version", "quit",
    )
    val BEANSTALK_PREFIXES = arrayOf(
        "use ", "put ", "reserve", "delete ", "stats", "list-tubes", "peek-",
    )
    val HTTP_PORTS = setOf(80, 8080, 8000, 8008, 8888, 5000)
    val HTTPS_PORTS = setOf(443, 8443)
}
