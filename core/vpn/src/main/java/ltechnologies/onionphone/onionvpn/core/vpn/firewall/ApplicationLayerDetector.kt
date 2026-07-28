package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsPacketParser
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Lightweight DPI for firewall UX: classify TCP/UDP into application protocols.
 *
 * Hot path must stay cheap — call only on cold ASK/DENY/journal paths, never on every packet.
 *
 * Detection order:
 * 1. Payload signatures (DNS, HTTP/2, HTTP, TLS/DTLS, QUIC, SSH, STUN, …)
 * 2. Well-known port heuristics when the first packet has no payload (TCP SYN)
 */
object ApplicationLayerDetector {

    data class Result(
        /** Short label for notifications. */
        val label: String,
        /** Optional detail: QNAME, Host, SNI, method, banner snippet. */
        val detail: String? = null,
        val kind: Kind = Kind.UNKNOWN,
    )

    enum class Kind {
        DNS,
        MDNS,
        LLMNR,
        DOH,
        DOT,
        HTTP,
        HTTP2,
        HTTPS,
        WEBSOCKET,
        TLS,
        DTLS,
        QUIC,
        SSH,
        FTP,
        SMTP,
        SMTPS,
        IMAP,
        IMAPS,
        POP3,
        POP3S,
        SIP,
        RTSP,
        MQTT,
        STUN,
        WIREGUARD,
        OPENVPN,
        RDP,
        VNC,
        REDIS,
        MYSQL,
        POSTGRES,
        MONGODB,
        BITTORRENT,
        SOCKS,
        NTP,
        DHCP,
        TFTP,
        SSDP,
        XMPP,
        IRC,
        GIT,
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
        // --- DNS family (UDP/TCP) ---
        if (looksLikeDns(packet, offset, len, info)) {
            val parsed = DnsPacketParser.parse(packet, offset, len)
            val qname = parsed?.qname?.takeIf { it.isNotBlank() }
            val kind = when (info.dstPort) {
                5353, 5355 -> if (info.dstPort == 5353) Kind.MDNS else Kind.LLMNR
                else -> Kind.DNS
            }
            val label = when (kind) {
                Kind.MDNS -> "mDNS"
                Kind.LLMNR -> "LLMNR"
                else -> "DNS"
            }
            val detail = when {
                qname != null && parsed?.isResponse == true -> "$label response $qname"
                qname != null -> "$label query $qname"
                else -> null
            }
            return Result(label = label, detail = detail, kind = kind)
        }

        // --- Cleartext ASCII / framed app protocols ---
        if (info.isTcp && looksLikeHttp2Preface(packet, offset, len)) {
            return Result(label = "HTTP/2", detail = "PRI preface", kind = Kind.HTTP2)
        }

        if ((info.isTcp || info.isUdp) && looksLikeHttp(packet, offset, len)) {
            return classifyHttpFamily(packet, offset, len, info)
        }

        if (info.isTcp && looksLikeSsh(packet, offset, len)) {
            val banner = asciiPrefix(packet, offset, len, 48)
            return Result(label = "SSH", detail = banner, kind = Kind.SSH)
        }

        if (info.isTcp && looksLikeFtp(packet, offset, len)) {
            return Result(label = "FTP", detail = asciiPrefix(packet, offset, len, 40), kind = Kind.FTP)
        }

        if (info.isTcp && looksLikeSmtp(packet, offset, len)) {
            return Result(label = "SMTP", detail = asciiPrefix(packet, offset, len, 40), kind = Kind.SMTP)
        }

        if (info.isTcp && looksLikeImap(packet, offset, len)) {
            return Result(label = "IMAP", detail = asciiPrefix(packet, offset, len, 40), kind = Kind.IMAP)
        }

        if (info.isTcp && looksLikePop3(packet, offset, len)) {
            return Result(label = "POP3", detail = asciiPrefix(packet, offset, len, 40), kind = Kind.POP3)
        }

        if (looksLikeSip(packet, offset, len)) {
            return Result(label = "SIP", detail = asciiPrefix(packet, offset, len, 48), kind = Kind.SIP)
        }

        if (info.isTcp && looksLikeRtsp(packet, offset, len)) {
            return Result(label = "RTSP", detail = asciiPrefix(packet, offset, len, 48), kind = Kind.RTSP)
        }

        if (info.isUdp && looksLikeSsdp(packet, offset, len)) {
            return Result(label = "SSDP", detail = "M-SEARCH", kind = Kind.SSDP)
        }

        if (info.isTcp && looksLikeXmpp(packet, offset, len)) {
            return Result(label = "XMPP", detail = asciiPrefix(packet, offset, len, 48), kind = Kind.XMPP)
        }

        if (info.isTcp && looksLikeIrc(packet, offset, len)) {
            return Result(label = "IRC", detail = asciiPrefix(packet, offset, len, 40), kind = Kind.IRC)
        }

        if (info.isTcp && looksLikeRedis(packet, offset, len)) {
            return Result(label = "Redis", detail = asciiPrefix(packet, offset, len, 32), kind = Kind.REDIS)
        }

        if (info.isTcp && looksLikeBitTorrent(packet, offset, len)) {
            return Result(label = "BitTorrent", detail = "handshake", kind = Kind.BITTORRENT)
        }

        if (info.isTcp && looksLikeSocks(packet, offset, len)) {
            val ver = packet[offset].toInt() and 0xff
            return Result(label = "SOCKS$ver", detail = null, kind = Kind.SOCKS)
        }

        if (info.isTcp && looksLikeRdp(packet, offset, len)) {
            return Result(label = "RDP", detail = "TPKT/X.224", kind = Kind.RDP)
        }

        if (info.isTcp && looksLikeVnc(packet, offset, len)) {
            return Result(label = "VNC", detail = asciiPrefix(packet, offset, len, 16), kind = Kind.VNC)
        }

        if (info.isTcp && looksLikePostgres(packet, offset, len)) {
            return Result(label = "PostgreSQL", detail = "startup", kind = Kind.POSTGRES)
        }

        if (info.isTcp && looksLikeMysql(packet, offset, len)) {
            return Result(label = "MySQL", detail = "greeting/handshake", kind = Kind.MYSQL)
        }

        if (info.isTcp && looksLikeMqtt(packet, offset, len)) {
            return Result(label = "MQTT", detail = "CONNECT", kind = Kind.MQTT)
        }

        if (info.isUdp && looksLikeStun(packet, offset, len)) {
            return Result(label = "STUN", detail = "UDP/${info.dstPort}", kind = Kind.STUN)
        }

        if (info.isUdp && looksLikeWireGuard(packet, offset, len)) {
            return Result(label = "WireGuard", detail = "UDP/${info.dstPort}", kind = Kind.WIREGUARD)
        }

        if (info.isUdp && looksLikeOpenVpn(packet, offset, len)) {
            return Result(label = "OpenVPN", detail = "UDP/${info.dstPort}", kind = Kind.OPENVPN)
        }

        if (info.isUdp && looksLikeNtp(packet, offset, len, info)) {
            return Result(label = "NTP", detail = null, kind = Kind.NTP)
        }

        if (info.isUdp && looksLikeDhcp(packet, offset, len, info)) {
            return Result(label = "DHCP", detail = null, kind = Kind.DHCP)
        }

        if (info.isUdp && looksLikeTftp(packet, offset, len, info)) {
            return Result(label = "TFTP", detail = null, kind = Kind.TFTP)
        }

        // --- TLS / DTLS / QUIC (after cleartext checks) ---
        if (info.isUdp && looksLikeDtls(packet, offset, len)) {
            return Result(label = "DTLS", detail = "UDP/${info.dstPort}", kind = Kind.DTLS)
        }

        if (info.isTcp && looksLikeTls(packet, offset, len)) {
            return classifyTls(packet, offset, len, info)
        }

        if (info.isUdp && looksLikeQuic(packet, offset, len)) {
            val http3 = info.dstPort == 443 || info.dstPort == 80
            return Result(
                label = if (http3) "HTTP/3" else "QUIC",
                detail = "UDP/${info.dstPort}",
                kind = Kind.QUIC,
            )
        }

        return null
    }

    private fun classifyHttpFamily(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result {
        val text = String(packet, offset, minOf(len, 512), StandardCharsets.US_ASCII)
        val preview = httpPreview(text)
        val lower = text.lowercase(Locale.US)
        val websocket = lower.contains("upgrade: websocket") ||
            lower.contains("\nsec-websocket-key:")
        val doh = lower.contains("/dns-query") ||
            lower.contains("/.well-known/dns-query") ||
            lower.contains("application/dns-message") ||
            lower.contains("application/dns-json")
        return when {
            websocket -> Result(label = "WebSocket", detail = preview, kind = Kind.WEBSOCKET)
            doh -> Result(label = "DoH", detail = preview, kind = Kind.DOH)
            else -> Result(label = "HTTP", detail = preview, kind = Kind.HTTP)
        }
    }

    private fun classifyTls(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result {
        val sni = extractTlsSni(packet, offset, len)
        val detail = sni?.let { "SNI $it" }
        return when (info.dstPort) {
            443, 8443 -> Result(label = "HTTPS", detail = detail, kind = Kind.HTTPS)
            853 -> Result(label = "DoT", detail = detail ?: "TLS DNS :853", kind = Kind.DOT)
            465, 587 -> Result(label = "SMTPS", detail = detail, kind = Kind.SMTPS)
            993 -> Result(label = "IMAPS", detail = detail, kind = Kind.IMAPS)
            995 -> Result(label = "POP3S", detail = detail, kind = Kind.POP3S)
            5223, 5222 -> Result(label = "XMPP", detail = detail ?: "TLS", kind = Kind.XMPP)
            8883 -> Result(label = "MQTT", detail = detail ?: "TLS :8883", kind = Kind.MQTT)
            636 -> Result(label = "TLS", detail = detail ?: "LDAPS :636", kind = Kind.TLS)
            else -> Result(label = "TLS", detail = detail, kind = Kind.TLS)
        }
    }

    private fun portHeuristic(info: IpPacketInfo): Result {
        val p = info.dstPort
        return when {
            p == 53 || info.srcPort == 53 ->
                Result(label = "DNS", detail = null, kind = Kind.DNS)
            p == 5353 ->
                Result(label = "mDNS", detail = "port 5353", kind = Kind.MDNS)
            p == 5355 ->
                Result(label = "LLMNR", detail = "port 5355", kind = Kind.LLMNR)
            p == 853 ->
                Result(label = "DoT", detail = "TLS DNS :853", kind = Kind.DOT)
            info.isTcp && p in HTTP_PORTS ->
                Result(label = "HTTP", detail = "port $p", kind = Kind.HTTP)
            info.isTcp && p in HTTPS_PORTS ->
                Result(label = "HTTPS", detail = "port $p", kind = Kind.HTTPS)
            info.isUdp && (p == 443 || p == 80) ->
                Result(label = "HTTP/3", detail = "port $p", kind = Kind.QUIC)
            info.isTcp && p == 22 ->
                Result(label = "SSH", detail = "port 22", kind = Kind.SSH)
            info.isTcp && (p == 21 || p == 20) ->
                Result(label = "FTP", detail = "port $p", kind = Kind.FTP)
            info.isTcp && p == 25 ->
                Result(label = "SMTP", detail = "port 25", kind = Kind.SMTP)
            info.isTcp && (p == 465 || p == 587) ->
                Result(label = "SMTPS", detail = "port $p", kind = Kind.SMTPS)
            info.isTcp && p == 143 ->
                Result(label = "IMAP", detail = "port 143", kind = Kind.IMAP)
            info.isTcp && p == 993 ->
                Result(label = "IMAPS", detail = "port 993", kind = Kind.IMAPS)
            info.isTcp && p == 110 ->
                Result(label = "POP3", detail = "port 110", kind = Kind.POP3)
            info.isTcp && p == 995 ->
                Result(label = "POP3S", detail = "port 995", kind = Kind.POP3S)
            (info.isTcp || info.isUdp) && (p == 5060 || p == 5061) ->
                Result(
                    label = if (p == 5061) "SIP/TLS" else "SIP",
                    detail = "port $p",
                    kind = Kind.SIP,
                )
            info.isTcp && p == 554 ->
                Result(label = "RTSP", detail = "port 554", kind = Kind.RTSP)
            info.isTcp && (p == 1883 || p == 8883) ->
                Result(label = "MQTT", detail = "port $p", kind = Kind.MQTT)
            (info.isUdp || info.isTcp) && (p == 3478 || p == 5349) ->
                Result(label = "STUN", detail = "port $p", kind = Kind.STUN)
            info.isUdp && p in 51820..51830 ->
                Result(label = "WireGuard", detail = "port $p", kind = Kind.WIREGUARD)
            (info.isUdp || info.isTcp) && p == 1194 ->
                Result(label = "OpenVPN", detail = "port 1194", kind = Kind.OPENVPN)
            info.isTcp && p == 3389 ->
                Result(label = "RDP", detail = "port 3389", kind = Kind.RDP)
            info.isTcp && (p == 5900 || p in 5900..5910) ->
                Result(label = "VNC", detail = "port $p", kind = Kind.VNC)
            info.isTcp && p == 6379 ->
                Result(label = "Redis", detail = "port 6379", kind = Kind.REDIS)
            info.isTcp && p == 3306 ->
                Result(label = "MySQL", detail = "port 3306", kind = Kind.MYSQL)
            info.isTcp && p == 5432 ->
                Result(label = "PostgreSQL", detail = "port 5432", kind = Kind.POSTGRES)
            info.isTcp && p == 27017 ->
                Result(label = "MongoDB", detail = "port 27017", kind = Kind.MONGODB)
            info.isTcp && (p == 1080 || p == 9050 || p == 9150) ->
                Result(label = "SOCKS", detail = "port $p", kind = Kind.SOCKS)
            info.isUdp && p == 123 ->
                Result(label = "NTP", detail = "port 123", kind = Kind.NTP)
            info.isUdp && (p == 67 || p == 68) ->
                Result(label = "DHCP", detail = "port $p", kind = Kind.DHCP)
            info.isUdp && p == 69 ->
                Result(label = "TFTP", detail = "port 69", kind = Kind.TFTP)
            info.isUdp && p == 1900 ->
                Result(label = "SSDP", detail = "port 1900", kind = Kind.SSDP)
            info.isTcp && (p == 5222 || p == 5223) ->
                Result(label = "XMPP", detail = "port $p", kind = Kind.XMPP)
            info.isTcp && (p == 6667 || p == 6697) ->
                Result(label = "IRC", detail = "port $p", kind = Kind.IRC)
            info.isTcp && p == 9418 ->
                Result(label = "Git", detail = "port 9418", kind = Kind.GIT)
            info.isTcp && (p == 6881 || p in 6881..6889) ->
                Result(label = "BitTorrent", detail = "port $p", kind = Kind.BITTORRENT)
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
    }

    // --- signature helpers ---

    private fun looksLikeDns(packet: ByteArray, offset: Int, len: Int, info: IpPacketInfo): Boolean {
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
        val qd = u16(packet, off + 4)
        val an = u16(packet, off + 6)
        val ns = u16(packet, off + 8)
        val ar = u16(packet, off + 10)
        if (qd > 16 || an > 64 || ns > 64 || ar > 64) return false
        if (qd == 0 && an == 0) return false
        val parsed = DnsPacketParser.parse(packet, off, dnsLen)
        if (parsed?.qname != null) return true
        return onDnsPort && qd >= 1
    }

    private fun looksLikeHttp2Preface(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

    private fun looksLikeHttp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        for (m in HTTP_METHODS) {
            if (startsWithAscii(packet, offset, len, m)) return true
        }
        return false
    }

    private fun httpPreview(text: String): String? {
        val firstLine = text.lineSequence().firstOrNull()?.trim().orEmpty()
        if (firstLine.isEmpty()) return null
        val host = Regex("""(?im)^Host:\s*(\S+)""")
            .find(text)?.groupValues?.getOrNull(1)
        val line = firstLine.take(80)
        return if (host != null) "$line · Host $host" else line
    }

    private fun looksLikeTls(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        val type = packet[offset].toInt() and 0xff
        if (type !in 0x14..0x17) return false
        val major = packet[offset + 1].toInt() and 0xff
        val minor = packet[offset + 2].toInt() and 0xff
        return major == 0x03 && minor <= 0x04
    }

    private fun looksLikeDtls(packet: ByteArray, offset: Int, len: Int): Boolean {
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
        val recordLen = u16(packet, offset + 3)
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
        val cipherLen = u16(packet, p)
        p += 2 + cipherLen
        if (p + 1 > helloEnd) return null
        val compLen = packet[p].toInt() and 0xff
        p += 1 + compLen
        if (p + 2 > helloEnd) return null
        val extLen = u16(packet, p)
        p += 2
        val extEnd = minOf(helloEnd, p + extLen)
        while (p + 4 <= extEnd) {
            val type = u16(packet, p)
            val elen = u16(packet, p + 2)
            p += 4
            if (p + elen > extEnd) break
            if (type == 0x0000 && elen >= 5) {
                var q = p + 2
                if (q + 3 > p + elen) break
                val nameType = packet[q].toInt() and 0xff
                q += 1
                val nameLen = u16(packet, q)
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

    private fun looksLikeQuic(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        val b0 = packet[offset].toInt() and 0xff
        // Long header (bit7=1) or short header with fixed bit (bit6=1) — RFC 9000.
        return (b0 and 0x80) != 0 || (b0 and 0x40) != 0
    }

    private fun looksLikeSsh(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "SSH-")

    private fun looksLikeFtp(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (startsWithAscii(packet, offset, len, "USER ") ||
            startsWithAscii(packet, offset, len, "PASS ") ||
            startsWithAscii(packet, offset, len, "QUIT")
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

    private fun looksLikeSmtp(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in SMTP_PREFIXES) {
            if (startsWithAscii(packet, offset, len, p)) return true
        }
        return len >= 4 &&
            (packet[offset].toInt() and 0xff) == '2'.code &&
            (packet[offset + 1].toInt() and 0xff) == '2'.code &&
            (packet[offset + 2].toInt() and 0xff) == '0'.code &&
            (packet[offset + 3].toInt() and 0xff) == ' '.code &&
            asciiContains(packet, offset, minOf(len, 64), "ESMTP")
    }

    private fun looksLikeImap(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "* OK") ||
            startsWithAscii(packet, offset, len, "* PREAUTH") ||
            asciiStartsWithTagCommand(packet, offset, len, "LOGIN") ||
            asciiStartsWithTagCommand(packet, offset, len, "AUTHENTICATE")

    private fun looksLikePop3(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "+OK") ||
            startsWithAscii(packet, offset, len, "-ERR") ||
            startsWithAscii(packet, offset, len, "USER ") ||
            startsWithAscii(packet, offset, len, "PASS ") ||
            startsWithAscii(packet, offset, len, "STAT") ||
            startsWithAscii(packet, offset, len, "RETR ")

    private fun looksLikeSip(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in SIP_PREFIXES) {
            if (startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    private fun looksLikeRtsp(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in RTSP_PREFIXES) {
            if (startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    private fun looksLikeSsdp(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "M-SEARCH ") ||
            startsWithAscii(packet, offset, len, "NOTIFY ")

    private fun looksLikeXmpp(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "<?xml") ||
            startsWithAscii(packet, offset, len, "<stream:stream") ||
            startsWithAscii(packet, offset, len, "<stream:")

    private fun looksLikeIrc(packet: ByteArray, offset: Int, len: Int): Boolean {
        for (p in IRC_PREFIXES) {
            if (startsWithAscii(packet, offset, len, p)) return true
        }
        return false
    }

    private fun looksLikeRedis(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 3) return false
        val c0 = packet[offset].toInt() and 0xff
        // RESP: *n\r\n  or +OK / -ERR / $ / :
        if (c0 == '*'.code || c0 == '+'.code || c0 == '-'.code ||
            c0 == '$'.code || c0 == ':'.code
        ) {
            // Prefer clear Redis verbs in the first chunk.
            return asciiContains(packet, offset, minOf(len, 64), "\r\n") &&
                (
                    asciiContains(packet, offset, minOf(len, 64), "PING") ||
                        asciiContains(packet, offset, minOf(len, 64), "AUTH") ||
                        asciiContains(packet, offset, minOf(len, 64), "INFO") ||
                        asciiContains(packet, offset, minOf(len, 64), "HELLO") ||
                        c0 == '*'.code
                    )
        }
        return false
    }

    private fun looksLikeBitTorrent(packet: ByteArray, offset: Int, len: Int): Boolean =
        len >= 20 &&
            (packet[offset].toInt() and 0xff) == 19 &&
            startsWithAscii(packet, offset + 1, len - 1, "BitTorrent protocol")

    private fun looksLikeSocks(packet: ByteArray, offset: Int, len: Int): Boolean {
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

    private fun looksLikeRdp(packet: ByteArray, offset: Int, len: Int): Boolean {
        // TPKT version 3 + X.224 Connection Request (CR length / type 0xE0)
        if (len < 7) return false
        if ((packet[offset].toInt() and 0xff) != 3) return false
        if ((packet[offset + 1].toInt() and 0xff) != 0) return false
        val tpktLen = u16(packet, offset + 2)
        if (tpktLen < 7 || tpktLen > len + 64) return false
        val li = packet[offset + 4].toInt() and 0xff
        val code = packet[offset + 5].toInt() and 0xff
        return li >= 6 && (code == 0xE0 || code == 0xD0)
    }

    private fun looksLikeVnc(packet: ByteArray, offset: Int, len: Int): Boolean =
        startsWithAscii(packet, offset, len, "RFB ")

    private fun looksLikePostgres(packet: ByteArray, offset: Int, len: Int): Boolean {
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

    private fun looksLikeMysql(packet: ByteArray, offset: Int, len: Int): Boolean {
        // Server greeting: 3-byte len + seq 0 + protocol version 10 + version string
        if (len < 10) return false
        val payloadLen = (packet[offset].toInt() and 0xff) or
            ((packet[offset + 1].toInt() and 0xff) shl 8) or
            ((packet[offset + 2].toInt() and 0xff) shl 16)
        val seq = packet[offset + 3].toInt() and 0xff
        val proto = packet[offset + 4].toInt() and 0xff
        return seq == 0 && proto == 10 && payloadLen in 20..1024
    }

    private fun looksLikeMqtt(packet: ByteArray, offset: Int, len: Int): Boolean {
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
                val nameLen = u16(packet, p)
                p += 2
                if (p + nameLen > offset + len || nameLen !in 4..6) return false
                val name = String(packet, p, nameLen, StandardCharsets.US_ASCII)
                return name == "MQTT" || name == "MQIsdp"
            }
        }
        return false
    }

    private fun looksLikeStun(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 20) return false
        // First two bits must be 0; magic cookie at bytes 4..7
        if ((packet[offset].toInt() and 0xC0) != 0) return false
        return (packet[offset + 4].toInt() and 0xff) == 0x21 &&
            (packet[offset + 5].toInt() and 0xff) == 0x12 &&
            (packet[offset + 6].toInt() and 0xff) == 0xA4 &&
            (packet[offset + 7].toInt() and 0xff) == 0x42
    }

    private fun looksLikeWireGuard(packet: ByteArray, offset: Int, len: Int): Boolean {
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

    private fun looksLikeOpenVpn(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 2) return false
        val opcode = (packet[offset].toInt() and 0xff) shr 3
        // P_CONTROL_HARD_RESET_CLIENT_V2 = 7, V3 = 10, etc.
        return opcode in 1..10 && len >= 14
    }

    private fun looksLikeNtp(
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

    private fun looksLikeDhcp(
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

    private fun looksLikeTftp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Boolean {
        if (len < 4) return false
        if (info.dstPort != 69 && info.srcPort != 69) return false
        val opcode = u16(packet, offset)
        return opcode in 1..5
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

    private fun asciiPrefix(packet: ByteArray, offset: Int, len: Int, max: Int): String? {
        val n = minOf(len, max)
        if (n <= 0) return null
        val sb = StringBuilder(n)
        for (i in 0 until n) {
            val c = packet[offset + i].toInt() and 0xff
            if (c == 0 || c == '\r'.code || c == '\n'.code) break
            if (c in 32..126) sb.append(c.toChar()) else break
        }
        return sb.toString().takeIf { it.isNotBlank() }
    }

    private fun asciiContains(packet: ByteArray, offset: Int, len: Int, needle: String): Boolean {
        if (len < needle.length) return false
        outer@ for (i in 0..len - needle.length) {
            for (j in needle.indices) {
                if ((packet[offset + i + j].toInt() and 0xff).toChar() != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    /** IMAP tagged command: `a001 LOGIN …` */
    private fun asciiStartsWithTagCommand(
        packet: ByteArray,
        offset: Int,
        len: Int,
        command: String,
    ): Boolean {
        if (len < command.length + 2) return false
        var i = 0
        while (i < len && i < 16) {
            val c = packet[offset + i].toInt() and 0xff
            if (c == ' '.code) {
                return startsWithAscii(packet, offset + i + 1, len - i - 1, "$command ") ||
                    startsWithAscii(packet, offset + i + 1, len - i - 1, command)
            }
            if (c !in 'A'.code..'Z'.code && c !in 'a'.code..'z'.code &&
                c !in '0'.code..'9'.code && c != '.'.code
            ) {
                return false
            }
            i++
        }
        return false
    }

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

    private val HTTP_METHODS = arrayOf(
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ",
        "HTTP/1.", "HTTP/2",
    )
    private val SMTP_PREFIXES = arrayOf(
        "EHLO ", "HELO ", "MAIL FROM:", "RCPT TO:", "DATA\r\n", "QUIT\r\n", "STARTTLS",
    )
    private val SIP_PREFIXES = arrayOf(
        "INVITE ", "REGISTER ", "OPTIONS ", "BYE ", "ACK ", "CANCEL ", "SUBSCRIBE ",
        "NOTIFY ", "SIP/2.0",
    )
    private val RTSP_PREFIXES = arrayOf(
        "OPTIONS ", "DESCRIBE ", "SETUP ", "PLAY ", "TEARDOWN ", "PAUSE ", "RTSP/1.0",
    )
    private val IRC_PREFIXES = arrayOf(
        "NICK ", "USER ", "JOIN ", "PRIVMSG ", "NOTICE ", "PING ", "PONG ", "CAP ",
    )
    private val HTTP_PORTS = setOf(80, 8080, 8000, 8008, 8888, 5000)
    private val HTTPS_PORTS = setOf(443, 8443)
}
