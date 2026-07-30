package ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi

import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ApplicationLayerDetector.Kind
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ApplicationLayerDetector.Result
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Ordered payload classification graph: first matching probe wins (early-return branches).
 * Keep hot-path callers on [ApplicationLayerDetector.classify] only.
 */
private typealias DpiProbe = (ByteArray, Int, Int, IpPacketInfo) -> Result?

internal object DpiPayloadGraph {

    /** Detection order: DNS → cleartext ASCII → framed → VPN/UDP → TLS/DTLS/QUIC. */
    private val PROBES: List<DpiProbe> = listOf(
        ::probeDnsFamily,
        ::probeHttp2,
        ::probeHttpFamily,
        ::probeSsh,
        ::probeFtp,
        ::probeSmtp,
        ::probeImap,
        ::probePop3,
        ::probeSip,
        ::probeRtsp,
        ::probeSsdp,
        ::probeXmpp,
        ::probeIrc,
        ::probeRedis,
        ::probeBitTorrent,
        ::probeSocks,
        ::probeRdp,
        ::probeVnc,
        ::probePostgres,
        ::probeMysql,
        ::probeMqtt,
        ::probeTelnet,
        ::probeLdap,
        ::probeSmb,
        ::probeKerberos,
        ::probeSnmp,
        ::probeMemcached,
        ::probeAmqp,
        ::probeCoap,
        ::probeMssql,
        ::probeMongodb,
        ::probeGit,
        ::probeNntp,
        ::probeRadius,
        ::probeModbus,
        ::probeRtmp,
        ::probeIke,
        ::probeL2tp,
        ::probeCassandra,
        ::probeKafka,
        ::probeBeanstalkd,
        ::probeMinecraft,
        ::probeBitcoin,
        ::probeStun,
        ::probeWireGuard,
        ::probeOpenVpn,
        ::probeNtp,
        ::probeDhcp,
        ::probeTftp,
        ::probeDtls,
        ::probeTls,
        ::probeQuic,
    )

    fun classify(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        DpiPortCatalog.uniqueKindForPort(info)?.let { preferred ->
            for (probe in PROBES) {
                probe(packet, offset, len, info)?.takeIf { it.kind == preferred }?.let { return it }
            }
        }
        for (probe in PROBES) {
            probe(packet, offset, len, info)?.let { return it }
        }
        return null
    }

    private fun probeDnsFamily(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!DpiSignatures.looksLikeDns(packet, offset, len, info)) return null
        val parsed = DnsPacketParser.parse(packet, offset, len)
        val qname = parsed?.qname?.takeIf { it.isNotBlank() }
        val kind = when (info.dstPort) {
            5353 -> Kind.MDNS
            5355 -> Kind.LLMNR
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

    private fun probeHttp2(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeHttp2Preface(packet, offset, len)) return null
        return Result(label = "HTTP/2", detail = "PRI preface", kind = Kind.HTTP2)
    }

    private fun probeHttpFamily(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!(info.isTcp || info.isUdp) || !DpiSignatures.looksLikeHttp(packet, offset, len)) {
            return null
        }
        return classifyHttpFamily(packet, offset, len)
    }

    private fun probeSsh(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeSsh(packet, offset, len)) return null
        return Result(
            label = "SSH",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 48),
            kind = Kind.SSH,
        )
    }

    private fun probeFtp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeFtp(packet, offset, len)) return null
        return Result(
            label = "FTP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 40),
            kind = Kind.FTP,
        )
    }

    private fun probeSmtp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeSmtp(packet, offset, len)) return null
        return Result(
            label = "SMTP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 40),
            kind = Kind.SMTP,
        )
    }

    private fun probeImap(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeImap(packet, offset, len)) return null
        return Result(
            label = "IMAP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 40),
            kind = Kind.IMAP,
        )
    }

    private fun probePop3(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikePop3(packet, offset, len)) return null
        return Result(
            label = "POP3",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 40),
            kind = Kind.POP3,
        )
    }

    private fun probeSip(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!DpiSignatures.looksLikeSip(packet, offset, len)) return null
        return Result(
            label = "SIP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 48),
            kind = Kind.SIP,
        )
    }

    private fun probeRtsp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeRtsp(packet, offset, len)) return null
        return Result(
            label = "RTSP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 48),
            kind = Kind.RTSP,
        )
    }

    private fun probeSsdp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeSsdp(packet, offset, len)) return null
        return Result(label = "SSDP", detail = "M-SEARCH", kind = Kind.SSDP)
    }

    private fun probeXmpp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeXmpp(packet, offset, len)) return null
        return Result(
            label = "XMPP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 48),
            kind = Kind.XMPP,
        )
    }

    private fun probeIrc(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeIrc(packet, offset, len)) return null
        return Result(
            label = "IRC",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 40),
            kind = Kind.IRC,
        )
    }

    private fun probeRedis(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeRedis(packet, offset, len)) return null
        return Result(
            label = "Redis",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 32),
            kind = Kind.REDIS,
        )
    }

    private fun probeBitTorrent(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeBitTorrent(packet, offset, len)) return null
        return Result(label = "BitTorrent", detail = "handshake", kind = Kind.BITTORRENT)
    }

    private fun probeSocks(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeSocks(packet, offset, len)) return null
        val ver = packet[offset].toInt() and 0xff
        return Result(label = "SOCKS$ver", detail = null, kind = Kind.SOCKS)
    }

    private fun probeRdp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeRdp(packet, offset, len)) return null
        return Result(label = "RDP", detail = "TPKT/X.224", kind = Kind.RDP)
    }

    private fun probeVnc(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeVnc(packet, offset, len)) return null
        return Result(
            label = "VNC",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 16),
            kind = Kind.VNC,
        )
    }

    private fun probePostgres(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikePostgres(packet, offset, len)) return null
        return Result(label = "PostgreSQL", detail = "startup", kind = Kind.POSTGRES)
    }

    private fun probeMysql(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeMysql(packet, offset, len)) return null
        return Result(label = "MySQL", detail = "greeting/handshake", kind = Kind.MYSQL)
    }

    private fun probeMqtt(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeMqtt(packet, offset, len)) return null
        return Result(label = "MQTT", detail = "CONNECT", kind = Kind.MQTT)
    }

    private fun probeTelnet(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeTelnet(packet, offset, len)) return null
        return Result(label = "Telnet", detail = "IAC", kind = Kind.TELNET)
    }

    private fun probeLdap(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeLdap(packet, offset, len)) return null
        return Result(label = "LDAP", detail = "BER", kind = Kind.LDAP)
    }

    private fun probeSmb(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeSmb(packet, offset, len)) return null
        return Result(label = "SMB", detail = "magic", kind = Kind.SMB)
    }

    private fun probeKerberos(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!(info.isTcp || info.isUdp) || !DpiSignatures.looksLikeKerberos(packet, offset, len)) {
            return null
        }
        return Result(label = "Kerberos", detail = "AS/TGS", kind = Kind.KERBEROS)
    }

    private fun probeSnmp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeSnmp(packet, offset, len)) return null
        return Result(label = "SNMP", detail = "UDP/${info.dstPort}", kind = Kind.SNMP)
    }

    private fun probeMemcached(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!(info.isTcp || info.isUdp) || !DpiSignatures.looksLikeMemcached(packet, offset, len)) {
            return null
        }
        return Result(label = "Memcached", detail = null, kind = Kind.MEMCACHED)
    }

    private fun probeAmqp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeAmqp(packet, offset, len)) return null
        return Result(label = "AMQP", detail = "header", kind = Kind.AMQP)
    }

    private fun probeCoap(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeCoap(packet, offset, len)) return null
        return Result(label = "CoAP", detail = "UDP/${info.dstPort}", kind = Kind.COAP)
    }

    private fun probeMssql(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeMssql(packet, offset, len)) return null
        return Result(label = "MSSQL", detail = "TDS", kind = Kind.MSSQL)
    }

    private fun probeMongodb(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeMongodb(packet, offset, len)) return null
        return Result(label = "MongoDB", detail = "wire", kind = Kind.MONGODB)
    }

    private fun probeGit(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeGit(packet, offset, len)) return null
        return Result(label = "Git", detail = "pkt-line", kind = Kind.GIT)
    }

    private fun probeNntp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeNntp(packet, offset, len)) return null
        return Result(
            label = "NNTP",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 40),
            kind = Kind.NNTP,
        )
    }

    private fun probeRadius(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeRadius(packet, offset, len)) return null
        return Result(label = "RADIUS", detail = "UDP/${info.dstPort}", kind = Kind.RADIUS)
    }

    private fun probeModbus(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeModbus(packet, offset, len)) return null
        return Result(label = "Modbus", detail = "MBAP", kind = Kind.MODBUS)
    }

    private fun probeRtmp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || info.dstPort != 1935) return null
        if (!DpiSignatures.looksLikeRtmp(packet, offset, len)) return null
        return Result(label = "RTMP", detail = "handshake", kind = Kind.RTMP)
    }

    private fun probeIke(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeIke(packet, offset, len)) return null
        return Result(label = "IKE", detail = "UDP/${info.dstPort}", kind = Kind.IKE)
    }

    private fun probeL2tp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeL2tp(packet, offset, len)) return null
        return Result(label = "L2TP", detail = "UDP/${info.dstPort}", kind = Kind.L2TP)
    }

    private fun probeCassandra(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeCassandra(packet, offset, len)) return null
        return Result(label = "Cassandra", detail = "native", kind = Kind.CASSANDRA)
    }

    private fun probeKafka(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeKafka(packet, offset, len)) return null
        return Result(label = "Kafka", detail = "API", kind = Kind.KAFKA)
    }

    private fun probeBeanstalkd(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeBeanstalkd(packet, offset, len)) return null
        return Result(
            label = "Beanstalkd",
            detail = DpiBytes.asciiPrefix(packet, offset, len, 32),
            kind = Kind.BEANSTALKD,
        )
    }

    private fun probeMinecraft(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeMinecraft(packet, offset, len)) return null
        return Result(label = "Minecraft", detail = "handshake", kind = Kind.MINECRAFT)
    }

    private fun probeBitcoin(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeBitcoin(packet, offset, len)) return null
        return Result(label = "Bitcoin", detail = "mainnet magic", kind = Kind.BITCOIN)
    }

    private fun probeStun(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeStun(packet, offset, len)) return null
        return Result(label = "STUN", detail = "UDP/${info.dstPort}", kind = Kind.STUN)
    }

    private fun probeWireGuard(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeWireGuard(packet, offset, len)) return null
        return Result(label = "WireGuard", detail = "UDP/${info.dstPort}", kind = Kind.WIREGUARD)
    }

    private fun probeOpenVpn(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeOpenVpn(packet, offset, len)) return null
        return Result(label = "OpenVPN", detail = "UDP/${info.dstPort}", kind = Kind.OPENVPN)
    }

    private fun probeNtp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeNtp(packet, offset, len, info)) return null
        return Result(label = "NTP", detail = null, kind = Kind.NTP)
    }

    private fun probeDhcp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeDhcp(packet, offset, len, info)) return null
        return Result(label = "DHCP", detail = null, kind = Kind.DHCP)
    }

    private fun probeTftp(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeTftp(packet, offset, len, info)) return null
        return Result(label = "TFTP", detail = null, kind = Kind.TFTP)
    }

    private fun probeDtls(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeDtls(packet, offset, len)) return null
        return Result(label = "DTLS", detail = "UDP/${info.dstPort}", kind = Kind.DTLS)
    }

    private fun probeTls(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isTcp || !DpiSignatures.looksLikeTls(packet, offset, len)) return null
        return classifyTls(packet, offset, len, info)
    }

    private fun probeQuic(
        packet: ByteArray,
        offset: Int,
        len: Int,
        info: IpPacketInfo,
    ): Result? {
        if (!info.isUdp || !DpiSignatures.looksLikeQuic(packet, offset, len)) return null
        val http3 = info.dstPort == 443 || info.dstPort == 80
        return Result(
            label = if (http3) "HTTP/3" else "QUIC",
            detail = "UDP/${info.dstPort}",
            kind = Kind.QUIC,
        )
    }

    private fun classifyHttpFamily(
        packet: ByteArray,
        offset: Int,
        len: Int,
    ): Result {
        val text = String(packet, offset, minOf(len, HTTP_PREVIEW_CAP), StandardCharsets.US_ASCII)
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
        val sni = DpiSignatures.extractTlsSni(packet, offset, len)
        val detail = sni?.let { "SNI $it" }
        return when (info.dstPort) {
            443, 8443 -> Result(label = "HTTPS", detail = detail, kind = Kind.HTTPS)
            853 -> Result(label = "DoT", detail = detail ?: "TLS DNS :853", kind = Kind.DOT)
            465, 587 -> Result(label = "SMTPS", detail = detail, kind = Kind.SMTPS)
            993 -> Result(label = "IMAPS", detail = detail, kind = Kind.IMAPS)
            995 -> Result(label = "POP3S", detail = detail, kind = Kind.POP3S)
            5223, 5222 -> Result(label = "XMPP", detail = detail ?: "TLS", kind = Kind.XMPP)
            8883 -> Result(label = "MQTT", detail = detail ?: "TLS :8883", kind = Kind.MQTT)
            636 -> Result(label = "LDAPS", detail = detail ?: "LDAPS :636", kind = Kind.LDAPS)
            else -> Result(label = "TLS", detail = detail, kind = Kind.TLS)
        }
    }

    private fun httpPreview(text: String): String? {
        val firstLine = text.lineSequence().firstOrNull()?.trim().orEmpty()
        if (firstLine.isEmpty()) return null
        val host = DpiSignatures.HTTP_HOST_PATTERN
            .find(text)?.groupValues?.getOrNull(1)
        val line = firstLine.take(80)
        return if (host != null) "$line · Host $host" else line
    }

    private const val HTTP_PREVIEW_CAP = 512
}
