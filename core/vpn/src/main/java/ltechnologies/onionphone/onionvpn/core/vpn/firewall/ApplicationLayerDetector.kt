package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi.DpiBytes
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi.DpiPayloadGraph
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi.DpiSignatures

/**
 * Lightweight DPI for firewall UX: classify TCP/UDP into application protocols.
 *
 * Hot path must stay cheap — call only on cold ASK/DENY/journal paths, never on every packet.
 *
 * Nested graph:
 * 1. [DpiPayloadGraph] — ordered payload probes (first match wins)
 * 2. [portHeuristic] — well-known ports when the first packet has no payload (TCP SYN)
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
        val payloadOff = DpiBytes.transportPayloadOffset(packet, length, info)
        if (payloadOff != null) {
            val payloadLen = length - payloadOff
            if (payloadLen > 0) {
                DpiPayloadGraph.classify(packet, payloadOff, payloadLen, info)?.let { return it }
            }
        }
        return portHeuristic(info)
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
            info.isTcp && p in DpiSignatures.HTTP_PORTS ->
                Result(label = "HTTP", detail = "port $p", kind = Kind.HTTP)
            info.isTcp && p in DpiSignatures.HTTPS_PORTS ->
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
}
