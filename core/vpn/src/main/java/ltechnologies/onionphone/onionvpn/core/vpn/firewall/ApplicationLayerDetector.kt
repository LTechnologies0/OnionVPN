package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi.DpiBytes
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi.DpiPayloadGraph
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi.DpiPortCatalog

/**
 * Lightweight DPI for firewall UX: classify TCP/UDP into application protocols.
 *
 * Hot path must stay cheap — call only on cold ASK/DENY/journal paths, never on every packet.
 *
 * Nested graph:
 * 1. [DpiPayloadGraph] — ordered payload probes (first match wins)
 * 2. [DpiPortCatalog] — IANA / well-known ports when the first packet has no payload (TCP SYN)
 */
object ApplicationLayerDetector {

    data class Result(
        /** Short label for notifications. */
        val label: String,
        /** Optional detail: QNAME, Host, SNI, method, banner snippet. */
        val detail: String? = null,
        val kind: Kind = Kind.UNKNOWN,
    )

    /**
     * Application-layer kinds (original set + 100+ catalog additions).
     * Prefer payload signatures; ports are a SYN fallback only.
     */
    enum class Kind {
        // Original
        DNS, MDNS, LLMNR, DOH, DOT,
        HTTP, HTTP2, HTTPS, WEBSOCKET, TLS, DTLS, QUIC,
        SSH, FTP, SMTP, SMTPS, IMAP, IMAPS, POP3, POP3S,
        SIP, RTSP, MQTT, STUN, WIREGUARD, OPENVPN,
        RDP, VNC, REDIS, MYSQL, POSTGRES, MONGODB, BITTORRENT,
        SOCKS, NTP, DHCP, TFTP, SSDP, XMPP, IRC, GIT,
        // +100 catalog / signature protocols
        ECHO, DISCARD, DAYTIME, CHARGEN, TIME, TELNET, WHOIS, FINGER, GOPHER,
        IDENT, NNTP, NNTPS, TACACS, KERBEROS, LDAP, LDAPS, SNMP, SYSLOG,
        RADIUS, DIAMETER, BGP, RIP, RIPNG, RPCBIND, NFS, SMB,
        NETBIOS_NS, NETBIOS_DGM, MSRPC, LPD, IPP, AFP, RSYNC, FTPS,
        IKE, L2TP, PPTP, MODBUS, BACNET, IEC104, DNP3, OPCUA,
        TURN, RTMP, COAP, COAPS, AMQP, AMQPS, STOMP, NATS,
        MSSQL, ORACLE, FIREBIRD, SYBASE, DB2, CASSANDRA, COUCHDB,
        ELASTICSEARCH, MEMCACHED, ZOOKEEPER, ETCD, CONSUL, KAFKA,
        CLICKHOUSE, INFLUXDB, NEO4J, HAZELCAST, AEROSPIKE, BEANSTALKD,
        GEARMAN, RABBITMQ, ACTIVEMQ, DOCKER, KUBERNETES, VAULT,
        WINRM, TEAMVIEWER, MINECRAFT, STEAM, TEAMSPEAK, SPOTIFY,
        AIRPLAY, CHROMECAST, WSD, MATRIX, BITCOIN, ETHEREUM, MONERO,
        ELECTRUM, STRATUM, IPFS, TOR_OR, HTTP_PROXY, REXEC, RLOGIN, RSH,
        NDMP, IPERF, HIVE,
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
        return DpiPortCatalog.lookup(info)
            ?: when {
                info.isTcp -> Result(label = "TCP", detail = null, kind = Kind.UNKNOWN)
                info.isUdp -> Result(label = "UDP", detail = null, kind = Kind.UNKNOWN)
                else -> Result(
                    label = IpPacketParser.protocolLabel(info.protocol),
                    detail = null,
                    kind = Kind.UNKNOWN,
                )
            }
    }
}
