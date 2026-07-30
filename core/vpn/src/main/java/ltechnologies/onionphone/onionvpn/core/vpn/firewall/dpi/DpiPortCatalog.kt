package ltechnologies.onionphone.onionvpn.core.vpn.firewall.dpi

import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ApplicationLayerDetector.Kind
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ApplicationLayerDetector.Result
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo

/**
 * IANA / well-known port → protocol catalog for SYN/empty-payload heuristics.
 * Payload [DpiPayloadGraph] still wins when magic bytes match.
 *
 * RFCs cited in [ApplicationLayerDetector] / [DpiSignatures] where applicable.
 */
internal object DpiPortCatalog {

    data class Entry(
        val label: String,
        val kind: Kind,
        val tcp: Boolean = true,
        val udp: Boolean = false,
        val detail: String? = null,
    )

    /** When dst port maps to exactly one protocol for this L4, DPI can try that family first. */
    fun uniqueKindForPort(info: IpPacketInfo): Kind? {
        val hits = BY_PORT[info.dstPort] ?: return null
        val matched = hits.filter { e -> (info.isTcp && e.tcp) || (info.isUdp && e.udp) }
        if (matched.size != 1) return null
        return matched.first().kind
    }

    fun lookup(info: IpPacketInfo): Result? {
        val p = info.dstPort
        val hits = BY_PORT[p] ?: return null
        for (e in hits) {
            when {
                info.isTcp && e.tcp ->
                    return Result(label = e.label, detail = e.detail ?: "port $p", kind = e.kind)
                info.isUdp && e.udp ->
                    return Result(label = e.label, detail = e.detail ?: "port $p", kind = e.kind)
            }
        }
        // Also match when only srcPort is well-known (server→client first packet rare).
        val srcHits = BY_PORT[info.srcPort] ?: return null
        for (e in srcHits) {
            when {
                info.isTcp && e.tcp ->
                    return Result(
                        label = e.label,
                        detail = e.detail ?: "src port ${info.srcPort}",
                        kind = e.kind,
                    )
                info.isUdp && e.udp ->
                    return Result(
                        label = e.label,
                        detail = e.detail ?: "src port ${info.srcPort}",
                        kind = e.kind,
                    )
            }
        }
        return null
    }

    /** 100+ additional / classic application ports beyond the original DPI set. */
    private val BY_PORT: Map<Int, List<Entry>> = buildMap {
        fun put(port: Int, vararg entries: Entry) {
            put(port, entries.toList())
        }

        // --- Original core (kept for catalog completeness) ---
        put(7, Entry("Echo", Kind.ECHO, tcp = true, udp = true, detail = "RFC 862"))
        put(9, Entry("Discard", Kind.DISCARD, tcp = true, udp = true, detail = "RFC 863"))
        put(13, Entry("Daytime", Kind.DAYTIME, tcp = true, udp = true, detail = "RFC 867"))
        put(19, Entry("Chargen", Kind.CHARGEN, tcp = true, udp = true, detail = "RFC 864"))
        put(21, Entry("FTP", Kind.FTP, detail = "RFC 959"))
        put(22, Entry("SSH", Kind.SSH, detail = "RFC 4253"))
        put(23, Entry("Telnet", Kind.TELNET, detail = "RFC 854"))
        put(25, Entry("SMTP", Kind.SMTP, detail = "RFC 5321"))
        put(37, Entry("Time", Kind.TIME, tcp = true, udp = true, detail = "RFC 868"))
        put(43, Entry("WHOIS", Kind.WHOIS, detail = "RFC 3912"))
        put(49, Entry("TACACS+", Kind.TACACS, detail = "RFC 8907"))
        put(53, Entry("DNS", Kind.DNS, tcp = true, udp = true, detail = "RFC 1035"))
        put(67, Entry("DHCP", Kind.DHCP, tcp = false, udp = true, detail = "RFC 2131"))
        put(68, Entry("DHCP", Kind.DHCP, tcp = false, udp = true, detail = "RFC 2131"))
        put(69, Entry("TFTP", Kind.TFTP, tcp = false, udp = true, detail = "RFC 1350"))
        put(70, Entry("Gopher", Kind.GOPHER, detail = "RFC 1436"))
        put(79, Entry("Finger", Kind.FINGER, detail = "RFC 1288"))
        put(80, Entry("HTTP", Kind.HTTP, detail = "RFC 9110"), Entry("HTTP/3", Kind.QUIC, tcp = false, udp = true))
        put(88, Entry("Kerberos", Kind.KERBEROS, tcp = true, udp = true, detail = "RFC 4120"))
        put(110, Entry("POP3", Kind.POP3, detail = "RFC 1939"))
        put(111, Entry("RPCBIND", Kind.RPCBIND, tcp = true, udp = true, detail = "RFC 1833"))
        put(113, Entry("Ident", Kind.IDENT, detail = "RFC 1413"))
        put(119, Entry("NNTP", Kind.NNTP, detail = "RFC 3977"))
        put(123, Entry("NTP", Kind.NTP, tcp = false, udp = true, detail = "RFC 5905"))
        put(135, Entry("MSRPC", Kind.MSRPC, tcp = true, udp = true))
        put(137, Entry("NetBIOS-NS", Kind.NETBIOS_NS, tcp = false, udp = true))
        put(138, Entry("NetBIOS-DGM", Kind.NETBIOS_DGM, tcp = false, udp = true))
        put(139, Entry("NetBIOS-SSN", Kind.SMB, detail = "SMB over NetBIOS"))
        put(143, Entry("IMAP", Kind.IMAP, detail = "RFC 9051"))
        put(161, Entry("SNMP", Kind.SNMP, tcp = false, udp = true, detail = "RFC 3411"))
        put(162, Entry("SNMP-Trap", Kind.SNMP, tcp = false, udp = true, detail = "RFC 3411"))
        put(179, Entry("BGP", Kind.BGP, detail = "RFC 4271"))
        put(389, Entry("LDAP", Kind.LDAP, detail = "RFC 4511"))
        put(443, Entry("HTTPS", Kind.HTTPS, detail = "RFC 8446"), Entry("HTTP/3", Kind.QUIC, tcp = false, udp = true))
        put(445, Entry("SMB", Kind.SMB, detail = "CIFS/SMB"))
        put(464, Entry("Kerberos", Kind.KERBEROS, tcp = true, udp = true, detail = "kpasswd"))
        put(465, Entry("SMTPS", Kind.SMTPS, detail = "RFC 8314"))
        put(500, Entry("IKE", Kind.IKE, tcp = false, udp = true, detail = "RFC 7296"))
        put(502, Entry("Modbus", Kind.MODBUS, detail = "Modbus TCP"))
        put(512, Entry("rexec", Kind.REXEC))
        put(513, Entry("rlogin", Kind.RLOGIN))
        put(514, Entry("Syslog", Kind.SYSLOG, tcp = false, udp = true, detail = "RFC 5424"), Entry("rsh", Kind.RSH, udp = false))
        put(515, Entry("LPD", Kind.LPD, detail = "RFC 1179"))
        put(520, Entry("RIP", Kind.RIP, tcp = false, udp = true, detail = "RFC 2453"))
        put(521, Entry("RIPng", Kind.RIPNG, tcp = false, udp = true, detail = "RFC 2080"))
        put(548, Entry("AFP", Kind.AFP))
        put(554, Entry("RTSP", Kind.RTSP, tcp = true, udp = true, detail = "RFC 7826"))
        put(563, Entry("NNTPS", Kind.NNTPS))
        put(587, Entry("SMTPS", Kind.SMTPS, detail = "submission"))
        put(631, Entry("IPP", Kind.IPP, detail = "RFC 8010 / CUPS"))
        put(636, Entry("LDAPS", Kind.LDAPS, detail = "RFC 4511 + TLS"))
        put(853, Entry("DoT", Kind.DOT, detail = "RFC 7858"))
        put(873, Entry("Rsync", Kind.RSYNC))
        put(989, Entry("FTPS", Kind.FTPS, detail = "data"))
        put(990, Entry("FTPS", Kind.FTPS, detail = "control"))
        put(993, Entry("IMAPS", Kind.IMAPS))
        put(995, Entry("POP3S", Kind.POP3S))
        put(1080, Entry("SOCKS", Kind.SOCKS, detail = "RFC 1928"))
        put(1194, Entry("OpenVPN", Kind.OPENVPN, tcp = true, udp = true))
        put(1433, Entry("MSSQL", Kind.MSSQL))
        put(1434, Entry("MSSQL-Browser", Kind.MSSQL, tcp = false, udp = true))
        put(1521, Entry("Oracle", Kind.ORACLE))
        put(1701, Entry("L2TP", Kind.L2TP, tcp = false, udp = true, detail = "RFC 2661"))
        put(1723, Entry("PPTP", Kind.PPTP, detail = "RFC 2637"))
        put(1812, Entry("RADIUS", Kind.RADIUS, tcp = false, udp = true, detail = "RFC 2865"))
        put(1813, Entry("RADIUS-Acct", Kind.RADIUS, tcp = false, udp = true, detail = "RFC 2866"))
        put(1883, Entry("MQTT", Kind.MQTT, detail = "OASIS MQTT"))
        put(1900, Entry("SSDP", Kind.SSDP, tcp = false, udp = true))
        put(1935, Entry("RTMP", Kind.RTMP))
        put(2049, Entry("NFS", Kind.NFS, tcp = true, udp = true, detail = "RFC 7530"))
        put(2181, Entry("ZooKeeper", Kind.ZOOKEEPER))
        put(2375, Entry("Docker", Kind.DOCKER))
        put(2376, Entry("Docker-TLS", Kind.DOCKER))
        put(2379, Entry("etcd", Kind.ETCD))
        put(2380, Entry("etcd-peer", Kind.ETCD))
        put(2404, Entry("IEC-104", Kind.IEC104))
        put(25565, Entry("Minecraft", Kind.MINECRAFT))
        put(27015, Entry("Steam", Kind.STEAM, tcp = true, udp = true))
        put(27017, Entry("MongoDB", Kind.MONGODB))
        put(3000, Entry("Aerospike", Kind.AEROSPIKE))
        put(3050, Entry("Firebird", Kind.FIREBIRD))
        put(3128, Entry("HTTP-Proxy", Kind.HTTP_PROXY))
        put(3268, Entry("LDAP-GC", Kind.LDAP, detail = "AD Global Catalog"))
        put(3269, Entry("LDAPS-GC", Kind.LDAPS))
        put(3306, Entry("MySQL", Kind.MYSQL))
        put(3333, Entry("Stratum", Kind.STRATUM))
        put(3389, Entry("RDP", Kind.RDP))
        put(3478, Entry("STUN", Kind.STUN, tcp = true, udp = true, detail = "RFC 8489"), Entry("TURN", Kind.TURN, tcp = true, udp = true, detail = "RFC 8656"))
        put(3702, Entry("WS-Discovery", Kind.WSD, tcp = false, udp = true))
        put(3868, Entry("Diameter", Kind.DIAMETER, detail = "RFC 6733"))
        put(4070, Entry("Spotify", Kind.SPOTIFY))
        put(4222, Entry("NATS", Kind.NATS))
        put(4500, Entry("IKE-NAT", Kind.IKE, tcp = false, udp = true, detail = "RFC 3948"))
        put(4730, Entry("Gearman", Kind.GEARMAN))
        put(4840, Entry("OPC-UA", Kind.OPCUA))
        put(5000, Entry("Sybase", Kind.SYBASE), Entry("HTTP", Kind.HTTP, detail = "alt HTTP"))
        put(5001, Entry("Iperf", Kind.IPERF, tcp = true, udp = true))
        put(5060, Entry("SIP", Kind.SIP, tcp = true, udp = true, detail = "RFC 3261"))
        put(5061, Entry("SIP/TLS", Kind.SIP, detail = "RFC 3261"))
        put(5222, Entry("XMPP", Kind.XMPP, detail = "RFC 6120"))
        put(5223, Entry("XMPP", Kind.XMPP, detail = "Apple push / XMPP TLS"))
        put(5269, Entry("XMPP-S2S", Kind.XMPP, detail = "RFC 6120 s2s"))
        put(5349, Entry("STUNS", Kind.STUN, tcp = true, udp = true, detail = "TLS TURN"))
        put(5353, Entry("mDNS", Kind.MDNS, tcp = false, udp = true, detail = "RFC 6762"))
        put(5355, Entry("LLMNR", Kind.LLMNR, tcp = true, udp = true, detail = "RFC 4795"))
        put(5432, Entry("PostgreSQL", Kind.POSTGRES))
        put(5671, Entry("AMQPS", Kind.AMQPS, detail = "AMQP over TLS"))
        put(5672, Entry("AMQP", Kind.AMQP, detail = "OASIS AMQP 1.0"))
        put(5683, Entry("CoAP", Kind.COAP, tcp = false, udp = true, detail = "RFC 7252"))
        put(5684, Entry("CoAPS", Kind.COAPS, tcp = false, udp = true, detail = "RFC 7252"))
        put(5701, Entry("Hazelcast", Kind.HAZELCAST))
        put(5900, Entry("VNC", Kind.VNC, detail = "RFB"))
        put(5938, Entry("TeamViewer", Kind.TEAMVIEWER))
        put(5984, Entry("CouchDB", Kind.COUCHDB))
        put(5985, Entry("WinRM", Kind.WINRM, detail = "HTTP"))
        put(5986, Entry("WinRM-TLS", Kind.WINRM, detail = "HTTPS"))
        put(6379, Entry("Redis", Kind.REDIS))
        put(6443, Entry("Kubernetes", Kind.KUBERNETES))
        put(6667, Entry("IRC", Kind.IRC, detail = "RFC 1459"))
        put(6697, Entry("IRC", Kind.IRC, detail = "IRC+TLS"))
        put(6881, Entry("BitTorrent", Kind.BITTORRENT))
        put(7000, Entry("AirPlay", Kind.AIRPLAY))
        put(7687, Entry("Neo4j", Kind.NEO4J, detail = "Bolt"))
        put(8009, Entry("Chromecast", Kind.CHROMECAST))
        put(8080, Entry("HTTP", Kind.HTTP, detail = "alt"))
        put(8086, Entry("InfluxDB", Kind.INFLUXDB))
        put(8123, Entry("ClickHouse", Kind.CLICKHOUSE))
        put(8200, Entry("Vault", Kind.VAULT))
        put(8333, Entry("Bitcoin", Kind.BITCOIN))
        put(8443, Entry("HTTPS", Kind.HTTPS, detail = "alt"))
        put(8448, Entry("Matrix", Kind.MATRIX, detail = "federation"))
        put(8500, Entry("Consul", Kind.CONSUL))
        put(8883, Entry("MQTT", Kind.MQTT, detail = "MQTT over TLS"))
        put(9001, Entry("Tor-OR", Kind.TOR_OR))
        put(9042, Entry("Cassandra", Kind.CASSANDRA))
        put(9050, Entry("SOCKS", Kind.SOCKS, detail = "Tor"))
        put(9092, Entry("Kafka", Kind.KAFKA))
        put(9150, Entry("SOCKS", Kind.SOCKS, detail = "TBB"))
        put(9200, Entry("Elasticsearch", Kind.ELASTICSEARCH))
        put(9418, Entry("Git", Kind.GIT))
        put(9987, Entry("TeamSpeak", Kind.TEAMSPEAK, tcp = false, udp = true))
        put(10000, Entry("Hive", Kind.HIVE), Entry("NDMP", Kind.NDMP))
        put(11211, Entry("Memcached", Kind.MEMCACHED, tcp = true, udp = true))
        put(11300, Entry("Beanstalkd", Kind.BEANSTALKD))
        put(15672, Entry("RabbitMQ-Mgmt", Kind.RABBITMQ))
        put(18080, Entry("Monero", Kind.MONERO))
        put(20000, Entry("DNP3", Kind.DNP3))
        put(30303, Entry("Ethereum", Kind.ETHEREUM, tcp = true, udp = true))
        put(4001, Entry("IPFS", Kind.IPFS))
        put(47808, Entry("BACnet", Kind.BACNET, tcp = false, udp = true))
        put(50000, Entry("DB2", Kind.DB2))
        put(50001, Entry("Electrum", Kind.ELECTRUM))
        put(51820, Entry("WireGuard", Kind.WIREGUARD, tcp = false, udp = true))
        put(61613, Entry("STOMP", Kind.STOMP))
        put(61616, Entry("ActiveMQ", Kind.ACTIVEMQ))

        // WireGuard adjacent ports often used by clients
        for (p in 51821..51830) {
            put(p, Entry("WireGuard", Kind.WIREGUARD, tcp = false, udp = true))
        }
        for (p in 6882..6889) {
            put(p, Entry("BitTorrent", Kind.BITTORRENT))
        }
        for (p in 5901..5910) {
            put(p, Entry("VNC", Kind.VNC))
        }
    }
}
