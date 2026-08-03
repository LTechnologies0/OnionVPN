package ltechnologies.onionphone.onionvpn.core.model

/**
 * Fail-closed network policy for OnionVPN: every clearnet name → DNSCrypt-over-Tor,
 * every `.onion`/`.exit` → Tor Automap + SOCKS5A, every torrifiable TCP → Tor/Arti SOCKS.
 *
 * Host rules follow RFC 1035 / 1123; onion/exit follow Tor address-spec.
 * IP classification follows RFC 1918 / 3927 / 4291 / 5737 / 6598 and Tor Automap pools.
 */
object TorNetPolicy {
    enum class DnsRoute {
        /** `.onion` / `.exit` → Tor DNSPort Automap (never DNSCrypt). */
        TorAutomap,
        /** Clearnet FQDN → local DNSCrypt stub (SOCKS5 upstream = Tor). */
        DnsCryptOverTor,
        /** Malformed / empty / injection — drop. */
        Drop,
    }

    enum class IpClass {
        Loopback,
        PrivateRfc1918,
        LinkLocal,
        Multicast,
        Broadcast,
        Documentation,
        Cgnat,
        TorAutomap,
        VpnTun,
        Unspecified,
        GloballyRoutable,
        Invalid,
    }

    /** Absolute max FQDN length (RFC 1035). */
    const val MAX_HOSTNAME_LEN = 253
    const val MAX_LABEL_LEN = 63
    const val MAX_DNS_QDCOUNT = 8
    const val MAX_DNS_ANSWERS = 32

    fun normalizeHostname(hostname: String): String =
        hostname.trim().trimEnd('.').lowercase()

    /**
     * Clearnet DNS hostname (RFC 1123) **or** Tor special name (onion/exit suffix).
     * Rejects empty, CRLF, spaces, underscores, and overlong names.
     */
    fun isValidDnsHostname(hostname: String): Boolean {
        val h = normalizeHostname(hostname)
        if (h.isEmpty() || h.length > MAX_HOSTNAME_LEN) return false
        if (h.any { it <= ' ' || it == '"' || it == '\\' }) return false
        if (TunnelEndpoints.isOnionLikeHostname(h)) {
            // Automap candidates: allow any `.onion`/`.exit` label set that is DNS-shaped
            // so Tor sees the query; strict v3 checks are [TunnelEndpoints.isValidOnionHostname].
            return h.split('.').all { isDnsLabel(it) }
        }
        return isRfc1123Hostname(h)
    }

    /** Strict clearnet FQDN (no `.onion`/`.exit`). */
    fun isValidClearnetHostname(hostname: String): Boolean {
        val h = normalizeHostname(hostname)
        if (h.isEmpty() || TunnelEndpoints.isOnionLikeHostname(h)) return false
        return isRfc1123Hostname(h)
    }

    /**
     * SOCKS5 CONNECT destination: IPv4/IPv6 literal, clearnet hostname, or onion-like.
     * Dotted-quad lookalikes that are not valid IPv4 are rejected (never treated as DNS).
     */
    fun isValidSocksDestination(host: String): Boolean {
        val h = host.trim()
        if (h.isEmpty() || h.length > MAX_HOSTNAME_LEN) return false
        if (h.any { it <= ' ' || it == '"' || it == '\r' || it == '\n' }) return false
        if (TunnelEndpoints.parseIpv4Literal(h) != null) return true
        if (looksLikeDottedQuad(h)) return false
        if (h.indexOf(':') >= 0) return isValidIpv6Literal(h)
        return isValidDnsHostname(h)
    }

    /** Four all-digit labels — IPv4 shape, not a hostname. */
    private fun looksLikeDottedQuad(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        return parts.all { label -> label.isNotEmpty() && label.all { it in '0'..'9' } }
    }

    fun isValidPort(port: Int): Boolean = port in 1..65535

    /**
     * Classify a DNS QNAME for the torrified path.
     * Invalid → [DnsRoute.Drop]; onion/exit → Automap; else → DNSCrypt-over-Tor.
     */
    fun classifyDnsQuery(qname: String?): DnsRoute {
        if (qname.isNullOrBlank()) return DnsRoute.Drop
        val h = normalizeHostname(qname)
        if (!isValidDnsHostname(h)) return DnsRoute.Drop
        if (TunnelEndpoints.isOnionLikeHostname(h)) return DnsRoute.TorAutomap
        return DnsRoute.DnsCryptOverTor
    }

    /** True when an A/AAAA RDATA string is a parseable IP (including Automap / CGNAT). */
    fun isValidDnsAddressRecord(ip: String): Boolean {
        val s = ip.trim()
        if (s.isEmpty()) return false
        if (TunnelEndpoints.parseIpv4Literal(s) != null) return true
        return isValidIpv6Literal(s)
    }

    fun classifyIpv4(ipInt: Int): IpClass {
        val a = (ipInt ushr 24) and 0xff
        val b = (ipInt ushr 16) and 0xff
        val c = (ipInt ushr 8) and 0xff
        val d = ipInt and 0xff
        when {
            a == 0 -> return IpClass.Unspecified
            a == 127 -> return IpClass.Loopback
            a == 10 -> {
                if (b in 192..255) return IpClass.TorAutomap
                if (b == 8 && c == 0 && (d == 1 || d == 2)) return IpClass.VpnTun
                return IpClass.PrivateRfc1918
            }
            a == 172 && b in 16..31 -> return IpClass.PrivateRfc1918
            a == 192 && b == 168 -> return IpClass.PrivateRfc1918
            a == 169 && b == 254 -> return IpClass.LinkLocal
            a == 100 && b in 64..127 -> return IpClass.Cgnat
            a == 192 && b == 0 && c == 2 -> return IpClass.Documentation // TEST-NET-1
            a == 198 && b == 51 && c == 100 -> return IpClass.Documentation // TEST-NET-2
            a == 203 && b == 0 && c == 113 -> return IpClass.Documentation // TEST-NET-3
            a >= 224 && a <= 239 -> return IpClass.Multicast
            a >= 240 -> return IpClass.Broadcast
            a == 255 && b == 255 && c == 255 && d == 255 -> return IpClass.Broadcast
            else -> return IpClass.GloballyRoutable
        }
    }

    fun classifyIpv4Literal(hostAddress: String): IpClass {
        val ip = TunnelEndpoints.parseIpv4Literal(hostAddress) ?: return IpClass.Invalid
        return classifyIpv4(ip)
    }

    /**
     * Destinations that must never reach Tor SOCKS / hev / onionmasq (LAN, CGNAT,
     * loopback, VPN TUN, documentation, multicast, link-local).
     * Tor Automap virtuals and globally routable addresses still go through Tor SOCKS.
     */
    fun mustBlackholeIpv4Destination(ipInt: Int): Boolean =
        when (classifyIpv4(ipInt)) {
            IpClass.Multicast, IpClass.Broadcast, IpClass.LinkLocal, IpClass.Unspecified,
            IpClass.Invalid,
            IpClass.PrivateRfc1918, IpClass.Cgnat, IpClass.Loopback, IpClass.VpnTun,
            IpClass.Documentation,
            -> true
            // TorAutomap + GloballyRoutable → false (torrify)
            else -> false
        }

    fun isRfc1123Hostname(hostname: String): Boolean {
        if (hostname.isEmpty() || hostname.length > MAX_HOSTNAME_LEN) return false
        if (hostname.startsWith('.') || hostname.endsWith('.')) return false
        if (hostname.contains("..")) return false
        val labels = hostname.split('.')
        if (labels.isEmpty() || labels.size > 127) return false
        // Require at least one dot for FQDN-style clearnet (e.g. example.com), except single-label
        // localhost-style which we reject for DNSCrypt (no ISP search domains).
        if (labels.size < 2) return false
        return labels.all { isDnsLabel(it) }
    }

    fun isDnsLabel(label: String): Boolean {
        if (label.isEmpty() || label.length > MAX_LABEL_LEN) return false
        if (label[0] == '-' || label.last() == '-') return false
        for (ch in label) {
            val ok = ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch == '-'
            if (!ok) return false
        }
        return true
    }

    fun isValidIpv6Literal(host: String): Boolean {
        if (host.isEmpty() || host.indexOf(':') < 0) return false
        if (host.any { it <= ' ' }) return false
        return runCatching {
            val raw = java.net.InetAddress.getByName(host).address
            raw.size == 16
        }.getOrDefault(false)
    }

    /**
     * IPv4 header sanity: version, IHL, Total Length vs buffer.
     * @return false → drop before any routing decision.
     */
    fun isWellFormedIpv4Packet(packet: ByteArray, length: Int): Boolean {
        if (length < 20 || packet.size < length) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return false
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl) return false
        val totalLen = ((packet[2].toInt() and 0xff) shl 8) or (packet[3].toInt() and 0xff)
        // Some stacks leave Total Length 0 on TUN; accept 0 or length match / ≤ buffer.
        if (totalLen != 0 && (totalLen < ihl || totalLen > length)) return false
        return true
    }

    fun isWellFormedIpv6Packet(packet: ByteArray, length: Int): Boolean {
        if (length < 40 || packet.size < length) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 6) return false
        val payloadLen = ((packet[4].toInt() and 0xff) shl 8) or (packet[5].toInt() and 0xff)
        // payloadLen is without the 40-byte header; 0 allowed (jumbogram / some TUN).
        if (payloadLen != 0 && 40 + payloadLen > length) return false
        return true
    }

    /** TCP/UDP port fields after a validated IP header. */
    fun isWellFormedTransportPorts(srcPort: Int, dstPort: Int): Boolean =
        srcPort in 0..65535 && dstPort in 0..65535 && dstPort != 0
}
