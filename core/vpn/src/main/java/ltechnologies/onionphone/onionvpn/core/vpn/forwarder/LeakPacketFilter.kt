package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.util.concurrent.atomic.AtomicLong
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import timber.log.Timber

/**
 * Fail-closed packet filters for torrified VPN (Privacy Guides / Tor: TCP + DNS only).
 *
 * Strategy (no remote UDP gateway until prop. 339 ships):
 * 1. Divert UDP/53 (IPv4) → DNSCrypt-over-Tor (handled by [TunDnsMux]).
 * 2. Forward IPv4 TCP (+ Automap IPv6 ULA) via hev → SocksUidBridge → Tor SOCKS.
 * 3. Blackhole clearnet IPv6 TCP (DNSCrypt A-only; kills Happy Eyeballs Tor stalls),
 *    other UDP/ICMP/multicast so apps fall back to TCP.
 * 4. Never forward to the clearnet underlying network.
 */
object LeakPacketFilter {
    private const val PROTO_ICMP = 1
    private const val PROTO_IGMP = 2
    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17
    private const val PROTO_ICMPV6 = 58

    /** STUN magic cookie (RFC 8489). */
    private const val STUN_MAGIC_0 = 0x21
    private const val STUN_MAGIC_1 = 0x12
    private const val STUN_MAGIC_2 = 0xA4
    private const val STUN_MAGIC_3 = 0x42

    enum class UdpDisposition {
        /** UDP destination port 53 — divert to DNSCrypt (torrified). */
        DivertDns,
        /** Drop to force TCP fallback / kill UDP side-channels. */
        Blackhole,
    }

    enum class BlackholeReason {
        NotUdp,
        Multicast,
        LinkLocal,
        Icmp,
        QuicHttp3,
        StunWebrtc,
        MdnsLlmnr,
        Ssdp,
        Ntp,
        Dhcp,
        WireGuard,
        OpenVpn,
        Dtls,
        TcpDns,
        GenericUdp,
        /** Clearnet IPv6 TCP (non-Automap) — force IPv4 / Happy Eyeballs fail-fast. */
        Ipv6,
    }

    private val dropQuic = AtomicLong(0)
    private val dropStun = AtomicLong(0)
    private val dropOtherUdp = AtomicLong(0)
    private val dropNonUdp = AtomicLong(0)
    private var lastLogNs = 0L

    fun resetStats() {
        dropQuic.set(0)
        dropStun.set(0)
        dropOtherUdp.set(0)
        dropNonUdp.set(0)
    }

    fun statsSummary(): String =
        "quic=${dropQuic.get()} stun/webrtc=${dropStun.get()} " +
            "udp_other=${dropOtherUdp.get()} non_udp=${dropNonUdp.get()}"

    /**
     * @return true if the packet may be considered for Tor SOCKS / DNS divert.
     * IPv4 or IPv6 TCP (except TCP DNS/DoT) → true.
     */
    fun isTorrifiableTcp(packet: ByteArray, length: Int): Boolean {
        if (length < 20) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        return when (version) {
            4 -> isTorrifiableIpv4Tcp(packet, length)
            6 -> isTorrifiableIpv6Tcp(packet, length)
            else -> false
        }
    }

    /** @deprecated Prefer [isTorrifiableTcp]. */
    fun isTorrifiableIpv4Tcp(packet: ByteArray, length: Int): Boolean {
        if (length < 20) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return false
        if (isMulticastOrBroadcastV4(packet)) return false
        val proto = packet[9].toInt() and 0xff
        if (proto != PROTO_TCP) return false
        if (isDnsTcpPort(packet, length)) return false
        return true
    }

    fun isTorrifiableIpv6Tcp(packet: ByteArray, length: Int): Boolean {
        if (length < 40) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 6) return false
        if (isMulticastOrLinkLocalV6(packet)) return false
        // Assume no extension headers (common TUN path); next-header at offset 6.
        val next = packet[6].toInt() and 0xff
        if (next != PROTO_TCP) return false
        if (length < 40 + 20) return false
        val destPort = ((packet[40 + 2].toInt() and 0xff) shl 8) or
            (packet[40 + 3].toInt() and 0xff)
        // TCP/53 and DoT/853 → blackhole; apps must use UDP/53 → DNSCrypt.
        if (destPort == 53 || destPort == 853) return false
        // Clearnet IPv6 TCP: blackhole — DNSCrypt is A-only; Happy Eyeballs IPv6
        // races through Tor exits cause SSL timeouts (Speedtest). Automap ULA only.
        val dest = ipv6DestHost(packet) ?: return false
        return TunnelEndpoints.isAutomapVirtualIpv6(dest)
    }

    /** True when IPv4 UDP dest port is 53 (IPv6 DNS is blackholed — mux is IPv4-only). */
    fun isDnsUdpPort53(packet: ByteArray, length: Int): Boolean {
        if (length < 28) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return false
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (length < ihl + 8) return false
        if (packet[9].toInt() and 0xff != PROTO_UDP) return false
        val destPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or
            (packet[ihl + 3].toInt() and 0xff)
        return destPort == 53
    }

    /** IPv6 UDP/53 — blackhole until TunDnsMux supports v6 DNS replies. */
    fun isIpv6DnsUdpPort53(packet: ByteArray, length: Int): Boolean {
        if (length < 40 + 8) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 6) return false
        if (packet[6].toInt() and 0xff != PROTO_UDP) return false
        val destPort = ((packet[40 + 2].toInt() and 0xff) shl 8) or
            (packet[40 + 3].toInt() and 0xff)
        return destPort == 53
    }

    /** TCP DNS (53) or DoT (853) — blackhole so apps use UDP/53 → DNSCrypt. */
    fun isDnsTcpPort(packet: ByteArray, length: Int): Boolean {
        if (length < 40) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        return when (version) {
            4 -> {
                val ihl = (packet[0].toInt() and 0x0f) * 4
                if (length < ihl + 20) return false
                if (packet[9].toInt() and 0xff != PROTO_TCP) return false
                val destPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or
                    (packet[ihl + 3].toInt() and 0xff)
                destPort == 53 || destPort == 853
            }
            6 -> {
                if (length < 40 + 20) return false
                if (packet[6].toInt() and 0xff != PROTO_TCP) return false
                val destPort = ((packet[40 + 2].toInt() and 0xff) shl 8) or
                    (packet[40 + 3].toInt() and 0xff)
                destPort == 53 || destPort == 853
            }
            else -> false
        }
    }

    fun classifyUdp(packet: ByteArray, length: Int): UdpDisposition {
        return if (isDnsUdpPort53(packet, length)) {
            UdpDisposition.DivertDns
        } else {
            UdpDisposition.Blackhole
        }
    }

    fun classifyBlackholeReason(packet: ByteArray, length: Int): BlackholeReason {
        if (length < 20) return BlackholeReason.GenericUdp
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version == 6) {
            if (isMulticastOrLinkLocalV6(packet)) return BlackholeReason.Multicast
            val next = packet[6].toInt() and 0xff
            return when (next) {
                PROTO_ICMPV6 -> BlackholeReason.Icmp
                PROTO_TCP -> when {
                    isDnsTcpPort(packet, length) -> BlackholeReason.TcpDns
                    !isTorrifiableIpv6Tcp(packet, length) -> BlackholeReason.Ipv6
                    else -> BlackholeReason.NotUdp
                }
                PROTO_UDP -> classifyUdpPortReasonV6(packet, length)
                else -> BlackholeReason.GenericUdp
            }
        }
        if (version != 4) return BlackholeReason.GenericUdp
        if (isMulticastOrBroadcastV4(packet)) return BlackholeReason.Multicast
        if (isLinkLocalV4(packet)) return BlackholeReason.LinkLocal
        val proto = packet[9].toInt() and 0xff
        when (proto) {
            PROTO_ICMP, PROTO_IGMP, PROTO_ICMPV6 -> return BlackholeReason.Icmp
            PROTO_TCP -> {
                return if (isDnsTcpPort(packet, length)) {
                    BlackholeReason.TcpDns
                } else {
                    BlackholeReason.NotUdp
                }
            }
            PROTO_UDP -> Unit
            else -> return BlackholeReason.GenericUdp
        }
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (length < ihl + 8) return BlackholeReason.GenericUdp
        val dstPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or
            (packet[ihl + 3].toInt() and 0xff)
        val payloadOff = ihl + 8
        val payloadLen = length - payloadOff
        return classifyUdpPortReason(dstPort, packet, payloadOff, payloadLen)
    }

    fun noteBlackhole(reason: BlackholeReason) {
        when (reason) {
            BlackholeReason.QuicHttp3 -> dropQuic.incrementAndGet()
            BlackholeReason.StunWebrtc -> dropStun.incrementAndGet()
            BlackholeReason.Ipv6, BlackholeReason.Icmp, BlackholeReason.Multicast,
            BlackholeReason.LinkLocal, BlackholeReason.NotUdp, BlackholeReason.TcpDns,
            -> dropNonUdp.incrementAndGet()
            else -> dropOtherUdp.incrementAndGet()
        }
        val now = System.nanoTime()
        if (now - lastLogNs > 5_000_000_000L) {
            lastLogNs = now
            Timber.i("UDP/non-TCP blackhole (force TCP): %s | %s", reason, statsSummary())
        }
    }

    /**
     * @return null if the packet may continue toward hev; otherwise blackhole reason.
     */
    fun blackholeBeforeTorTcp(packet: ByteArray, length: Int): BlackholeReason? {
        if (shouldDropEarly(packet, length)) {
            return if (length >= 20) classifyBlackholeReason(packet, length) else BlackholeReason.GenericUdp
        }
        if (shouldBlackholeUdp(packet, length)) {
            return classifyBlackholeReason(packet, length)
        }
        if (!isTorrifiableTcp(packet, length)) {
            return classifyBlackholeReason(packet, length)
        }
        return null
    }

    /**
         * Early drop before DNS divert / firewall.
         * IPv4 UDP/53 is NOT dropped here (caller diverts). IPv6 UDP/53 blackholes (mux IPv4-only).
         */
    fun shouldDropEarly(packet: ByteArray, length: Int): Boolean {
        if (length < 20) return true
        val version = (packet[0].toInt() ushr 4) and 0x0f
        return when (version) {
            4 -> {
                if (isMulticastOrBroadcastV4(packet)) return true
                if (isLinkLocalV4(packet)) return true
                val proto = packet[9].toInt() and 0xff
                when (proto) {
                    PROTO_TCP, PROTO_UDP -> false
                    PROTO_ICMP, PROTO_IGMP, PROTO_ICMPV6 -> true
                    else -> true
                }
            }
            6 -> {
                if (length < 40) return true
                if (isMulticastOrLinkLocalV6(packet)) return true
                val next = packet[6].toInt() and 0xff
                when (next) {
                    PROTO_TCP, PROTO_UDP -> false
                    PROTO_ICMPV6 -> true
                    else -> true
                }
            }
            else -> true
        }
    }

    /** Non-DNS UDP must never reach the SOCKS engine. */
    fun shouldBlackholeUdp(packet: ByteArray, length: Int): Boolean {
        if (length < 20) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        val isUdp = when (version) {
            4 -> (packet[9].toInt() and 0xff) == PROTO_UDP
            6 -> length >= 40 && (packet[6].toInt() and 0xff) == PROTO_UDP
            else -> false
        }
        return isUdp && classifyUdp(packet, length) == UdpDisposition.Blackhole
    }

    private fun classifyUdpPortReasonV6(packet: ByteArray, length: Int): BlackholeReason {
        if (length < 40 + 8) return BlackholeReason.GenericUdp
        val dstPort = ((packet[40 + 2].toInt() and 0xff) shl 8) or
            (packet[40 + 3].toInt() and 0xff)
        val payloadOff = 40 + 8
        val payloadLen = length - payloadOff
        return classifyUdpPortReason(dstPort, packet, payloadOff, payloadLen)
    }

    private fun classifyUdpPortReason(
        dstPort: Int,
        packet: ByteArray,
        payloadOff: Int,
        payloadLen: Int,
    ): BlackholeReason {
        when (dstPort) {
            53 -> return BlackholeReason.TcpDns // IPv6 UDP/53 (mux is IPv4-only)
            443, 80, 8443, 853 -> {
                if (payloadLen > 0 && looksLikeQuic(packet, payloadOff, payloadLen)) {
                    return BlackholeReason.QuicHttp3
                }
                if (dstPort == 443 || dstPort == 80) return BlackholeReason.QuicHttp3
            }
            3478, 3479, 5349, 19302, 19305, 19306, 19307, 19308, 19309 ->
                return BlackholeReason.StunWebrtc
            5353, 5355 -> return BlackholeReason.MdnsLlmnr
            1900 -> return BlackholeReason.Ssdp
            123 -> return BlackholeReason.Ntp
            67, 68 -> return BlackholeReason.Dhcp
            51820 -> return BlackholeReason.WireGuard
            1194 -> return BlackholeReason.OpenVpn
        }
        if (payloadLen >= 20 && looksLikeStun(packet, payloadOff, payloadLen)) {
            return BlackholeReason.StunWebrtc
        }
        if (payloadLen >= 5 && looksLikeQuic(packet, payloadOff, payloadLen)) {
            return BlackholeReason.QuicHttp3
        }
        if (payloadLen >= 13 && looksLikeDtls(packet, payloadOff, payloadLen)) {
            return BlackholeReason.Dtls
        }
        if (payloadLen >= 4 && looksLikeWireGuard(packet, payloadOff, payloadLen)) {
            return BlackholeReason.WireGuard
        }
        return BlackholeReason.GenericUdp
    }

    private fun looksLikeQuic(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 5) return false
        val b0 = packet[offset].toInt() and 0xff
        return (b0 and 0x80) != 0 || (b0 and 0x40) != 0
    }

    private fun looksLikeStun(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 20) return false
        if ((packet[offset].toInt() and 0xC0) != 0) return false
        return (packet[offset + 4].toInt() and 0xff) == STUN_MAGIC_0 &&
            (packet[offset + 5].toInt() and 0xff) == STUN_MAGIC_1 &&
            (packet[offset + 6].toInt() and 0xff) == STUN_MAGIC_2 &&
            (packet[offset + 7].toInt() and 0xff) == STUN_MAGIC_3
    }

    private fun looksLikeDtls(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 13) return false
        val contentType = packet[offset].toInt() and 0xff
        if (contentType !in 20..24) return false
        return (packet[offset + 1].toInt() and 0xff) == 0xfe
    }

    private fun looksLikeWireGuard(packet: ByteArray, offset: Int, len: Int): Boolean {
        if (len < 4) return false
        val type = packet[offset].toInt() and 0xff
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

    private fun isMulticastOrBroadcastV4(packet: ByteArray): Boolean {
        val dst = ipv4Int(packet, 16)
        return when (TorNetPolicy.classifyIpv4(dst)) {
            TorNetPolicy.IpClass.Multicast,
            TorNetPolicy.IpClass.Broadcast,
            -> true
            else -> false
        }
    }

    private fun isLinkLocalV4(packet: ByteArray): Boolean =
        TorNetPolicy.classifyIpv4(ipv4Int(packet, 16)) == TorNetPolicy.IpClass.LinkLocal

    private fun ipv4Int(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)

    /** ff00::/8 multicast or fe80::/10 link-local destination. */
    private fun isMulticastOrLinkLocalV6(packet: ByteArray): Boolean {
        if (packet.size < 40) return true
        val b0 = packet[24].toInt() and 0xff
        if (b0 == 0xff) return true // multicast
        if (b0 == 0xfe && (packet[25].toInt() and 0xc0) == 0x80) return true // link-local
        return false
    }

    /** IPv6 destination host string from a TUN packet (bytes 24..39). */
    private fun ipv6DestHost(packet: ByteArray): String? {
        if (packet.size < 40) return null
        return runCatching {
            java.net.InetAddress.getByAddress(packet.copyOfRange(24, 40))
                .hostAddress
                ?.substringBefore('%')
        }.getOrNull()
    }
}
