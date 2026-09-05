package ltechnologies.onionphone.onionvpn.core.openvpn

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import timber.log.Timber

/**
 * 1:1 SNAT/DNAT between OnionVPN's VpnService address ([TunnelEndpoints.VPN_CLIENT_ADDRESS])
 * and the OpenVPN-assigned client IP from management `IFCONFIG`.
 *
 * Without this, ALLOW_OVPN dumps `10.8.0.2`-sourced packets into the peer net30
 * (often a different subnet), which the remote NAT rejects → apps see
 * `net::ERR_CONNECTION_RESET` while OVPN mgmt still reports CONNECTED + BYTECOUNT
 * (control keepalive only).
 *
 * Inbound frames are only injected when they match an outbound SNAT flow (conntrack).
 * Peer keepalives / stale RSTs must not land on the shared VpnService TUN and reset
 * Tor-path TCP.
 */
internal object OvpnIpNat {
    private val vpnClientIp = TunnelEndpoints.parseIpv4Literal(TunnelEndpoints.VPN_CLIENT_ADDRESS)
        ?: error("bad VPN_CLIENT_ADDRESS")

    /** OpenVPN client IPv4 from IFCONFIG (host order), 0 = unset. */
    private val ovpnClientIp = AtomicInteger(0)

    /** remoteIp:remotePort:localPort → lastSeenMs (TCP and UDP maps are separate). */
    private val tcpFlows = ConcurrentHashMap<Long, Long>(256)
    private val udpFlows = ConcurrentHashMap<Long, Long>(256)

    @Volatile
    var snatRewriteCount: Long = 0
        private set

    @Volatile
    var dnatRewriteCount: Long = 0
        private set

    /** Wall-clock of last successful SNAT (app→OpenVPN peer). */
    @Volatile
    var lastSnatWallMs: Long = 0
        private set

    /** Wall-clock of last successful DNAT (OpenVPN peer→app). */
    @Volatile
    var lastDnatWallMs: Long = 0
        private set

    fun clear() {
        ovpnClientIp.set(0)
        tcpFlows.clear()
        udpFlows.clear()
        snatRewriteCount = 0
        dnatRewriteCount = 0
        lastSnatWallMs = 0
        lastDnatWallMs = 0
    }

    /**
     * Some OpenVPN peers sometimes accepts outbound SYN then blackholes replies
     * while management still reports CONNECTED + BYTECOUNT (control keepalive).
     * True when recent SNAT demand has no matching DNAT within [silenceMs].
     */
    fun isDataPlaneSilent(
        nowMs: Long = System.currentTimeMillis(),
        silenceMs: Long = DATA_PLANE_SILENCE_MS,
    ): Boolean {
        val snatAt = lastSnatWallMs
        if (snatAt <= 0L) return false
        // No recent outbound demand → not a blackhole signal.
        if (nowMs - snatAt > silenceMs) return false
        val dnatAt = lastDnatWallMs
        return dnatAt <= 0L || snatAt - dnatAt >= silenceMs
    }

    /**
     * Parse IFCONFIG MSG body: `10.211.1.173 10.211.1.174 1280 net30` (client peer mtu topo).
     */
    fun setFromIfconfigMsg(extra: String) {
        val first = extra.trim().split(Regex("\\s+")).firstOrNull().orEmpty()
        val ip = TunnelEndpoints.parseIpv4Literal(first)
        if (ip == null) {
            Timber.w("OVPN IFCONFIG NAT skip — no IPv4 in %s", extra.take(64))
            return
        }
        ovpnClientIp.set(ip)
        tcpFlows.clear()
        udpFlows.clear()
        Timber.i(
            "OVPN IP NAT VpnService %s ↔ OpenVPN %s",
            TunnelEndpoints.VPN_CLIENT_ADDRESS,
            first,
        )
    }

    fun isReady(): Boolean = ovpnClientIp.get() != 0

    /**
     * Outbound VpnService → OpenVPN: rewrite IPv4 src to OpenVPN client IP.
     * @return false if packet must not be written (caller should demote / drop)
     */
    fun snatOutbound(packet: ByteArray, length: Int): Boolean {
        val ovpn = ovpnClientIp.get()
        if (ovpn == 0) return false
        if (length < 20) return false
        val version = (packet[0].toInt() ushr 4) and 0xf
        if (version != 4) return false
        val ihl = (packet[0].toInt() and 0xf) * 4
        if (length < ihl || ihl < 20) return false
        val src = readIpv4(packet, 12)
        if (src != ovpn) {
            writeIpv4(packet, 12, ovpn)
            fixIpv4HeaderChecksum(packet, ihl)
            recomputeTransportChecksum(packet, length, ihl)
        }
        rememberOutboundFlow(packet, length, ihl)
        snatRewriteCount++
        lastSnatWallMs = System.currentTimeMillis()
        return true
    }

    /**
     * Inbound OpenVPN → VpnService: rewrite IPv4 dst OpenVPN client → 10.8.0.2.
     * @return false to drop (no SNAT flow — avoid peer RST colliding with Tor TCP)
     */
    fun dnatInbound(packet: ByteArray, length: Int): Boolean {
        val ovpn = ovpnClientIp.get()
        if (ovpn == 0) return false
        if (length < 20) return false
        val version = (packet[0].toInt() ushr 4) and 0xf
        if (version != 4) return false
        val ihl = (packet[0].toInt() and 0xf) * 4
        if (length < ihl || ihl < 20) return false
        val dst = readIpv4(packet, 16)
        if (dst != ovpn) {
            // Not addressed to our OpenVPN client IP — never inject into VpnService.
            return false
        }
        if (!hasInboundFlow(packet, length, ihl)) {
            return false
        }
        writeIpv4(packet, 16, vpnClientIp)
        fixIpv4HeaderChecksum(packet, ihl)
        recomputeTransportChecksum(packet, length, ihl)
        dnatRewriteCount++
        lastDnatWallMs = System.currentTimeMillis()
        return true
    }

    private fun rememberOutboundFlow(packet: ByteArray, length: Int, ihl: Int) {
        val proto = packet[9].toInt() and 0xff
        val map = flowMap(proto) ?: return
        if (length < ihl + 4) return
        val remoteIp = readIpv4(packet, 16)
        val localPort = readPort(packet, ihl)
        val remotePort = readPort(packet, ihl + 2)
        map[flowKey(remoteIp, remotePort, localPort)] = System.currentTimeMillis()
        if (map.size > 2_000) trimFlows(map)
    }

    private fun hasInboundFlow(packet: ByteArray, length: Int, ihl: Int): Boolean {
        val proto = packet[9].toInt() and 0xff
        val map = flowMap(proto) ?: return false
        if (length < ihl + 4) return false
        val remoteIp = readIpv4(packet, 12)
        val remotePort = readPort(packet, ihl)
        val localPort = readPort(packet, ihl + 2)
        val key = flowKey(remoteIp, remotePort, localPort)
        val last = map[key] ?: return false
        map[key] = System.currentTimeMillis()
        return System.currentTimeMillis() - last < FLOW_TTL_MS
    }

    private fun flowMap(proto: Int): ConcurrentHashMap<Long, Long>? = when (proto) {
        6 -> tcpFlows
        17 -> udpFlows
        else -> null
    }

    private fun trimFlows(map: ConcurrentHashMap<Long, Long>) {
        val now = System.currentTimeMillis()
        val it = map.entries.iterator()
        while (it.hasNext()) {
            if (now - it.next().value > FLOW_TTL_MS) it.remove()
        }
    }

    /**
     * Pack remoteIp|remotePort|localPort only. Proto lives in separate maps —
     * XOR into IP bits collided (e.g. 10.0.0.5/TCP vs 10.23.0.5/UDP).
     */
    private fun flowKey(remoteIp: Int, remotePort: Int, localPort: Int): Long =
        ((remoteIp.toLong() and 0xffffffffL) shl 32) or
            (((remotePort and 0xffff).toLong()) shl 16) or
            ((localPort and 0xffff).toLong())

    private fun readPort(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

    /** Full TCP/UDP checksum recompute (pseudo-header includes rewritten addresses). */
    private fun recomputeTransportChecksum(packet: ByteArray, length: Int, ihl: Int) {
        val proto = packet[9].toInt() and 0xff
        val payloadLen = length - ihl
        when (proto) {
            6 -> {
                if (payloadLen < 20) return
                packet[ihl + 16] = 0
                packet[ihl + 17] = 0
                val sum = transportChecksum(packet, ihl, payloadLen, proto)
                packet[ihl + 16] = (sum ushr 8).toByte()
                packet[ihl + 17] = (sum and 0xff).toByte()
            }
            17 -> {
                if (payloadLen < 8) return
                val old = ((packet[ihl + 6].toInt() and 0xff) shl 8) or
                    (packet[ihl + 7].toInt() and 0xff)
                if (old == 0) return
                packet[ihl + 6] = 0
                packet[ihl + 7] = 0
                var sum = transportChecksum(packet, ihl, payloadLen, proto)
                if (sum == 0) sum = 0xffff
                packet[ihl + 6] = (sum ushr 8).toByte()
                packet[ihl + 7] = (sum and 0xff).toByte()
            }
            else -> Unit
        }
    }

    private fun transportChecksum(
        packet: ByteArray,
        ihl: Int,
        payloadLen: Int,
        proto: Int,
    ): Int {
        var sum = 0L
        sum += ((packet[12].toInt() and 0xff) shl 8) or (packet[13].toInt() and 0xff)
        sum += ((packet[14].toInt() and 0xff) shl 8) or (packet[15].toInt() and 0xff)
        sum += ((packet[16].toInt() and 0xff) shl 8) or (packet[17].toInt() and 0xff)
        sum += ((packet[18].toInt() and 0xff) shl 8) or (packet[19].toInt() and 0xff)
        sum += proto and 0xff
        sum += payloadLen
        var i = ihl
        val end = ihl + payloadLen
        while (i + 1 < end) {
            sum += ((packet[i].toInt() and 0xff) shl 8) or (packet[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (packet[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xffff) + (sum ushr 16)
        }
        return sum.inv().toInt() and 0xffff
    }

    private fun fixIpv4HeaderChecksum(packet: ByteArray, ihl: Int) {
        packet[10] = 0
        packet[11] = 0
        val sum = onesComplement(packet, 0, ihl)
        packet[10] = (sum ushr 8).toByte()
        packet[11] = (sum and 0xff).toByte()
    }

    private fun onesComplement(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xffff) + (sum ushr 16)
        }
        return sum.inv().toInt() and 0xffff
    }

    private fun readIpv4(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 24) or
            ((packet[offset + 1].toInt() and 0xff) shl 16) or
            ((packet[offset + 2].toInt() and 0xff) shl 8) or
            (packet[offset + 3].toInt() and 0xff)

    private fun writeIpv4(packet: ByteArray, offset: Int, ip: Int) {
        packet[offset] = (ip ushr 24).toByte()
        packet[offset + 1] = (ip ushr 16).toByte()
        packet[offset + 2] = (ip ushr 8).toByte()
        packet[offset + 3] = ip.toByte()
    }

    private const val FLOW_TTL_MS = 120_000L
    const val DATA_PLANE_SILENCE_MS = 20_000L
}
