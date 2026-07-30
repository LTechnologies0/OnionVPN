package ltechnologies.onionphone.onionvpn.firewall.engine

import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser

/**
 * Nested key graph for firewall caches (hot path — no String alloc on TUN flow keys).
 */
internal object FirewallCacheKeys {
    /** Golden-ratio mix (signed Long form of 0x9E3779B97F4A7C15). */
    private const val MIX = -7046029254386353131L
    private const val PACL = 0x5041434CL // "PACL"

    fun tupleFlowKey(info: IpPacketInfo): Long {
        var h = 0L
        h = h * MIX + (info.srcIpInt.toLong() and 0xffffffffL)
        h = h * MIX + (info.dstIpInt.toLong() and 0xffffffffL)
        h = h * MIX + info.srcPort
        h = h * MIX + info.dstPort
        h = h * MIX + info.protocol
        return h
    }

    fun flowKey(uid: Int, info: IpPacketInfo): Long {
        var h = uid.toLong()
        h = h * MIX + (info.srcIpInt.toLong() and 0xffffffffL)
        h = h * MIX + (info.dstIpInt.toLong() and 0xffffffffL)
        h = h * MIX + info.srcPort
        h = h * MIX + info.dstPort
        h = h * MIX + info.protocol
        return h
    }

    fun decisionKey(uid: Int, matchDest: String, info: IpPacketInfo): Long =
        socksDecisionKey(uid, matchDest, info.dstPort, info.protocol)

    fun socksFlowKey(uid: Int, matchDest: String, destPort: Int): Long {
        var h = uid.toLong()
        h = h * MIX + matchDest.lowercase().hashCode().toLong()
        h = h * MIX + destPort
        h = h * MIX + IpPacketParser.PROTO_TCP
        h = h * MIX + PACL // distinguish PAC from TUN flow keys
        return h
    }

    fun socksDecisionKey(uid: Int, matchDest: String, destPort: Int, protocol: Int): Long {
        var h = uid.toLong()
        h = h * MIX + matchDest.lowercase().hashCode().toLong()
        h = h * MIX + destPort
        h = h * MIX + protocol
        return h
    }

    fun ruleKey(uid: Int, matchDest: String, destPort: Int, protocol: Int): String =
        "$uid|$matchDest|$destPort|$protocol"
}
