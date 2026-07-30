package ltechnologies.onionphone.onionvpn.firewall.engine

import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo

/**
 * Nested rule match graph: score by specificity (host > port > protocol), then newest wins.
 */
internal object FirewallRuleMatcher {
    fun find(
        rules: List<FirewallRule>,
        uid: Int,
        matchDest: String,
        info: IpPacketInfo,
    ): FirewallRule? = find(rules, uid, matchDest, info.dstPort, info.protocol)

    fun find(
        rules: List<FirewallRule>,
        uid: Int,
        matchDest: String,
        destPort: Int,
        protocol: Int,
    ): FirewallRule? {
        val now = System.currentTimeMillis()
        var best: FirewallRule? = null
        var bestScore = -1
        var bestCreated = Long.MIN_VALUE
        for (rule in rules) {
            if (rule.isExpired(now)) continue
            if (!rule.matches(uid, matchDest, destPort, protocol)) continue
            val score =
                (if (rule.destHost.isNotEmpty()) 4 else 0) +
                    (if (rule.destPort >= 0) 2 else 0) +
                    (if (rule.protocol >= 0) 1 else 0)
            if (score > bestScore ||
                (score == bestScore && rule.createdAtEpochMs > bestCreated)
            ) {
                best = rule
                bestScore = score
                bestCreated = rule.createdAtEpochMs
            }
        }
        return best
    }
}
