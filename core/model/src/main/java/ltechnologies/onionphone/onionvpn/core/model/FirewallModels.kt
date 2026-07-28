package ltechnologies.onionphone.onionvpn.core.model

enum class FirewallVerdict {
    ALLOW,
    DENY,
}

enum class FirewallRuleScope {
    /** Permanent until user deletes. */
    PERMANENT,
    /** Until VPN session ends. */
    SESSION,
    /** Until [FirewallRule.expiresAtEpochMs]. */
    TEMPORARY,
}

/**
 * Least-privilege default when interactive firewall is on and no rule matches.
 * ASK prompts the user; timeout falls back to DENY.
 */
enum class FirewallDefaultAction {
    ASK,
    DENY,
    ALLOW,
}

data class FirewallRule(
    val id: String,
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    /** Empty = any destination host/IP. */
    val destHost: String = "",
    /** -1 = any port. */
    val destPort: Int = -1,
    /** -1 = any protocol (TCP/UDP). Otherwise IPPROTO_TCP=6 / IPPROTO_UDP=17. */
    val protocol: Int = -1,
    val verdict: FirewallVerdict,
    val scope: FirewallRuleScope,
    val expiresAtEpochMs: Long? = null,
    val createdAtEpochMs: Long = System.currentTimeMillis(),
) {
    fun isExpired(nowMs: Long = System.currentTimeMillis()): Boolean {
        if (scope == FirewallRuleScope.TEMPORARY) {
            val until = expiresAtEpochMs ?: return true
            return nowMs >= until
        }
        return false
    }

    fun matches(
        uid: Int,
        destHost: String,
        destPort: Int,
        protocol: Int,
    ): Boolean {
        if (this.uid != uid) return false
        if (this.protocol >= 0 && this.protocol != protocol) return false
        if (this.destPort >= 0 && this.destPort != destPort) return false
        if (this.destHost.isNotEmpty() &&
            !this.destHost.equals(destHost, ignoreCase = true)
        ) {
            return false
        }
        return true
    }
}

data class FirewallConnectionInfo(
    val requestId: String,
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val destIp: String,
    val destPort: Int,
    val protocol: Int,
    val protocolLabel: String,
    val timestampEpochMs: Long = System.currentTimeMillis(),
)

data class FirewallJournalEntry(
    val id: String,
    val timestampEpochMs: Long,
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val destIp: String,
    val destPort: Int,
    val protocolLabel: String,
    val verdict: FirewallVerdict,
    val scope: FirewallRuleScope,
    val note: String = "",
)

data class TunnelPreferences(
    val routeAllTrafficThroughTor: Boolean = true,
    val killSwitchEnabled: Boolean = true,
    val dnsCryptServerName: String = "cloudflare",
    val dnsResolverMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    val torBridges: String = "",
    val torEntryNodes: String = "",
    val torExitNodes: String = "",
    val torExcludeNodes: String = "",
    val torNewCircuitPeriodSec: Int = 30,
    val torMaxCircuitDirtinessSec: Int = 180,
    val dnsCryptRequireNoLog: Boolean = true,
    val dnsCryptRequireNoFilter: Boolean = false,
    val dnsCryptForceTcp: Boolean = true,
    /** Interactive OpenSnitch-style firewall on the TUN path. */
    val firewallEnabled: Boolean = false,
    val firewallDefaultAction: FirewallDefaultAction = FirewallDefaultAction.ASK,
    /** Temporary allow/deny TTL in minutes. */
    val firewallTempMinutes: Int = 5,
    /** Prompt timeout before default DENY (seconds). */
    val firewallPromptTimeoutSec: Int = 15,
)
