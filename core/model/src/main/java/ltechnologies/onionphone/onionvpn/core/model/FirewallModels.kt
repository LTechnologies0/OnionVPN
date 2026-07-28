package ltechnologies.onionphone.onionvpn.core.model

/**
 * Package `model` — shared immutable tunnel / firewall / validation types.
 *
 * Imported by every `core:*` module and the app. No I/O.
 */

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
 * ASK queues a prompt until the user answers (no timeout).
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
    /**
     * Match key: destination IP (packet path) or empty = any destination.
     * Hostname is stored separately in [displayHost] for UI only.
     */
    val destHost: String = "",
    /** -1 = any port. */
    val destPort: Int = -1,
    /** -1 = any protocol (TCP/UDP). Otherwise IPPROTO_TCP=6 / IPPROTO_UDP=17. */
    val protocol: Int = -1,
    val verdict: FirewallVerdict,
    val scope: FirewallRuleScope,
    val expiresAtEpochMs: Long? = null,
    val createdAtEpochMs: Long = System.currentTimeMillis(),
    /** DNS hostname at decision time (display only; matching uses [destHost]/IP). */
    val displayHost: String = "",
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

/**
 * Reputation of a destination hostname from local blocklist databases.
 *
 * - [TRACKING]: ads / tracking / telemetry → orange in the UI
 * - [MALWARE]: malware / C2 / phishing → red in the UI
 * - [NONE]: unknown or not listed
 */
enum class DomainThreatCategory {
    NONE,
    TRACKING,
    MALWARE,
}

data class FirewallConnectionInfo(
    val requestId: String,
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val destIp: String,
    val destPort: Int,
    val protocol: Int,
    /**
     * Transport or DPI application label shown in UI
     * (TCP/UDP, or DNS/HTTP/HTTPS/TLS/DoT/QUIC when classified).
     */
    val protocolLabel: String,
    /** Resolved hostname from DNS snooping, when available. */
    val destHost: String? = null,
    val threatCategory: DomainThreatCategory = DomainThreatCategory.NONE,
    /**
     * Optional DPI detail for notifications (DNS QNAME, HTTP Host, TLS SNI, …).
     */
    val dpiDetail: String? = null,
    val timestampEpochMs: Long = System.currentTimeMillis(),
) {
    /** Prefer hostname for display; fall back to IP. */
    fun displayDestination(): String = destHost?.takeIf { it.isNotBlank() } ?: destIp
}

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
    val destHost: String? = null,
    val threatCategory: DomainThreatCategory = DomainThreatCategory.NONE,
) {
    /** Prefer hostname for display; fall back to IP. */
    fun displayDestination(): String = destHost?.takeIf { it.isNotBlank() } ?: destIp
}
