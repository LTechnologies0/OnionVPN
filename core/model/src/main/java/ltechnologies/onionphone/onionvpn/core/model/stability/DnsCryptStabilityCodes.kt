package ltechnologies.onionphone.onionvpn.core.model.stability

/**
 * DNSCrypt-proxy log / failure patterns relevant to OnionVPN stability
 * (upstream via Tor SOCKS, stub listen, certificate / server pool).
 *
 * Protocol security context: draft-denis-dprive-dnscrypt (confidentiality,
 * integrity, short-term keys) — we only classify operational failures here.
 */
object DnsCryptStabilityCodes {

    enum class LogLevel(
        val tag: String,
        val severity: StabilitySeverity,
    ) {
        DEBUG("DEBUG", StabilitySeverity.IGNORE),
        INFO("INFO", StabilitySeverity.INFO),
        NOTICE("NOTICE", StabilitySeverity.INFO),
        WARNING("WARNING", StabilitySeverity.WARN),
        WARN("WARN", StabilitySeverity.WARN),
        ERROR("ERROR", StabilitySeverity.ERROR),
        CRITICAL("CRITICAL", StabilitySeverity.CRITICAL),
        FATAL("FATAL", StabilitySeverity.CRITICAL),
        ;

        companion object {
            fun fromLine(line: String): LogLevel? {
                val upper = line.uppercase()
                return entries.firstOrNull { upper.contains("[${it.tag}]") }
            }
        }
    }

    /**
     * Message fragments that mean the resolver path is broken (vs transient probe noise).
     */
    private val ERROR_FRAGMENTS = listOf(
        "no servers" to StabilityAction.SOFT_RECOVER,
        "network error" to StabilityAction.SOFT_RECOVER,
        "connection refused" to StabilityAction.SOFT_RECOVER,
        "certificate" to StabilityAction.NONE,
        "invalid stamp" to StabilityAction.NONE,
        "failed to bind" to StabilityAction.PREFER_BLOCKING,
        "address already in use" to StabilityAction.PREFER_BLOCKING,
        "permission denied" to StabilityAction.PREFER_BLOCKING,
        "proxy error" to StabilityAction.SOFT_RECOVER,
        "socks" to StabilityAction.SOFT_RECOVER,
        "upstream" to StabilityAction.SOFT_RECOVER,
    )

    /** Transient probe noise — do not mark UI error when only these appear at DEBUG. */
    private val NOISE_FRAGMENTS = listOf(
        "probe ",
        "timeout waiting",
        "temporarily",
        "try again",
    )

    fun signalForLogLine(line: String): StabilitySignal {
        val level = LogLevel.fromLine(line)
        val lower = line.lowercase()
        if (level == null || level.severity <= StabilitySeverity.INFO) {
            // Keyword escalation only for unlabeled / notice lines with hard failures.
            if (level == null) {
                for ((frag, action) in ERROR_FRAGMENTS) {
                    if (frag in lower && NOISE_FRAGMENTS.none { it in lower }) {
                        return StabilitySignal("DNSCRYPT", StabilitySeverity.ERROR, action, frag)
                    }
                }
            }
            return StabilitySignal(
                level?.tag ?: "DNSCRYPT",
                level?.severity ?: StabilitySeverity.IGNORE,
            )
        }
        if (level.severity == StabilitySeverity.WARN) {
            val action = ERROR_FRAGMENTS.firstOrNull { it.first in lower }?.second
                ?: StabilityAction.NONE
            return StabilitySignal(level.tag, StabilitySeverity.WARN, action)
        }
        val action = when {
            "bind" in lower || "listen" in lower -> StabilityAction.PREFER_BLOCKING
            "no servers" in lower || "socks" in lower || "proxy" in lower ->
                StabilityAction.SOFT_RECOVER
            else -> StabilityAction.NONE
        }
        return StabilitySignal(level.tag, level.severity, action, line.take(160))
    }

    /** True when a log line should surface as an error in the Logs UI. */
    fun isErrorLine(line: String): Boolean {
        val signal = signalForLogLine(line)
        if (signal.severity >= StabilitySeverity.ERROR) return true
        val lower = line.lowercase()
        if (NOISE_FRAGMENTS.any { it in lower }) return false
        return ERROR_FRAGMENTS.any { it.first in lower } &&
            (lower.contains("[error]") || lower.contains("[critical]") || lower.contains("error:"))
    }
}
