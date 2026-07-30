package ltechnologies.onionphone.onionvpn.core.model.stability

/**
 * Unified classifier for Tor control events, SOCKS replies, DNSCrypt logs, and OS errno.
 */
object StabilityClassifier {

    fun forStreamReason(reason: String?): StabilitySignal =
        TorStabilityCodes.StreamEnd.signalFor(reason)

    fun forCircReason(reason: String?): StabilitySignal =
        TorStabilityCodes.CircReason.signalFor(reason)

    fun forOrConnReason(reason: String?): StabilitySignal =
        TorStabilityCodes.OrConnReason.signalFor(reason)

    fun forSocksStatus(code: Int): StabilitySignal =
        TorStabilityCodes.SocksReply.signalFor(code)

    fun forDnsCryptLog(line: String): StabilitySignal =
        DnsCryptStabilityCodes.signalForLogLine(line)

    fun forErrno(errno: Int?): StabilitySignal? =
        AndroidStabilityCodes.signalForErrno(errno)

    fun forTorLogLine(line: String): StabilitySignal {
        val lower = line.lowercase()
        return when {
            "[err]" in lower || "[error]" in lower ->
                StabilitySignal("TOR_ERR", StabilitySeverity.ERROR, StabilityAction.SOFT_RECOVER)
            "problem bootstrapping" in lower || "bootstrapped 0%" in lower ->
                StabilitySignal("TOR_BOOTSTRAP", StabilitySeverity.ERROR, StabilityAction.SOFT_RECOVER)
            "[warn]" in lower && (
                "failed" in lower || "error" in lower || "reject" in lower ||
                    "timeout" in lower || "noroute" in lower
                ) ->
                StabilitySignal("TOR_WARN", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER)
            "[warn]" in lower ->
                StabilitySignal("TOR_WARN", StabilitySeverity.WARN)
            else ->
                StabilitySignal("TOR", StabilitySeverity.IGNORE)
        }
    }

    fun forAppLogLine(line: String): StabilitySignal {
        val lower = line.lowercase()
        return when {
            "hard fail" in lower || "periodic hard fail" in lower ->
                StabilitySignal("APP_HARD", StabilitySeverity.ERROR, StabilityAction.PREFER_BLOCKING)
            "soft fail" in lower || "request fail" in lower || "periodic soft fail" in lower ->
                StabilitySignal("APP_SOFT", StabilitySeverity.WARN)
            " fatal" in lower || " crash" in lower || lower.endsWith("crash") ->
                StabilitySignal("APP_CRASH", StabilitySeverity.CRITICAL, StabilityAction.PREFER_BLOCKING)
            "exception" in lower ->
                StabilitySignal("APP_EX", StabilitySeverity.ERROR)
            else ->
                StabilitySignal("APP", StabilitySeverity.IGNORE)
        }
    }

    /**
     * Highest-priority action among signals (STOP_TOR > PREFER_BLOCKING > HARD > SOFT > NONE).
     */
    fun mergeAction(vararg signals: StabilitySignal): StabilityAction {
        var best = StabilityAction.NONE
        for (s in signals) {
            best = maxAction(best, s.action)
        }
        return best
    }

    private fun maxAction(a: StabilityAction, b: StabilityAction): StabilityAction {
        fun rank(x: StabilityAction) = when (x) {
            StabilityAction.NONE -> 0
            StabilityAction.SOFT_RECOVER -> 1
            StabilityAction.HARD_RECOVER -> 2
            StabilityAction.PREFER_BLOCKING -> 3
            StabilityAction.STOP_TOR -> 4
        }
        return if (rank(b) > rank(a)) b else a
    }
}
