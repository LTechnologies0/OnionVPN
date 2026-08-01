package ltechnologies.onionphone.onionvpn.core.model.stability

/**
 * Unified classifier for Tor control events, SOCKS replies, DNSCrypt logs, OS errno,
 * and process log lines (C Tor / Arti / app).
 *
 * Log lines: parse explicit [ProcessLogLevel] first, then escalate [StabilityAction]
 * from known failure fragments without inventing a higher level than the line declares
 * (except unlabeled lines, which may keyword-escalate to ERROR).
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
        val level = ProcessLogLevel.parse(line)

        // Content-based escalations that always matter for tunnel health.
        when {
            "problem bootstrapping" in lower || "bootstrapped 0%" in lower ->
                return StabilitySignal(
                    "TOR_BOOTSTRAP",
                    StabilitySeverity.ERROR,
                    StabilityAction.SOFT_RECOVER,
                    detail = level?.name ?: "",
                )
            "wrong state" in lower ->
                return StabilitySignal(
                    "TOR_STATE",
                    StabilitySeverity.ERROR,
                    StabilityAction.SOFT_RECOVER,
                    detail = level?.name ?: "",
                )
        }

        if (level != null) {
            val action = torActionFor(level, lower)
            return StabilitySignal(
                code = "TOR_${level.name}",
                severity = level.severity,
                action = action,
                detail = level.name,
            )
        }

        // Unlabeled little-t / control noise — keyword only.
        return when {
            "failed" in lower || "error" in lower || "reject" in lower ||
                "timeout" in lower || "noroute" in lower ->
                StabilitySignal("TOR_WARN", StabilitySeverity.WARN, StabilityAction.SOFT_RECOVER)
            else ->
                StabilitySignal("TOR", StabilitySeverity.DEBUG)
        }
    }

    fun forAppLogLine(line: String): StabilitySignal {
        val lower = line.lowercase()
        val level = ProcessLogLevel.parse(line)
        return when {
            "hard fail" in lower || "periodic hard fail" in lower ->
                StabilitySignal("APP_HARD", StabilitySeverity.ERROR, StabilityAction.PREFER_BLOCKING)
            "soft fail" in lower || "request fail" in lower || "periodic soft fail" in lower ->
                StabilitySignal("APP_SOFT", StabilitySeverity.WARN)
            " fatal" in lower || " crash" in lower || lower.endsWith("crash") ->
                StabilitySignal("APP_CRASH", StabilitySeverity.CRITICAL, StabilityAction.PREFER_BLOCKING)
            "exception" in lower || "tunnel failure" in lower ->
                StabilitySignal("APP_EX", StabilitySeverity.ERROR)
            level != null ->
                StabilitySignal("APP_${level.name}", level.severity, detail = level.name)
            else ->
                StabilitySignal("APP", StabilitySeverity.INFO)
        }
    }

    /**
     * Classify from an Android/Timber priority plus message (OnionVPN app tab).
     */
    fun forAppPriority(priority: Int, line: String): StabilitySignal {
        val fromPriority = ProcessLogLevel.fromAndroidPriority(priority)
        // DEBUG/VERBOSE: trust Timber. Throwable dumps include "IOException" /
        // "InterruptedException" and would keyword-escalate every PAC/SOCKS abort to ERROR.
        if (fromPriority.severity <= StabilitySeverity.DEBUG) {
            return StabilitySignal(
                code = "APP_${fromPriority.name}",
                severity = fromPriority.severity,
                action = StabilityAction.NONE,
                detail = fromPriority.name,
            )
        }
        val fromText = forAppLogLine(line)
        // Take the worse of Timber priority vs keyword/level in the message.
        return if (fromText.severity > fromPriority.severity) {
            fromText
        } else {
            StabilitySignal(
                code = "APP_${fromPriority.name}",
                severity = fromPriority.severity,
                action = fromText.action,
                detail = fromPriority.name,
            )
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

    private fun torActionFor(level: ProcessLogLevel, lower: String): StabilityAction {
        if (level.severity < StabilitySeverity.WARN) return StabilityAction.NONE
        val soft = "failed" in lower || "error" in lower || "reject" in lower ||
            "timeout" in lower || "noroute" in lower ||
            "couldn't reload" in lower || "invalid configuration" in lower ||
            "connection timed out" in lower
        return when {
            level.severity >= StabilitySeverity.ERROR -> StabilityAction.SOFT_RECOVER
            soft -> StabilityAction.SOFT_RECOVER
            else -> StabilityAction.NONE
        }
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
