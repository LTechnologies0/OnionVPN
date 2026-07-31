package ltechnologies.onionphone.onionvpn.core.model.stability

/**
 * Canonical process-log levels shared by C Tor (`[warn]`), Arti tracing (` WARN `),
 * DNSCrypt (`[WARNING]`), and Android/Timber priorities.
 *
 * Maps onto [StabilitySeverity] so UI coloring, export marks, and recovery policy
 * stay aligned.
 */
enum class ProcessLogLevel(
    val severity: StabilitySeverity,
    /** Single-char mark for log export (` T `/` D `/` I `/` W `/` E `/` C `). */
    val exportMark: Char,
) {
    TRACE(StabilitySeverity.TRACE, 'T'),
    DEBUG(StabilitySeverity.DEBUG, 'D'),
    INFO(StabilitySeverity.INFO, 'I'),
    WARN(StabilitySeverity.WARN, 'W'),
    ERROR(StabilitySeverity.ERROR, 'E'),
    CRITICAL(StabilitySeverity.CRITICAL, 'C'),
    ;

    val isError: Boolean
        get() = severity.isError

    val isWarnOrWorse: Boolean
        get() = severity >= StabilitySeverity.WARN

    companion object {
        /**
         * Extract an explicit level token from a log line.
         * Prefers bracket tags (`[warn]`, `[ERROR]`) then Arti/tracing word tokens
         * near the start of the line (after an optional timestamp).
         */
        fun parse(line: String): ProcessLogLevel? {
            if (line.isBlank()) return null
            bracketLevel(line)?.let { return it }
            return wordLevel(line)
        }

        fun fromAndroidPriority(priority: Int): ProcessLogLevel = when {
            // android.util.Log: VERBOSE=2 DEBUG=3 INFO=4 WARN=5 ERROR=6 ASSERT=7
            priority >= 7 -> CRITICAL
            priority >= 6 -> ERROR
            priority >= 5 -> WARN
            priority >= 4 -> INFO
            priority >= 3 -> DEBUG
            else -> TRACE
        }

        fun fromSeverity(severity: StabilitySeverity): ProcessLogLevel = when (severity) {
            StabilitySeverity.IGNORE, StabilitySeverity.TRACE -> TRACE
            StabilitySeverity.DEBUG -> DEBUG
            StabilitySeverity.INFO -> INFO
            StabilitySeverity.WARN -> WARN
            StabilitySeverity.ERROR -> ERROR
            StabilitySeverity.CRITICAL -> CRITICAL
        }

        private fun bracketLevel(line: String): ProcessLogLevel? {
            // Scan bracket tags; pick the highest severity if several appear
            // (e.g. DNSCrypt "[ERROR] …" with incidental text).
            var best: ProcessLogLevel? = null
            val upper = line.uppercase()
            val tags = listOf(
                "[FATAL]" to CRITICAL,
                "[CRITICAL]" to CRITICAL,
                "[ERROR]" to ERROR,
                "[ERR]" to ERROR,
                "[WARNING]" to WARN,
                "[WARN]" to WARN,
                "[NOTICE]" to INFO,
                "[INFO]" to INFO,
                "[DEBUG]" to DEBUG,
                "[TRACE]" to TRACE,
                "[VERBOSE]" to TRACE,
            )
            for ((tag, level) in tags) {
                if (tag in upper) {
                    best = max(best, level)
                }
            }
            return best
        }

        /**
         * Arti / tracing_subscriber fmt (no ANSI):
         * `2026-07-31T15:33:28.732Z  INFO target: message`
         * Also matches lone `WARN message` at line start.
         */
        private fun wordLevel(line: String): ProcessLogLevel? {
            // Prefer token in the first ~96 chars so "… error: …" in the body does not win.
            val head = if (line.length > 96) line.substring(0, 96) else line
            val match = WORD_LEVEL.find(head) ?: return null
            return when (match.groupValues[1].uppercase()) {
                "TRACE", "VERBOSE" -> TRACE
                "DEBUG" -> DEBUG
                "INFO", "NOTICE" -> INFO
                "WARN", "WARNING" -> WARN
                "ERROR", "ERR" -> ERROR
                "CRITICAL", "FATAL" -> CRITICAL
                else -> null
            }
        }

        private fun max(a: ProcessLogLevel?, b: ProcessLogLevel): ProcessLogLevel =
            if (a == null || b.severity > a.severity) b else a

        // Word token: start or whitespace, level name, then whitespace (Arti) or end.
        private val WORD_LEVEL = Regex(
            """(?:^|\s)(TRACE|VERBOSE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|FATAL)(?:\s|$)""",
            RegexOption.IGNORE_CASE,
        )
    }
}
