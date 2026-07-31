package ltechnologies.onionphone.onionvpn.logging

import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityClassifier
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySignal
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySeverity

/**
 * Classifies Tor / DNSCrypt / app log lines into TRACE→CRITICAL for UI + recovery.
 * Delegates to [StabilityClassifier] / [ProcessLogLevel].
 */
object ProcessLogSeverity {
    fun classify(source: LogSource, line: String): StabilitySignal = when (source) {
        LogSource.TOR -> StabilityClassifier.forTorLogLine(line)
        LogSource.DNSCRYPT -> StabilityClassifier.forDnsCryptLog(line)
        LogSource.APP -> StabilityClassifier.forAppLogLine(line)
    }

    fun classifyApp(priority: Int, line: String): StabilitySignal =
        StabilityClassifier.forAppPriority(priority, line)

    fun level(source: LogSource, line: String): ProcessLogLevel =
        ProcessLogLevel.fromSeverity(classify(source, line).severity)

    fun isError(source: LogSource, line: String): Boolean =
        classify(source, line).isError

    fun isWarnOrWorse(source: LogSource, line: String): Boolean =
        classify(source, line).severity >= StabilitySeverity.WARN
}
