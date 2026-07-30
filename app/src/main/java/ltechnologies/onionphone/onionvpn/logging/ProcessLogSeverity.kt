package ltechnologies.onionphone.onionvpn.logging

import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityClassifier
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySeverity

/**
 * Classifies Tor / DNSCrypt / app log lines so failed requests surface as errors in the UI.
 * Delegates to [StabilityClassifier] (Tor / DNSCrypt / Android wire catalogs).
 */
object ProcessLogSeverity {
    fun isError(source: LogSource, line: String): Boolean {
        val signal = when (source) {
            LogSource.TOR -> StabilityClassifier.forTorLogLine(line)
            LogSource.DNSCRYPT -> StabilityClassifier.forDnsCryptLog(line)
            LogSource.APP -> StabilityClassifier.forAppLogLine(line)
        }
        return signal.severity == StabilitySeverity.ERROR ||
            signal.severity == StabilitySeverity.CRITICAL
    }
}
