package ltechnologies.onionphone.onionvpn.logging

/**
 * Classifies Tor / DNSCrypt / app log lines so failed requests surface as errors in the UI.
 */
object ProcessLogSeverity {
    fun isError(source: LogSource, line: String): Boolean {
        val lower = line.lowercase()
        return when (source) {
            LogSource.TOR -> {
                lower.contains("[err]") ||
                    lower.contains("[error]") ||
                    lower.contains(" bootstrapped 0%") ||
                    lower.contains("connection refused") ||
                    lower.contains("failed to") ||
                    lower.contains("problem bootstrapping") ||
                    (lower.contains("[warn]") && (
                        lower.contains("failed") ||
                            lower.contains("error") ||
                            lower.contains("reject") ||
                            lower.contains("timeout")
                        ))
            }
            LogSource.DNSCRYPT -> {
                lower.contains("[critical]") ||
                    lower.contains("[error]") ||
                    lower.contains("error:") ||
                    lower.contains("failed") ||
                    lower.contains("timeout") ||
                    lower.contains("refused") ||
                    lower.contains("no servers") ||
                    lower.contains("network error")
            }
            LogSource.APP -> {
                lower.contains("fail") ||
                    lower.contains("error") ||
                    lower.contains("timeout") ||
                    lower.contains("unreachable") ||
                    lower.contains("crash")
            }
        }
    }
}
