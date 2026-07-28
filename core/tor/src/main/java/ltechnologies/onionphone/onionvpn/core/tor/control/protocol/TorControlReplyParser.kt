package ltechnologies.onionphone.onionvpn.core.tor.control.protocol

/**
 * Package `control.protocol` — pure parsers for control replies and 650 events (zero I/O).
 *
 * Imported by: TorControlTransport consumers, TorControlOperations, TorControlClient, unit tests.
 */

/**
 * Extracts GETINFO / GETCONF values from a completed control reply line list.
 *
 * Handles single-line `250-key=value` and multi-line `250+key=` … `.` blocks.
 */
internal object TorControlReplyParser {
    /**
     * @param replyLines full reply including terminal `250 OK` / error
     * @param key GETINFO key (e.g. `circuit-status`)
     */
    fun multilineValue(replyLines: List<String>, key: String): String {
        val prefix = "250-$key="
        val midPrefix = "250+$key="
        replyLines.firstOrNull { it.startsWith(prefix) }?.let {
            return it.removePrefix(prefix)
        }
        val start = replyLines.indexOfFirst { it.startsWith(midPrefix) }
        if (start < 0) {
            return replyLines.firstOrNull { it.contains("$key=") }
                ?.substringAfter("$key=")
                .orEmpty()
        }
        val out = StringBuilder()
        for (i in start + 1 until replyLines.size) {
            val line = replyLines[i]
            if (line == "." || line.startsWith("250 ")) break
            out.appendLine(line)
        }
        return out.toString().trimEnd()
    }
}
