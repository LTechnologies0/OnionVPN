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

    /**
     * True for a control-spec terminal reply line (`250 ` / `251 ` / `4xx ` / `5xx `).
     *
     * Must not match GETINFO data-body lines such as `517 EXTENDED …` (circuit id 517) —
     * those are only safe when the transport ignores terminals inside a `250+` … `.` block.
     */
    fun isTerminalReplyLine(line: String): Boolean {
        if (line.startsWith("250 ") || line.startsWith("251 ")) return true
        return isErrorReplyLine(line)
    }

    /** True for a 3-digit `4xx`/`5xx` status line (space after the code). */
    fun isErrorReplyLine(line: String): Boolean {
        if (line.length < 4 || line[3] != ' ') return false
        val c0 = line[0]
        if (c0 != '4' && c0 != '5') return false
        return line[1].isDigit() && line[2].isDigit()
    }

    /** Start of a `250+key=` multi-line value block. */
    fun isMultilineDataStart(line: String): Boolean =
        line.length >= 4 &&
            line[0] == '2' &&
            line[1] == '5' &&
            line[2] == '0' &&
            line[3] == '+'
}
