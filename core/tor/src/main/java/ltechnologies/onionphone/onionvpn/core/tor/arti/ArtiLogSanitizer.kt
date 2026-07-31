package ltechnologies.onionphone.onionvpn.core.tor.arti

/**
 * Arti's tracing writer delivers **raw Write chunks** (not lines) and often includes ANSI
 * color codes. Normalize to one plain-text line at a time for Tor log UI / classifiers.
 */
internal object ArtiLogSanitizer {
    private val ansiRegex = Regex("\u001B\\[[0-9;]*[A-Za-z]")

    fun stripAnsi(text: String): String = ansiRegex.replace(text, "")

    /** Trim CR and surrounding whitespace; empty after strip → discard. */
    fun normalizeLine(raw: String): String? {
        val line = stripAnsi(raw).trimEnd('\r').trim()
        return line.ifEmpty { null }
    }
}

/**
 * Accumulates JNI/log callback chunks and emits complete newline-delimited lines.
 * Thread-safe — Arti may invoke the callback from a native worker thread.
 */
internal class ArtiLogLineBuffer(
    private val onLine: (String) -> Unit,
) {
    private val lock = Any()
    private val pending = StringBuilder()

    fun accept(chunk: String) {
        if (chunk.isEmpty()) return
        val ready = synchronized(lock) {
            pending.append(chunk)
            drainLocked()
        }
        for (line in ready) onLine(line)
    }

    /** Flush a trailing partial line (e.g. on stop). */
    fun flush() {
        val line = synchronized(lock) {
            if (pending.isEmpty()) return
            val raw = pending.toString()
            pending.clear()
            ArtiLogSanitizer.normalizeLine(raw)
        } ?: return
        onLine(line)
    }

    private fun drainLocked(): List<String> {
        val out = ArrayList<String>(4)
        while (true) {
            val i = pending.indexOf("\n")
            if (i < 0) break
            val raw = pending.substring(0, i)
            pending.delete(0, i + 1)
            ArtiLogSanitizer.normalizeLine(raw)?.let { out.add(it) }
        }
        return out
    }
}
