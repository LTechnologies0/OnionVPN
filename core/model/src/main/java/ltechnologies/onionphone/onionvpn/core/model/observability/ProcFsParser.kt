package ltechnologies.onionphone.onionvpn.core.model.observability

/**
 * Pure parsers for `/proc` status / stat used by [NativeResourceProfiler] (app layer)
 * and unit tests.
 */
object ProcFsParser {
    data class StatusMetrics(
        val vmRssKb: Long = 0L,
        val vmSizeKb: Long = 0L,
        val threads: Int = 0,
    )

    data class StatCpu(
        val utimeTicks: Long,
        val stimeTicks: Long,
    ) {
        val totalTicks: Long get() = utimeTicks + stimeTicks
    }

    fun parseStatus(text: String): StatusMetrics {
        var rss = 0L
        var size = 0L
        var threads = 0
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            when {
                line.startsWith("VmRSS:") -> rss = parseKb(line)
                line.startsWith("VmSize:") -> size = parseKb(line)
                line.startsWith("Threads:") -> threads = parseInt(line)
            }
        }
        return StatusMetrics(vmRssKb = rss, vmSizeKb = size, threads = threads)
    }

    /**
     * `/proc/self/stat` fields 14–15 (utime, stime) — 1-based field index after comm.
     * Format: `pid (comm) state ppid … utime stime …`
     */
    fun parseStatCpu(text: String): StatCpu? {
        val close = text.lastIndexOf(')')
        if (close < 0 || close + 2 >= text.length) return null
        val rest = text.substring(close + 2).trim().split(Regex("\\s+"))
        // After ") ": state is [0], … utime is index 11, stime is 12 (0-based in rest).
        if (rest.size < 13) return null
        val utime = rest[11].toLongOrNull() ?: return null
        val stime = rest[12].toLongOrNull() ?: return null
        return StatCpu(utime, stime)
    }

    private fun parseKb(line: String): Long {
        val parts = line.split(Regex("\\s+"))
        return parts.getOrNull(1)?.toLongOrNull() ?: 0L
    }

    private fun parseInt(line: String): Int {
        val parts = line.split(Regex("\\s+"))
        return parts.getOrNull(1)?.toIntOrNull() ?: 0
    }
}
