package ltechnologies.onionphone.onionvpn.logging

import android.os.Handler
import android.os.Looper
import java.util.ArrayDeque
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilitySeverity

enum class LogSource {
    APP,
    DNSCRYPT,
    TOR,
}

data class LogLine(
    val timestampMs: Long,
    val text: String,
    val severity: StabilitySeverity = StabilitySeverity.INFO,
) {
    val isError: Boolean
        get() = severity.isError

    val isWarnOrWorse: Boolean
        get() = severity >= StabilitySeverity.WARN

    val level: ProcessLogLevel
        get() = ProcessLogLevel.fromSeverity(severity)
}

/**
 * Thread-safe ring buffers for tunnel UI logs (app / DNSCrypt / Tor).
 */
object TunnelLogBuffer {
    private const val CAPACITY = 2_000
    private const val MAX_LINE_CHARS = 2_000
    private const val PUBLISH_DEBOUNCE_MS = 200L

    private val appDeque = ArrayDeque<LogLine>(CAPACITY)
    private val dnsDeque = ArrayDeque<LogLine>(CAPACITY)
    private val torDeque = ArrayDeque<LogLine>(CAPACITY)
    private val lock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var publishPending = false

    private val _app = MutableStateFlow<List<LogLine>>(emptyList())
    private val _dnscrypt = MutableStateFlow<List<LogLine>>(emptyList())
    private val _tor = MutableStateFlow<List<LogLine>>(emptyList())

    val appLogs: StateFlow<List<LogLine>> = _app.asStateFlow()
    val dnsCryptLogs: StateFlow<List<LogLine>> = _dnscrypt.asStateFlow()
    val torLogs: StateFlow<List<LogLine>> = _tor.asStateFlow()

    fun snapshot(source: LogSource): List<LogLine> = synchronized(lock) {
        when (source) {
            LogSource.APP -> appDeque.toList()
            LogSource.DNSCRYPT -> dnsDeque.toList()
            LogSource.TOR -> torDeque.toList()
        }
    }

    /** Plain-text dump for share/export (OnionVPN / DNSCrypt / Tor tabs). */
    fun exportText(source: LogSource? = null): String {
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", java.util.Locale.US)
        fun render(src: LogSource, lines: List<LogLine>): String {
            val header = "===== ${src.name} (${lines.size} lines) ====="
            if (lines.isEmpty()) return "$header\n(empty)\n"
            return buildString {
                appendLine(header)
                for (line in lines) {
                    val ts = fmt.format(java.util.Date(line.timestampMs))
                    val mark = " ${line.level.exportMark} "
                    appendLine("$ts$mark${line.text}")
                }
                appendLine()
            }
        }
        return synchronized(lock) {
            if (source != null) {
                render(source, snapshotUnlocked(source))
            } else {
                buildString {
                    appendLine("OnionVPN log export")
                    appendLine("generated=${fmt.format(java.util.Date())}")
                    appendLine("levels=T:trace D:debug I:info W:warn E:error C:critical")
                    appendLine()
                    append(render(LogSource.APP, snapshotUnlocked(LogSource.APP)))
                    append(render(LogSource.DNSCRYPT, snapshotUnlocked(LogSource.DNSCRYPT)))
                    append(render(LogSource.TOR, snapshotUnlocked(LogSource.TOR)))
                }
            }
        }
    }

    private fun snapshotUnlocked(source: LogSource): List<LogLine> = when (source) {
        LogSource.APP -> appDeque.toList()
        LogSource.DNSCRYPT -> dnsDeque.toList()
        LogSource.TOR -> torDeque.toList()
    }

    fun append(
        source: LogSource,
        text: String,
        severity: StabilitySeverity = StabilitySeverity.INFO,
    ) {
        if (!DiagnosticsGate.enabled()) return
        val clipped = if (text.length > MAX_LINE_CHARS) {
            text.take(MAX_LINE_CHARS) + "…"
        } else {
            text
        }
        val line = LogLine(System.currentTimeMillis(), clipped, severity = severity)
        synchronized(lock) {
            when (source) {
                LogSource.APP -> push(appDeque, line)
                LogSource.DNSCRYPT -> push(dnsDeque, line)
                LogSource.TOR -> push(torDeque, line)
            }
            schedulePublish()
        }
    }

    /** @deprecated Prefer [append] with [StabilitySeverity]. */
    @Suppress("unused")
    fun append(source: LogSource, text: String, isError: Boolean) {
        append(
            source,
            text,
            severity = if (isError) StabilitySeverity.ERROR else StabilitySeverity.INFO,
        )
    }

    fun clear(source: LogSource) {
        synchronized(lock) {
            when (source) {
                LogSource.APP -> {
                    appDeque.clear()
                    _app.value = emptyList()
                }
                LogSource.DNSCRYPT -> {
                    dnsDeque.clear()
                    _dnscrypt.value = emptyList()
                }
                LogSource.TOR -> {
                    torDeque.clear()
                    _tor.value = emptyList()
                }
            }
        }
    }

    fun clearAll() {
        LogSource.entries.forEach { clear(it) }
    }

    private fun schedulePublish() {
        if (publishPending) return
        publishPending = true
        mainHandler.postDelayed({
            synchronized(lock) {
                publishPending = false
                _app.value = appDeque.toList()
                _dnscrypt.value = dnsDeque.toList()
                _tor.value = torDeque.toList()
            }
        }, PUBLISH_DEBOUNCE_MS)
    }

    private fun push(deque: ArrayDeque<LogLine>, line: LogLine) {
        if (deque.size >= CAPACITY) deque.removeFirst()
        deque.addLast(line)
    }
}
