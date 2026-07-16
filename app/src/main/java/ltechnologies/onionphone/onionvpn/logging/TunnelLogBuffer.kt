package ltechnologies.onionphone.onionvpn.logging

import java.util.ArrayDeque
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class LogSource {
    APP,
    DNSCRYPT,
    TOR,
}

data class LogLine(
    val timestampMs: Long,
    val text: String,
)

/**
 * Thread-safe ring buffers for tunnel UI logs (app / DNSCrypt / Tor).
 */
object TunnelLogBuffer {
    private const val CAPACITY = 500

    private val appDeque = ArrayDeque<LogLine>(CAPACITY)
    private val dnsDeque = ArrayDeque<LogLine>(CAPACITY)
    private val torDeque = ArrayDeque<LogLine>(CAPACITY)
    private val lock = Any()

    private val _app = MutableStateFlow<List<LogLine>>(emptyList())
    private val _dnscrypt = MutableStateFlow<List<LogLine>>(emptyList())
    private val _tor = MutableStateFlow<List<LogLine>>(emptyList())

    val appLogs: StateFlow<List<LogLine>> = _app.asStateFlow()
    val dnsCryptLogs: StateFlow<List<LogLine>> = _dnscrypt.asStateFlow()
    val torLogs: StateFlow<List<LogLine>> = _tor.asStateFlow()

    fun append(source: LogSource, text: String) {
        val line = LogLine(System.currentTimeMillis(), text)
        synchronized(lock) {
            when (source) {
                LogSource.APP -> {
                    push(appDeque, line)
                    _app.value = appDeque.toList()
                }
                LogSource.DNSCRYPT -> {
                    push(dnsDeque, line)
                    _dnscrypt.value = dnsDeque.toList()
                }
                LogSource.TOR -> {
                    push(torDeque, line)
                    _tor.value = torDeque.toList()
                }
            }
        }
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

    private fun push(deque: ArrayDeque<LogLine>, line: LogLine) {
        if (deque.size >= CAPACITY) deque.removeFirst()
        deque.addLast(line)
    }
}
