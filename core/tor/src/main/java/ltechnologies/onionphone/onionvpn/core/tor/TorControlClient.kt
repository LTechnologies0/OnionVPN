package ltechnologies.onionphone.onionvpn.core.tor

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import timber.log.Timber

/**
 * Tor control-spec client over Unix [ControlSocket] + cookie auth.
 *
 * @see <a href="https://spec.torproject.org/control-spec/">control-spec</a>
 */
class TorControlClient {
    private val commandLock = Any()
    private var socket: LocalSocket? = null
    private var reader: BufferedReader? = null
    private var writer: BufferedWriter? = null
    private var readerThread: Thread? = null
    private val running = AtomicBoolean(false)

    private val replyLock = Any()
    private var replyBuffer: MutableList<String>? = null
    private var replyLatch: CountDownLatch? = null
    private var replyError: IOException? = null

    private val _status = MutableStateFlow(TorControlStatus())
    val status: StateFlow<TorControlStatus> = _status.asStateFlow()

    private val _events = MutableSharedFlow<TorControlEvent>(extraBufferCapacity = 64)
    val events: SharedFlow<TorControlEvent> = _events.asSharedFlow()

    val isConnected: Boolean get() = running.get()

    fun connect(controlSocketPath: File, cookieFile: File) {
        disconnect(sendShutdown = false)
        if (!controlSocketPath.exists()) {
            throw IOException("Control socket missing: ${controlSocketPath.absolutePath}")
        }
        if (!cookieFile.exists() || cookieFile.length() == 0L) {
            throw IOException("Cookie file missing: ${cookieFile.absolutePath}")
        }
        val cookieHex = cookieFile.readBytes().joinToString("") { b ->
            "%02X".format(b.toInt() and 0xff)
        }
        val sock = LocalSocket()
        sock.connect(
            LocalSocketAddress(
                controlSocketPath.absolutePath,
                LocalSocketAddress.Namespace.FILESYSTEM,
            ),
        )
        socket = sock
        reader = BufferedReader(InputStreamReader(sock.inputStream, StandardCharsets.US_ASCII))
        writer = BufferedWriter(OutputStreamWriter(sock.outputStream, StandardCharsets.US_ASCII))
        running.set(true)
        startReader()

        command("AUTHENTICATE $cookieHex")
        runCatching { command("TAKEOWNERSHIP") }
        runCatching { command("RESETCONF __OwningControllerProcess") }
        command("SETEVENTS STATUS_CLIENT CIRC CIRC_MINOR BW NOTICE WARN ERR GUARD")
        refreshInfo()
        _status.update { it.copy(connected = true, lastError = null) }
        Timber.i("Tor control connected (%s)", controlSocketPath.name)
    }

    fun disconnect(sendShutdown: Boolean = true) {
        if (sendShutdown && running.get()) {
            runCatching { command("SIGNAL SHUTDOWN") }
        }
        running.set(false)
        failPending(IOException("control disconnected"))
        runCatching { writer?.close() }
        runCatching { reader?.close() }
        runCatching { socket?.close() }
        writer = null
        reader = null
        socket = null
        readerThread?.interrupt()
        readerThread = null
        _status.value = TorControlStatus()
    }

    fun signal(name: String): Result<Unit> = runCatching {
        command("SIGNAL $name")
        Unit
    }

    fun newNym(): Result<Unit> = signal("NEWNYM").also {
        runCatching { command("SIGNAL CLEARDNSCACHE") }
    }

    fun clearDnsCache(): Result<Unit> = signal("CLEARDNSCACHE")

    fun setActive(): Result<Unit> = signal("ACTIVE")

    fun setDormant(): Result<Unit> = signal("DORMANT")

    fun closeBuiltCircuits(): Result<Int> = runCatching {
        val body = getInfo("circuit-status")
        var closed = 0
        body.lineSequence().forEach { line ->
            val parts = line.trim().split(' ')
            if (parts.size < 2) return@forEach
            val id = parts[0]
            val st = parts[1]
            if (st == "BUILT" || st == "EXTENDED" || st == "GUARD_WAIT") {
                runCatching { command("CLOSECIRCUIT $id") }
                closed++
            }
        }
        refreshInfo()
        closed
    }

    fun refreshInfo() {
        if (!running.get()) return
        runCatching {
            parseBootstrapPhase(getInfo("status/bootstrap-phase"))?.let { b ->
                _status.update {
                    it.copy(
                        bootstrapProgress = b.progress,
                        bootstrapTag = b.tag,
                        bootstrapSummary = b.summary,
                    )
                }
            }
            val circEst = getInfo("status/circuit-established") == "1"
            val dirOk = getInfo("status/enough-dir-info") == "1"
            val dormant = (getInfo("dormant").toIntOrNull() ?: 0) != 0
            val read = getInfo("traffic/read").toLongOrNull() ?: 0L
            val write = getInfo("traffic/written").toLongOrNull() ?: 0L
            val built = getInfo("circuit-status").lineSequence().count {
                it.trim().split(' ').getOrNull(1) == "BUILT"
            }
            _status.update {
                it.copy(
                    circuitEstablished = circEst,
                    enoughDirInfo = dirOk,
                    dormant = dormant,
                    readBytes = read,
                    writeBytes = write,
                    builtCircuits = built,
                )
            }
        }.onFailure { err ->
            Timber.w(err, "Tor GETINFO refresh failed")
            _status.update { it.copy(lastError = err.message) }
        }
    }

    fun getInfo(key: String): String {
        val lines = command("GETINFO $key")
        return multilineValue(lines, key)
    }

    private fun command(cmd: String): List<String> {
        synchronized(commandLock) {
            if (!running.get()) throw IOException("Tor control not connected")
            val w = writer ?: throw IOException("no writer")
            val latch = CountDownLatch(1)
            synchronized(replyLock) {
                replyBuffer = mutableListOf()
                replyError = null
                replyLatch = latch
            }
            w.write(cmd)
            w.write("\r\n")
            w.flush()
            if (!latch.await(30, TimeUnit.SECONDS)) {
                failPending(IOException("control command timeout: $cmd"))
                throw IOException("control command timeout: $cmd")
            }
            synchronized(replyLock) {
                replyError?.let { throw it }
                return replyBuffer?.toList() ?: emptyList()
            }
        }
    }

    private fun failPending(error: IOException) {
        synchronized(replyLock) {
            replyError = error
            replyLatch?.countDown()
            replyLatch = null
        }
    }

    private fun startReader() {
        readerThread = Thread({
            try {
                while (running.get()) {
                    val line = reader?.readLine() ?: break
                    if (line.startsWith("650 ") || line.startsWith("650-")) {
                        val payload = line.substring(4)
                        dispatchAsyncEvent(payload)
                        continue
                    }
                    synchronized(replyLock) {
                        val buf = replyBuffer ?: return@synchronized
                        buf.add(line)
                        val terminal = line.startsWith("250 ") ||
                            line.startsWith("251 ") ||
                            (line.length >= 4 && line[0] == '5' && line[3] == ' ')
                        if (terminal) {
                            if (line.startsWith("5")) {
                                replyError = IOException(line)
                            }
                            replyLatch?.countDown()
                            replyLatch = null
                        }
                    }
                }
            } catch (_: Exception) {
                if (running.get()) Timber.w("Tor control reader stopped")
            } finally {
                running.set(false)
                _status.update { it.copy(connected = false) }
                failPending(IOException("control reader ended"))
            }
        }, "tor-control-reader").apply {
            isDaemon = true
            start()
        }
    }

    private fun dispatchAsyncEvent(payload: String) {
        when {
            payload.contains("BOOTSTRAP") -> {
                parseBootstrapEvent(payload)?.let { boot ->
                    _status.update {
                        it.copy(
                            bootstrapProgress = boot.progress,
                            bootstrapTag = boot.tag,
                            bootstrapSummary = boot.summary,
                        )
                    }
                    _events.tryEmit(boot)
                }
            }
            payload.startsWith("CIRC ") || payload.startsWith("CIRC_MINOR ") -> {
                val parts = payload.split(' ')
                if (parts.size >= 3) {
                    val id = parts[1]
                    val st = parts[2]
                    val reason = parts.firstOrNull { it.startsWith("REASON=") }?.substringAfter('=')
                    val path = parts.getOrNull(3)?.takeIf { !it.contains('=') }.orEmpty()
                    if (st == "FAILED" || st == "CLOSED") {
                        _status.update {
                            it.copy(
                                failedCircuitsRecent = it.failedCircuitsRecent + 1,
                                lastCircEvent = "$st $id ${reason.orEmpty()}".trim(),
                            )
                        }
                    } else {
                        _status.update { it.copy(lastCircEvent = "$st $id") }
                    }
                    _events.tryEmit(TorControlEvent.Circuit(id, st, path, reason))
                }
            }
            payload.startsWith("BW ") -> {
                val parts = payload.split(' ')
                if (parts.size >= 3) {
                    val r = parts[1].toLongOrNull() ?: 0L
                    val w = parts[2].toLongOrNull() ?: 0L
                    _events.tryEmit(TorControlEvent.Bandwidth(r, w))
                }
            }
            payload.startsWith("GUARD ") -> _events.tryEmit(TorControlEvent.Guard(payload))
            payload.startsWith("NOTICE ") ||
                payload.startsWith("WARN ") ||
                payload.startsWith("ERR ") -> {
                _events.tryEmit(TorControlEvent.Notice(payload))
            }
        }
    }

    companion object {
        fun parseBootstrapPhase(raw: String): TorControlEvent.Bootstrap? = parseBootstrapEvent(raw)

        fun parseBootstrapEvent(payload: String): TorControlEvent.Bootstrap? {
            if (!payload.contains("BOOTSTRAP")) return null
            val progress = Regex("""PROGRESS=(\d+)""")
                .find(payload)?.groupValues?.get(1)?.toIntOrNull() ?: return null
            val tag = Regex("""TAG=(\S+)""").find(payload)?.groupValues?.get(1).orEmpty()
            val summary = Regex("""SUMMARY="([^"]*)"""").find(payload)?.groupValues?.get(1)
                ?: Regex("""SUMMARY=(\S+)""").find(payload)?.groupValues?.get(1).orEmpty()
            val warning = Regex("""WARNING="([^"]*)"""").find(payload)?.groupValues?.get(1)
            val reason = Regex("""REASON=(\S+)""").find(payload)?.groupValues?.get(1)
            return TorControlEvent.Bootstrap(progress, tag, summary, warning, reason)
        }

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
}
