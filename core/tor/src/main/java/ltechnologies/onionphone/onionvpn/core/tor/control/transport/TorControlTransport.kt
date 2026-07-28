package ltechnologies.onionphone.onionvpn.core.tor.control.transport

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
import timber.log.Timber

/**
 * Package `control.transport` — LocalSocket byte pipe for Tor ControlSocket.
 *
 * Imported only by [ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient].
 * Demultiplexes sync replies vs async `650` lines; no protocol parsing.
 */

/**
 * Low-level control channel: open filesystem Unix socket, send CRLF commands, await replies.
 *
 * @param onAsyncPayload invoked on the reader thread with text after `650 `/`650-`
 * @param onReaderEnded invoked when the reader stops (marks channel dead)
 */
internal class TorControlTransport(
    private val onAsyncPayload: (String) -> Unit,
    private val onReaderEnded: () -> Unit,
) {
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

    /** True while the reader loop is expected to run. */
    val isOpen: Boolean get() = running.get()

    /**
     * Connects to [controlSocketPath] (FILESYSTEM namespace) and starts the reader thread.
     * Does **not** authenticate — that is the client's sequential step.
     */
    fun open(controlSocketPath: File) {
        closeQuietly()
        if (!controlSocketPath.exists()) {
            throw IOException("Control socket missing: ${controlSocketPath.absolutePath}")
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
    }

    /**
     * Sends one control command and waits for a terminal reply line (`250 `/`251 `/`5xx `).
     *
     * @throws IOException on timeout, disconnect, or `5xx` reply
     */
    fun command(cmd: String): List<String> {
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

    /** Tears down socket/reader; fails any in-flight command. */
    fun closeQuietly() {
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
                        onAsyncPayload(line.substring(4))
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
                onReaderEnded()
                failPending(IOException("control reader ended"))
            }
        }, "tor-control-reader").apply {
            isDaemon = true
            start()
        }
    }
}
