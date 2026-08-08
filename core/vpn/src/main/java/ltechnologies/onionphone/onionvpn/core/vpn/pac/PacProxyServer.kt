package ltechnologies.onionphone.onionvpn.core.vpn.pac

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import timber.log.Timber

/**
 * Loopback HTTP server for a stable PAC URL + owns the DNSCrypt→Tor SOCKS bridge.
 *
 * PAC body always returns [TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT] (not raw Tor SOCKS),
 * so name resolution goes through DNSCrypt.
 */
class PacProxyServer(
    private val listenPort: Int = TunnelEndpoints.PAC_LISTEN_PORT,
) {
    private val running = AtomicBoolean(false)
    private val bridgeUp = AtomicBoolean(false)
    private val serverRef = AtomicReference<ServerSocket?>(null)
    private var acceptThread: Thread? = null
    private var clientExecutor = newClientExecutor()
    private val socksBridge = DnsCryptSocksBridge()

    val pacUrl: String get() = TunnelEndpoints.pacUrl()

    fun updateUpstream(torSocksPort: Int, dnsCryptListenPort: Int) {
        socksBridge.updateUpstream(torSocksPort, dnsCryptListenPort)
        bridgeUp.set(torSocksPort > 0 && dnsCryptListenPort > 0)
        Timber.i(
            "PAC upstream torSocks=%d dnsCrypt=%d bridge=%s url=%s",
            torSocksPort,
            dnsCryptListenPort,
            TunnelEndpoints.pacSocksBridge(),
            pacUrl,
        )
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        if (clientExecutor.isShutdown || clientExecutor.isTerminated) {
            clientExecutor = newClientExecutor()
        }
        socksBridge.start()
        val server = try {
            ServerSocket(listenPort, 8, InetAddress.getByName(TunnelEndpoints.LOOPBACK))
        } catch (e: Exception) {
            running.set(false)
            runCatching { socksBridge.stop() }
            Timber.e(e, "PAC listen failed on ${TunnelEndpoints.LOOPBACK}:$listenPort")
            throw e
        }
        serverRef.set(server)
        val acceptServer = server
        acceptThread = Thread({
            Timber.i("PAC server listening %s", pacUrl)
            while (!acceptServer.isClosed) {
                try {
                    val client = acceptServer.accept()
                    try {
                        clientExecutor.execute { handleClient(client) }
                    } catch (_: java.util.concurrent.RejectedExecutionException) {
                        runCatching { client.close() }
                    }
                } catch (_: SocketException) {
                    break
                } catch (e: Exception) {
                    if (!acceptServer.isClosed) Timber.d(e, "PAC accept error")
                }
            }
        }, "onionvpn-pac-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        bridgeUp.set(false)
        runCatching { socksBridge.stop() }
        runCatching { serverRef.getAndSet(null)?.close() }
        acceptThread?.let { t ->
            t.interrupt()
            runCatching { t.join(2_000L) }
        }
        acceptThread = null
        clientExecutor.shutdownNow()
        runCatching { clientExecutor.awaitTermination(2, TimeUnit.SECONDS) }
        Timber.i("PAC server stopped")
    }

    private fun newClientExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            1,
            8,
            30L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(16),
            { r -> Thread(r, "onionvpn-pac-req").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    private fun handleClient(socket: Socket) {
        socket.use { sock ->
            sock.soTimeout = 5_000
            val reader = BufferedReader(InputStreamReader(sock.getInputStream(), StandardCharsets.US_ASCII))
            val requestLine = reader.readLine() ?: return
            if (requestLine.length > MAX_REQUEST_LINE) {
                writePlain(
                    OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8),
                    400,
                    "bad request",
                )
                return
            }
            val method = requestLine.substringBefore(' ').trim().uppercase()
            if (method != "GET") {
                writePlain(
                    OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8),
                    405,
                    "method not allowed",
                )
                return
            }
            var hostHeader: String? = null
            var headerCount = 0
            while (headerCount < MAX_HEADERS) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) break
                if (line.length > MAX_HEADER_LINE) {
                    writePlain(
                        OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8),
                        400,
                        "bad request",
                    )
                    return
                }
                headerCount++
                val name = line.substringBefore(':').trim()
                if (name.equals("Host", ignoreCase = true)) {
                    hostHeader = line.substringAfter(':').trim().lowercase()
                }
            }
            if (headerCount >= MAX_HEADERS) {
                writePlain(
                    OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8),
                    400,
                    "bad request",
                )
                return
            }
            // Loopback-only bind is the primary control; Host check blocks odd local proxies.
            if (hostHeader != null && !isLoopbackHostHeader(hostHeader)) {
                writePlain(
                    OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8),
                    400,
                    "bad host",
                )
                return
            }
            val path = requestLine.substringAfter(' ').substringBefore(' ').trim()
            val writer = OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8)
            when {
                path == TunnelEndpoints.PAC_PATH ||
                    path == "/proxy.pac" ||
                    path == "/wpad.dat" ||
                    path == "/" -> {
                    val body = PacScript.build(bridgeUp = bridgeUp.get())
                    val bytes = body.toByteArray(StandardCharsets.UTF_8)
                    writer.write("HTTP/1.1 200 OK\r\n")
                    writer.write("Content-Type: application/x-ns-proxy-autoconfig\r\n")
                    writer.write("Cache-Control: no-store, max-age=0\r\n")
                    writer.write("Connection: close\r\n")
                    writer.write("Content-Length: ${bytes.size}\r\n")
                    writer.write("\r\n")
                    writer.flush()
                    sock.getOutputStream().write(bytes)
                    sock.getOutputStream().flush()
                }
                path == "/health" -> {
                    val ok = bridgeUp.get()
                    val msg = if (ok) {
                        "ok bridge=${TunnelEndpoints.pacSocksBridge()} dns=dnscrypt"
                    } else {
                        "down"
                    }
                    writePlain(writer, if (ok) 200 else 503, msg)
                }
                else -> writePlain(writer, 404, "not found")
            }
        }
    }

    private fun isLoopbackHostHeader(host: String): Boolean {
        val h = host.substringBefore(':').trim().lowercase()
        return h == "127.0.0.1" || h == "localhost" || h == "[::1]" || h == "::1"
    }

    private fun writePlain(writer: OutputStreamWriter, code: Int, body: String) {
        val reason = when (code) {
            200 -> "OK"
            400 -> "Bad Request"
            405 -> "Method Not Allowed"
            503 -> "Service Unavailable"
            else -> "Not Found"
        }
        val bytes = body.toByteArray(StandardCharsets.UTF_8)
        writer.write("HTTP/1.1 $code $reason\r\n")
        writer.write("Content-Type: text/plain; charset=utf-8\r\n")
        writer.write("Connection: close\r\n")
        writer.write("Content-Length: ${bytes.size}\r\n")
        writer.write("\r\n")
        writer.write(body)
        writer.flush()
    }

    companion object {
        private const val MAX_REQUEST_LINE = 512
        private const val MAX_HEADER_LINE = 512
        private const val MAX_HEADERS = 32
    }
}
