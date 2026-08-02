package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import timber.log.Timber

/**
 * Transparent TCP relay: accept on [listenPort], pipe bytes to [upstreamHost]:[upstreamPort].
 *
 * Used for Arti SessionGroup parity — DNSCrypt/probe get distinct loopback ports that
 * forward to the single Arti SOCKS listener; SOCKS auth (IsolationToken) passes through.
 */
class SocksTcpRelay(
    private val listenPort: Int,
    private val upstreamHost: String,
    private val upstreamPort: Int,
    private val label: String,
) {
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private var acceptExecutor: ThreadPoolExecutor? = null
    private var pipeExecutor: ThreadPoolExecutor? = null

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), listenPort))
        server = ss
        val accept = newAcceptExecutor()
        val pipe = newPipeExecutor()
        acceptExecutor = accept
        pipeExecutor = pipe
        accept.execute {
            Timber.i("SocksTcpRelay[$label] listen=$listenPort → $upstreamHost:$upstreamPort")
            while (running.get()) {
                val client = try {
                    ss.accept()
                } catch (_: IOException) {
                    break
                }
                try {
                    pipe.execute { handle(client, pipe) }
                } catch (_: Exception) {
                    runCatching { client.close() }
                }
            }
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        runCatching { server?.close() }
        server = null
        acceptExecutor?.shutdownNow()
        pipeExecutor?.shutdownNow()
        acceptExecutor = null
        pipeExecutor = null
        Timber.i("SocksTcpRelay[$label] stopped")
    }

    private fun handle(client: Socket, pipe: ThreadPoolExecutor) {
        var upstream: Socket? = null
        try {
            client.tcpNoDelay = true
            upstream = Socket()
            upstream.tcpNoDelay = true
            upstream.connect(InetSocketAddress(upstreamHost, upstreamPort), CONNECT_TIMEOUT_MS)
            val up = upstream
            val c2u = pipe.submit { copy(client, up) }
            val u2c = pipe.submit { copy(up, client) }
            c2u.get()
            u2c.get()
        } catch (error: Exception) {
            Timber.d(error, "SocksTcpRelay[$label] session end")
        } finally {
            runCatching { client.close() }
            runCatching { upstream?.close() }
        }
    }

    private fun copy(from: Socket, to: Socket) {
        val buf = ByteArray(16 * 1024)
        val input = from.getInputStream()
        val output = to.getOutputStream()
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            output.write(buf, 0, n)
            output.flush()
        }
        runCatching { to.shutdownOutput() }
    }

    private fun newAcceptExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            1,
            1,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(1),
            { r -> Thread(r, "onionvpn-socks-relay-$label").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )

    /**
     * Bounded pipe pool — role-mux traffic is DNSCrypt + probes only (not full TUN).
     * Avoids [java.util.concurrent.Executors.newCachedThreadPool] unbounded growth.
     */
    private fun newPipeExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            2,
            MAX_PIPE_THREADS,
            60L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(32),
            { r -> Thread(r, "onionvpn-socks-pipe-$label").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val MAX_PIPE_THREADS = 32
    }
}
