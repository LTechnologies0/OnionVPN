package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.Socks5Client
import timber.log.Timber

/**
 * Loopback UDP DNS → TCP DNS via SOCKS5 (IP literal upstream).
 *
 * Replaces Tor DNSPort for DNSCrypt `bootstrap_resolvers` / `netprobe_address` on the
 * onionmasq plane (single TorClient: queries ride the SOCKS sidecar, never clearnet).
 *
 * Receive loop is single-threaded; SOCKS resolves run on a bounded pool so one slow
 * query cannot stall DNSCrypt bootstrap / netprobe.
 */
class SocksDnsBootstrapRelay(
    private val listenPort: Int,
    private val socksHost: String = TunnelEndpoints.LOOPBACK,
    private val socksPort: Int,
    private val socksUser: String = TunnelEndpoints.SOCKS_DNSCRYPT_USER,
    private val socksPass: String = TunnelEndpoints.SOCKS_DNSCRYPT_PASS,
    private val upstreamHost: String = DEFAULT_UPSTREAM_HOST,
    private val upstreamPort: Int = DEFAULT_UPSTREAM_PORT,
) {
    private val running = AtomicBoolean(false)
    private var socket: DatagramSocket? = null
    private var thread: Thread? = null
    private var pool = newPool()

    fun start() {
        stop()
        pool = newPool()
        val sock = DatagramSocket(listenPort, InetAddress.getByName(TunnelEndpoints.LOOPBACK))
        sock.soTimeout = 0
        socket = sock
        running.set(true)
        thread = Thread({
            Timber.i(
                "SocksDnsBootstrapRelay listen=:%d via socks=:%d → %s:%d workers=%d",
                listenPort,
                socksPort,
                upstreamHost,
                upstreamPort,
                WORKERS,
            )
            val buf = ByteArray(2048)
            while (running.get()) {
                try {
                    val packet = DatagramPacket(buf, buf.size)
                    sock.receive(packet)
                    val query = buf.copyOf(packet.length)
                    val client = packet.address
                    val clientPort = packet.port
                    // Parallel SOCKS resolve — do not block the UDP receive loop.
                    pool.execute {
                        if (!running.get()) return@execute
                        val answer = resolveViaSocks(query) ?: return@execute
                        if (!running.get()) return@execute
                        runCatching {
                            sock.send(DatagramPacket(answer, answer.size, client, clientPort))
                        }.onFailure {
                            if (running.get()) Timber.d(it, "SocksDnsBootstrapRelay send failed")
                        }
                    }
                } catch (error: Exception) {
                    if (running.get()) {
                        Timber.d(error, "SocksDnsBootstrapRelay packet error")
                    }
                }
            }
        }, "socks-dns-bootstrap").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        running.set(false)
        runCatching { socket?.close() }
        socket = null
        thread?.interrupt()
        thread = null
        pool.shutdownNow()
        runCatching { pool.awaitTermination(2, TimeUnit.SECONDS) }
    }

    private fun resolveViaSocks(udpQuery: ByteArray): ByteArray? {
        if (!running.get()) return null
        return try {
            Socks5Client(
                proxyHost = socksHost,
                proxyPort = socksPort,
                username = socksUser,
                password = socksPass,
                connectTimeoutMs = 15_000,
                handshakeTimeoutMs = 60_000,
            ).connect(upstreamHost, upstreamPort).use { tcp ->
                if (!running.get()) return null
                tcp.soTimeout = 20_000
                val out = DataOutputStream(tcp.getOutputStream())
                val inp = DataInputStream(tcp.getInputStream())
                out.writeShort(udpQuery.size)
                out.write(udpQuery)
                out.flush()
                val len = inp.readUnsignedShort()
                if (len <= 0 || len > 4096) return null
                val resp = ByteArray(len)
                inp.readFully(resp)
                resp
            }
        } catch (error: Exception) {
            if (running.get()) {
                Timber.d(error, "SocksDnsBootstrapRelay SOCKS resolve failed")
            }
            null
        }
    }

    companion object {
        const val DEFAULT_UPSTREAM_HOST = "1.1.1.1"
        const val DEFAULT_UPSTREAM_PORT = 53
        private const val WORKERS = 4

        private fun newPool() = Executors.newFixedThreadPool(
            WORKERS,
            object : ThreadFactory {
                private val n = AtomicInteger()
                override fun newThread(r: Runnable): Thread =
                    Thread(r, "socks-dns-worker-${n.incrementAndGet()}").apply { isDaemon = true }
            },
        )
    }
}
