package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLSocketFactory
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.Socks5Client
import timber.log.Timber

/**
 * Loopback UDP DNS → DNS-over-HTTPS via SOCKS5 (IP literal CONNECT on :443).
 *
 * Replaces Tor DNSPort for DNSCrypt `bootstrap_resolvers` / `netprobe_address` on the
 * onionmasq plane. Classic TCP/53 through Tor exits is routinely rejected (exit policy);
 * DoH on 443 matches what DNSCrypt itself uses once bootstrapped.
 *
 * SOCKS CONNECT uses [DEFAULT_DOH_CONNECT_HOST] (1.1.1.1); TLS SNI + HTTP Host use
 * [DEFAULT_DOH_SNI_HOST] (dns.cloudflare.com) so the Cloudflare cert matches.
 *
 * Receive loop is single-threaded; DoH resolves run on a bounded pool so one slow
 * query cannot stall DNSCrypt bootstrap / netprobe.
 */
class SocksDnsBootstrapRelay(
    private val listenPort: Int,
    private val socksHost: String = TunnelEndpoints.LOOPBACK,
    private val socksPort: Int,
    private val socksUser: String = TunnelEndpoints.SOCKS_DNSCRYPT_USER,
    private val socksPass: String = TunnelEndpoints.SOCKS_DNSCRYPT_PASS,
    private val dohConnectHost: String = DEFAULT_DOH_CONNECT_HOST,
    private val dohSniHost: String = DEFAULT_DOH_SNI_HOST,
    private val dohPort: Int = DEFAULT_DOH_PORT,
    private val dohPath: String = DEFAULT_DOH_PATH,
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
                "SocksDnsBootstrapRelay listen=:%d via socks=:%d → DoH https://%s(%s):%d%s workers=%d",
                listenPort,
                socksPort,
                dohConnectHost,
                dohSniHost,
                dohPort,
                dohPath,
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
                    pool.execute {
                        if (!running.get()) return@execute
                        val answer = resolveViaDoh(query) ?: return@execute
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

    /**
     * Start-gate probe: minimal UDP DNS to this relay; true if any answer is received.
     */
    fun probeOnce(timeoutMs: Int = 3_000): Boolean {
        if (!running.get()) return false
        return try {
            DatagramSocket().use { probe ->
                probe.soTimeout = timeoutMs
                val query = MINIMAL_DNS_QUERY
                probe.send(
                    DatagramPacket(
                        query,
                        query.size,
                        InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                        listenPort,
                    ),
                )
                val response = DatagramPacket(ByteArray(512), 512)
                probe.receive(response)
                response.length >= 12
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun resolveViaDoh(udpQuery: ByteArray): ByteArray? {
        if (!running.get()) return null
        resolveViaDohOnce(udpQuery)?.let { return it }
        // One retry on transient SOCKS / TLS / DoH failure.
        if (!running.get()) return null
        return resolveViaDohOnce(udpQuery)
    }

    private fun resolveViaDohOnce(udpQuery: ByteArray): ByteArray? {
        if (!running.get()) return null
        return try {
            Socks5Client(
                proxyHost = socksHost,
                proxyPort = socksPort,
                username = socksUser,
                password = socksPass,
                connectTimeoutMs = 15_000,
                handshakeTimeoutMs = 60_000,
            ).connect(dohConnectHost, dohPort).use { tcp ->
                if (!running.get()) return null
                val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                // SNI + cert hostname = dns.cloudflare.com; TCP peer is still 1.1.1.1.
                val ssl = sslFactory.createSocket(tcp, dohSniHost, dohPort, true) as javax.net.ssl.SSLSocket
                ssl.soTimeout = 20_000
                ssl.startHandshake()
                val out = BufferedOutputStream(ssl.getOutputStream())
                val inp = BufferedInputStream(ssl.getInputStream())
                val headers = buildString {
                    append("POST $dohPath HTTP/1.1\r\n")
                    append("Host: $dohSniHost\r\n")
                    append("Content-Type: application/dns-message\r\n")
                    append("Accept: application/dns-message\r\n")
                    append("Content-Length: ${udpQuery.size}\r\n")
                    append("Connection: close\r\n")
                    append("User-Agent: OnionVPN-bootstrap\r\n")
                    append("\r\n")
                }.toByteArray(Charsets.US_ASCII)
                out.write(headers)
                out.write(udpQuery)
                out.flush()
                parseHttpDnsMessage(inp)
            }
        } catch (error: Exception) {
            if (running.get()) {
                Timber.d(error, "SocksDnsBootstrapRelay DoH resolve failed")
            }
            null
        }
    }

    private fun parseHttpDnsMessage(inp: BufferedInputStream): ByteArray? {
        val header = StringBuilder()
        while (true) {
            val line = readAsciiLine(inp) ?: return null
            if (line.isEmpty()) break
            header.append(line).append('\n')
            if (header.length > 8_192) return null
        }
        val status = header.lineSequence().firstOrNull().orEmpty()
        if (!status.contains(" 200")) {
            Timber.d("SocksDnsBootstrapRelay DoH HTTP status: %s", status.trim())
            return null
        }
        val chunked = header.contains("transfer-encoding: chunked", ignoreCase = true)
        val length = Regex("""content-length:\s*(\d+)""", RegexOption.IGNORE_CASE)
            .find(header.toString())
            ?.groupValues?.get(1)
            ?.toIntOrNull()
        val body = when {
            length != null && length > 0 && length <= 4096 -> {
                val buf = ByteArray(length)
                DataInputStream(inp).readFully(buf)
                buf
            }
            chunked -> readChunkedBody(inp)
            else -> null
        } ?: return null
        return body.takeIf { it.size >= 12 }
    }

    private fun readChunkedBody(inp: BufferedInputStream): ByteArray? {
        val out = ArrayList<Byte>()
        while (true) {
            val sizeLine = readAsciiLine(inp) ?: return null
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: return null
            if (size == 0) {
                readAsciiLine(inp) // trailing
                break
            }
            if (size < 0 || out.size + size > 4096) return null
            val chunk = ByteArray(size)
            DataInputStream(inp).readFully(chunk)
            chunk.forEach { out.add(it) }
            readAsciiLine(inp) // CRLF after chunk
        }
        return out.toByteArray()
    }

    private fun readAsciiLine(inp: BufferedInputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = inp.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
            if (sb.length > 2_048) return null
        }
        return sb.toString()
    }

    companion object {
        /** Cloudflare DoH anycast IP — SOCKS CONNECT target (port 443 survives exit policy). */
        const val DEFAULT_DOH_CONNECT_HOST = "1.1.1.1"
        /** TLS SNI + HTTP Host — must match Cloudflare cert (not the IP literal). */
        const val DEFAULT_DOH_SNI_HOST = "dns.cloudflare.com"
        /** @deprecated Use [DEFAULT_DOH_CONNECT_HOST]. */
        const val DEFAULT_DOH_HOST = DEFAULT_DOH_CONNECT_HOST
        const val DEFAULT_DOH_PORT = 443
        const val DEFAULT_DOH_PATH = "/dns-query"
        private const val WORKERS = 4

        /** A? example.com — used by [probeOnce]. */
        private val MINIMAL_DNS_QUERY = byteArrayOf(
            0x00, 0x01,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        )

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
