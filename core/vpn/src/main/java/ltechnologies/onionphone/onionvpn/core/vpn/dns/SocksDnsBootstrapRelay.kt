package ltechnologies.onionphone.onionvpn.core.vpn.dns

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocketFactory
import ltechnologies.onionphone.onionvpn.core.model.SocksJavaProxyAuth
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.Socks5Client
import ltechnologies.onionphone.onionvpn.core.vpn.net.SecureTorHttp.applyTorClientHardening
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import timber.log.Timber

/**
 * Loopback DNS bootstrap for DNSCrypt `bootstrap_resolvers` / `netprobe_address`.
 *
 * DNSCrypt uses `force_tcp = true` for Tor, so bootstrap prefers **TCP DNS**
 * (RFC 1035 length-prefixed). Arti’s stock `dns-proxy` is UDP-only — without a
 * TCP listener on the same port, DNSCrypt cannot bootstrap on Arti.
 *
 * Resolve order for A queries:
 * 1. Optional [hostnameResolver] (Arti Ext JNI → `TorClient::resolve`)
 * 2. Optional SOCKS Tor `RESOLVE` (0xF0) via [socksPort] (Arti SOCKS / role mux)
 * 3. DoH POST `/dns-query` over SOCKS CONNECT to :443 (exit-policy safe)
 *
 * UDP bind is optional: set [bindUdp]=false when Arti already owns UDP :dnsPort.
 * TCP and UDP may share the same port number (different protocols).
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
    /** Bind UDP DNS (skip when Arti dns-proxy already listens on [listenPort]). */
    private val bindUdp: Boolean = true,
    /** Bind TCP DNS — required for DNSCrypt `force_tcp` bootstrap/netprobe. */
    private val bindTcp: Boolean = true,
    /**
     * When true, try Tor SOCKS RESOLVE before DoH.
     * onionmasq sidecar supports RESOLVE via Arti TorClient::resolve.
     */
    private val useSocksResolve: Boolean = true,
    /** Optional Arti Ext / app resolver: hostname → dotted IPv4 (or null). */
    private val hostnameResolver: ((String) -> String?)? = null,
) {
    private val running = AtomicBoolean(false)
    private var udpSocket: DatagramSocket? = null
    private var tcpServer: ServerSocket? = null
    private var udpThread: Thread? = null
    private var tcpThread: Thread? = null
    private var pool = newPool()

    fun start() {
        stop()
        require(bindUdp || bindTcp) { "SocksDnsBootstrapRelay needs bindUdp and/or bindTcp" }
        pool = newPool()
        running.set(true)

        var udpOk = false
        var tcpOk = false
        if (bindTcp) {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(
                java.net.InetSocketAddress(TunnelEndpoints.LOOPBACK, listenPort),
                32,
            )
            tcpServer = server
            tcpOk = true
            tcpThread = Thread({ tcpAcceptLoop(server) }, "socks-dns-bootstrap-tcp").apply {
                isDaemon = true
                start()
            }
        }
        if (bindUdp) {
            try {
                val sock = DatagramSocket(listenPort, InetAddress.getByName(TunnelEndpoints.LOOPBACK))
                sock.soTimeout = 0
                udpSocket = sock
                udpOk = true
                udpThread = Thread({ udpReceiveLoop(sock) }, "socks-dns-bootstrap-udp").apply {
                    isDaemon = true
                    start()
                }
            } catch (error: Exception) {
                Timber.w(
                    error,
                    "SocksDnsBootstrapRelay UDP :%d bind failed — TCP-only (Arti dns-proxy may own UDP)",
                    listenPort,
                )
                if (!tcpOk) {
                    running.set(false)
                    throw error
                }
            }
        }
        Timber.i(
            "SocksDnsBootstrapRelay listen=:%d tcp=%s udp=%s socks=:%d " +
                "socksResolve=%s nativeResolve=%s → DoH https://%s(%s):%d%s",
            listenPort,
            tcpOk,
            udpOk,
            socksPort,
            useSocksResolve,
            hostnameResolver != null,
            dohConnectHost,
            dohSniHost,
            dohPort,
            dohPath,
        )
    }

    fun stop() {
        running.set(false)
        runCatching { udpSocket?.close() }
        runCatching { tcpServer?.close() }
        udpSocket = null
        tcpServer = null
        udpThread?.interrupt()
        tcpThread?.interrupt()
        udpThread = null
        tcpThread = null
        pool.shutdownNow()
        runCatching { pool.awaitTermination(2, TimeUnit.SECONDS) }
    }

    /**
     * Probe for DNSCrypt `force_tcp` path first (TCP), then UDP.
     */
    fun probeOnce(timeoutMs: Int = 3_000): Boolean {
        if (!running.get()) return false
        if (probeOnceTcp(timeoutMs)) return true
        return probeOnceUdp(timeoutMs)
    }

    fun probeOnceTcp(timeoutMs: Int = 3_000): Boolean {
        if (!running.get() || tcpServer == null) return false
        return try {
            Socket().use { sock ->
                sock.connect(
                    java.net.InetSocketAddress(TunnelEndpoints.LOOPBACK, listenPort),
                    timeoutMs.coerceAtLeast(500),
                )
                sock.soTimeout = timeoutMs
                val query = MINIMAL_DNS_QUERY
                // Do not close stream wrappers — that closes the Socket.
                val out = DataOutputStream(sock.getOutputStream())
                out.writeShort(query.size)
                out.write(query)
                out.flush()
                val inp = DataInputStream(sock.getInputStream())
                val len = inp.readUnsignedShort()
                if (len < 12 || len > 4_096) return false
                val resp = ByteArray(len)
                inp.readFully(resp)
                resp.size >= 12 &&
                    resp[0] == query[0] &&
                    resp[1] == query[1]
            }
        } catch (_: Exception) {
            false
        }
    }

    fun probeOnceUdp(timeoutMs: Int = 3_000): Boolean {
        if (!running.get() || udpSocket == null) return false
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

    private fun udpReceiveLoop(sock: DatagramSocket) {
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
                    val answer = resolveQuery(query) ?: return@execute
                    if (!running.get()) return@execute
                    runCatching {
                        sock.send(DatagramPacket(answer, answer.size, client, clientPort))
                    }.onFailure {
                        if (running.get()) Timber.d(it, "SocksDnsBootstrapRelay UDP send failed")
                    }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    Timber.d(error, "SocksDnsBootstrapRelay UDP packet error")
                }
            }
        }
    }

    private fun tcpAcceptLoop(server: ServerSocket) {
        while (running.get()) {
            try {
                val client = server.accept()
                pool.execute {
                    try {
                        handleTcpClient(client)
                    } finally {
                        runCatching { client.close() }
                    }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    Timber.d(error, "SocksDnsBootstrapRelay TCP accept error")
                }
            }
        }
    }

    private fun handleTcpClient(client: Socket) {
        if (!running.get()) return
        client.soTimeout = 20_000
        val inp = DataInputStream(client.getInputStream())
        val out = DataOutputStream(client.getOutputStream())
        // DNSCrypt may pipeline one query per connection; serve until EOF / error.
        while (running.get()) {
            val len = try {
                inp.readUnsignedShort()
            } catch (_: Exception) {
                break
            }
            if (len < 12 || len > 4_096) break
            val query = ByteArray(len)
            try {
                inp.readFully(query)
            } catch (_: Exception) {
                break
            }
            val answer = resolveQuery(query) ?: break
            try {
                out.writeShort(answer.size)
                out.write(answer)
                out.flush()
            } catch (_: Exception) {
                break
            }
        }
    }

    /**
     * Prefer Tor-native resolve for A queries; fall back to DoH over SOCKS.
     */
    private fun resolveQuery(udpQuery: ByteArray): ByteArray? {
        if (!running.get()) return null
        resolveViaTorA(udpQuery)?.let { return it }
        return resolveViaDoh(udpQuery)
    }

    private fun resolveViaTorA(udpQuery: ByteArray): ByteArray? {
        if (!isInetAQuery(udpQuery)) return null
        val parsed = DnsPacketParser.parse(udpQuery, 0, udpQuery.size) ?: return null
        val qname = parsed.qname?.takeIf { it.isNotBlank() } ?: return null

        hostnameResolver?.invoke(qname)?.let { ip ->
            DnsOnionAutomapReply.buildAResponse(udpQuery, 0, udpQuery.size, ip)?.let { return it }
        }

        if (useSocksResolve) {
            runCatching {
                Socks5Client(
                    proxyHost = socksHost,
                    proxyPort = socksPort,
                    username = socksUser,
                    password = socksPass,
                    connectTimeoutMs = 15_000,
                    handshakeTimeoutMs = 60_000,
                ).resolve(qname)
            }.onSuccess { addr ->
                val host = addr.hostAddress?.substringBefore('%') ?: return@onSuccess
                // Prefer IPv4 for DNSCrypt bootstrap (block_ipv6=true).
                if (addr.address.size == 4) {
                    DnsOnionAutomapReply.buildAResponse(udpQuery, 0, udpQuery.size, host)
                        ?.let { return it }
                }
            }.onFailure {
                if (running.get()) {
                    Timber.d(it, "SocksDnsBootstrapRelay SOCKS RESOLVE failed q=%s", qname)
                }
            }
        }
        return null
    }

    private fun resolveViaDoh(udpQuery: ByteArray): ByteArray? {
        if (!running.get()) return null
        val endpoints = buildList {
            add(DohEndpoint(dohConnectHost, dohSniHost, dohPort, dohPath))
            DOH_ENDPOINTS.forEach { ep ->
                if (ep.sniHost != dohSniHost) add(ep)
            }
        }
        for (endpoint in endpoints) {
            if (!running.get()) return null
            // Prefer OkHttp (battle-tested TLS+ALPN over Java SOCKS) — raw SSLSocket
            // over Socks5Client often got EOF mid-handshake on onionmasq sidecar.
            resolveViaDohOkHttp(udpQuery, endpoint)?.let { return it }
            if (!running.get()) return null
            resolveViaDohRawSsl(udpQuery, endpoint)?.let { return it }
        }
        return null
    }

    /**
     * DoH via OkHttp → Java SOCKS5h (hostname CONNECT) → Tor/onionmasq sidecar.
     * Same pattern as ExitIpValidator — Conscrypt + ALPN handled by OkHttp.
     */
    private fun resolveViaDohOkHttp(udpQuery: ByteArray, endpoint: DohEndpoint): ByteArray? {
        if (!running.get()) return null
        return try {
            val client = OkHttpClient.Builder()
                .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort)))
                .dns(BootstrapTorSocksDns)
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(25, TimeUnit.SECONDS)
                .writeTimeout(20, TimeUnit.SECONDS)
                .callTimeout(45, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .applyTorClientHardening()
                .build()
            val url = "https://${endpoint.sniHost}:${endpoint.port}${endpoint.path}"
            val body = udpQuery.toRequestBody(DNS_MESSAGE_MEDIA)
            SocksJavaProxyAuth.withCredentials(socksUser, socksPass) {
                client.newCall(
                    Request.Builder()
                        .url(url)
                        .header("Accept", "application/dns-message")
                        .header("User-Agent", "OnionVPN-bootstrap")
                        .post(body)
                        .build(),
                ).execute().use { response ->
                    if (!response.isSuccessful) {
                        Timber.d(
                            "SocksDnsBootstrapRelay DoH HTTP %s endpoint=%s",
                            response.code,
                            endpoint.sniHost,
                        )
                        return@withCredentials null
                    }
                    response.body?.bytes()?.takeIf { it.size >= 12 }
                }
            }
        } catch (error: Exception) {
            if (running.get()) {
                Timber.d(
                    error,
                    "SocksDnsBootstrapRelay DoH OkHttp failed endpoint=%s",
                    endpoint.sniHost,
                )
            }
            null
        }
    }

    /** Fallback: Socks5Client CONNECT (IP then hostname) + SSLSocket with SNI. */
    private fun resolveViaDohRawSsl(udpQuery: ByteArray, endpoint: DohEndpoint): ByteArray? {
        if (!running.get()) return null
        // IP CONNECT + SNI avoids a second remote resolve; hostname CONNECT is SOCKS5h.
        val targets = listOf(endpoint.connectHost, endpoint.sniHost).distinct()
        for (connectHost in targets) {
            if (!running.get()) return null
            try {
                Socks5Client(
                    proxyHost = socksHost,
                    proxyPort = socksPort,
                    username = socksUser,
                    password = socksPass,
                    connectTimeoutMs = 15_000,
                    handshakeTimeoutMs = 60_000,
                ).connect(connectHost, endpoint.port).use { tcp ->
                    if (!running.get()) return null
                    tcp.soTimeout = 25_000
                    val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
                    val ssl = sslFactory.createSocket(
                        tcp,
                        endpoint.sniHost,
                        endpoint.port,
                        true,
                    ) as javax.net.ssl.SSLSocket
                    ssl.useClientMode = true
                    runCatching {
                        ssl.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
                    }
                    ssl.soTimeout = 25_000
                    ssl.startHandshake()
                    val hv = HttpsURLConnection.getDefaultHostnameVerifier()
                    if (!hv.verify(endpoint.sniHost, ssl.session)) {
                        throw SSLPeerUnverifiedException(
                            "DoH hostname mismatch sni=${endpoint.sniHost}",
                        )
                    }
                    val out = BufferedOutputStream(ssl.getOutputStream())
                    val inp = BufferedInputStream(ssl.getInputStream())
                    val headers = buildString {
                        append("POST ${endpoint.path} HTTP/1.1\r\n")
                        append("Host: ${endpoint.sniHost}\r\n")
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
                    parseHttpDnsMessage(inp)?.let { return it }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    Timber.d(
                        error,
                        "SocksDnsBootstrapRelay DoH raw SSL failed connect=%s sni=%s",
                        connectHost,
                        endpoint.sniHost,
                    )
                }
            }
        }
        return null
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
                readAsciiLine(inp)
                break
            }
            if (size < 0 || out.size + size > 4096) return null
            val chunk = ByteArray(size)
            DataInputStream(inp).readFully(chunk)
            chunk.forEach { out.add(it) }
            readAsciiLine(inp)
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
        /** Cloudflare DoH anycast IP — legacy CONNECT target (raw SSL fallback). */
        const val DEFAULT_DOH_CONNECT_HOST = "1.1.1.1"
        /** TLS SNI + HTTP Host — must match Cloudflare cert (not the IP literal). */
        const val DEFAULT_DOH_SNI_HOST = "dns.cloudflare.com"
        /** @deprecated Use [DEFAULT_DOH_CONNECT_HOST]. */
        const val DEFAULT_DOH_HOST = DEFAULT_DOH_CONNECT_HOST
        const val DEFAULT_DOH_PORT = 443
        const val DEFAULT_DOH_PATH = "/dns-query"
        private const val WORKERS = 4
        private val DNS_MESSAGE_MEDIA = "application/dns-message".toMediaType()

        private data class DohEndpoint(
            val connectHost: String,
            val sniHost: String,
            val port: Int = DEFAULT_DOH_PORT,
            val path: String = DEFAULT_DOH_PATH,
        )

        /** Ordered DoH providers — OkHttp uses [DohEndpoint.sniHost] via SOCKS5h. */
        private val DOH_ENDPOINTS = listOf(
            DohEndpoint(DEFAULT_DOH_CONNECT_HOST, DEFAULT_DOH_SNI_HOST),
            DohEndpoint("1.0.0.1", "cloudflare-dns.com"),
            DohEndpoint("9.9.9.9", "dns.quad9.net"),
            DohEndpoint("8.8.8.8", "dns.google"),
        )

        /**
         * Never resolve on clearnet (VPN-excluded UID). Placeholder keeps hostname
         * for Java SOCKS5 unresolved CONNECT (SOCKS5h → Tor exit resolve).
         */
        private object BootstrapTorSocksDns : Dns {
            override fun lookup(hostname: String): List<InetAddress> {
                val placeholder = InetAddress.getByAddress(hostname, byteArrayOf(0, 0, 0, 0))
                return listOf(placeholder)
            }
        }

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

        /** True when the first question is IN/A (TYPE=1). */
        internal fun isInetAQuery(query: ByteArray): Boolean {
            if (query.size < 16) return false
            var pos = 12
            while (pos < query.size) {
                val len = query[pos].toInt() and 0xff
                when {
                    len == 0 -> {
                        pos += 1
                        break
                    }
                    (len and 0xc0) == 0xc0 -> {
                        pos += 2
                        break
                    }
                    else -> {
                        pos += 1 + len
                        if (pos > query.size) return false
                    }
                }
            }
            if (pos + 4 > query.size) return false
            val qtype = ((query[pos].toInt() and 0xff) shl 8) or (query[pos + 1].toInt() and 0xff)
            val qclass = ((query[pos + 2].toInt() and 0xff) shl 8) or (query[pos + 3].toInt() and 0xff)
            return qtype == 1 && qclass == 1
        }

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
