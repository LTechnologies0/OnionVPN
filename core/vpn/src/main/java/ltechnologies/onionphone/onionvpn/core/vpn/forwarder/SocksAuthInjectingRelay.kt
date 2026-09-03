package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import timber.log.Timber

/**
 * SOCKS5 terminating relay for OpenVPN → Arti:
 *
 * - Downstream OpenVPN: **NO AUTH (0x00)** — ics-openvpn 2.7 cannot speak RFC1929
 *   USERNAME/PASSWORD correctly (expects VER=5).
 * - Downstream Java [Socks5Client.probeAuth]: **USERNAME/PASSWORD (0x02)** with
 *   IsolateSOCKSAuth tokens (auth-only, no CONNECT).
 * - Upstream (Arti): always CONNECT with [TunnelEndpoints.SOCKS_OPENVPN_*].
 * - Then bidirectional pipe of the OpenVPN TLS/control stream.
 *
 * DNSCrypt / probe role ports stay on [SocksTcpRelay] (clients already authenticate).
 */
class SocksAuthInjectingRelay(
    val listenPort: Int,
    private val upstreamHost: String,
    upstreamPort: Int,
    private val label: String = "openvpn-auth",
    private val username: String = TunnelEndpoints.SOCKS_OPENVPN_USER,
    private val password: String = TunnelEndpoints.SOCKS_OPENVPN_PASS,
    private val acceptPeer: ((Socket) -> Boolean)? = null,
    private val connectTimeoutMs: Int = CONNECT_TIMEOUT_MS,
    private val handshakeTimeoutMs: Int = HANDSHAKE_TIMEOUT_MS,
) {
    enum class Method { NO_AUTH, USER_PASS }

    private val upstreamPort = java.util.concurrent.atomic.AtomicInteger(upstreamPort)
    private val running = AtomicBoolean(false)
    private var server: ServerSocket? = null
    private var acceptExecutor: ThreadPoolExecutor? = null
    private var sessionExecutor: ThreadPoolExecutor? = null
    private var pipeExecutor: ThreadPoolExecutor? = null

    fun updateUpstream(port: Int) {
        upstreamPort.set(port.coerceAtLeast(0))
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(
            InetSocketAddress(
                InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                listenPort,
            ),
        )
        server = ss
        val accept = newAcceptExecutor()
        val sessions = newSessionExecutor()
        val pipe = newPipeExecutor()
        acceptExecutor = accept
        sessionExecutor = sessions
        pipeExecutor = pipe
        accept.execute {
            Timber.i(
                "SocksAuthInjectingRelay[$label] listen=$listenPort → " +
                    "$upstreamHost:${upstreamPort.get()} (NO-AUTH|USERPASS→user=$username)",
            )
            while (running.get()) {
                val client = try {
                    ss.accept()
                } catch (_: IOException) {
                    break
                }
                if (acceptPeer?.invoke(client) == false) {
                    Timber.d("SocksAuthInjectingRelay[$label] reject untrusted peer")
                    runCatching { client.close() }
                    continue
                }
                try {
                    sessions.execute { handle(client, pipe) }
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
        sessionExecutor?.shutdownNow()
        pipeExecutor?.shutdownNow()
        acceptExecutor = null
        sessionExecutor = null
        pipeExecutor = null
        Timber.i("SocksAuthInjectingRelay[$label] stopped")
    }

    private fun handle(client: Socket, pipe: ThreadPoolExecutor) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = handshakeTimeoutMs
            val clientIn = DataInputStream(client.getInputStream())
            val clientOut = DataOutputStream(client.getOutputStream())

            when (negotiateMethod(clientIn, clientOut)) {
                Method.USER_PASS -> {
                    acceptUsernamePassword(clientIn, clientOut, username, password)
                    // Auth probe closes after USER/PASS — wait briefly for CONNECT.
                    client.soTimeout = POST_AUTH_CONNECT_WAIT_MS
                    val destOrNull = try {
                        readConnectRequest(clientIn)
                    } catch (_: IOException) {
                        null
                    }
                    if (destOrNull == null) {
                        Timber.d("SocksAuthInjectingRelay[$label] auth probe ok (no CONNECT)")
                        return
                    }
                    client.soTimeout = handshakeTimeoutMs
                    pipeViaUpstream(client, clientOut, destOrNull, pipe)
                }
                Method.NO_AUTH -> {
                    val dest = readConnectRequest(clientIn)
                    pipeViaUpstream(client, clientOut, dest, pipe)
                }
            }
        } catch (error: Exception) {
            Timber.d(error, "SocksAuthInjectingRelay[$label] session end")
        } finally {
            runCatching { client.close() }
        }
    }

    private fun pipeViaUpstream(
        client: Socket,
        clientOut: DataOutputStream,
        dest: Dest,
        pipe: ThreadPoolExecutor,
    ) {
        var upstream: Socket? = null
        try {
            val up = try {
                Socks5Client(
                    proxyHost = upstreamHost,
                    proxyPort = upstreamPort.get(),
                    username = username,
                    password = password,
                    connectTimeoutMs = connectTimeoutMs,
                    handshakeTimeoutMs = handshakeTimeoutMs,
                ).connect(dest.host, dest.port)
            } catch (upstreamError: Exception) {
                clientOut.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                clientOut.flush()
                throw upstreamError
            }
            upstream = up

            client.soTimeout = 0
            up.soTimeout = 0

            clientOut.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
            clientOut.flush()

            val c2u = pipe.submit { copy(client, up) }
            val u2c = pipe.submit { copy(up, client) }
            c2u.get()
            u2c.get()
        } finally {
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
            { r -> Thread(r, "onionvpn-socks-auth-$label").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )

    private fun newSessionExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            2,
            MAX_SESSION_THREADS,
            60L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(64),
            { r -> Thread(r, "onionvpn-socks-auth-session-$label").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    private fun newPipeExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            2,
            MAX_PIPE_THREADS,
            60L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(32),
            { r -> Thread(r, "onionvpn-socks-auth-pipe-$label").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val HANDSHAKE_TIMEOUT_MS = 120_000
        private const val MAX_SESSION_THREADS = 16
        private const val MAX_PIPE_THREADS = 32
        private const val POST_AUTH_CONNECT_WAIT_MS = 500

        data class Dest(val host: String, val port: Int)

        /**
         * Prefer NO AUTH (OpenVPN); else USER/PASS (Java auth probe).
         * Exposed for unit tests.
         */
        fun negotiateMethod(input: DataInputStream, output: DataOutputStream): Method {
            val ver = input.readUnsignedByte()
            if (ver != 0x05) throw IOException("SOCKS greeting ver=$ver")
            val nMethods = input.readUnsignedByte()
            if (nMethods < 1 || nMethods > 255) {
                throw IOException("SOCKS bad nmethods=$nMethods")
            }
            var offersNoAuth = false
            var offersUserPass = false
            repeat(nMethods) {
                when (input.readUnsignedByte()) {
                    0x00 -> offersNoAuth = true
                    0x02 -> offersUserPass = true
                }
            }
            return when {
                offersNoAuth -> {
                    output.write(byteArrayOf(0x05, 0x00))
                    output.flush()
                    Method.NO_AUTH
                }
                offersUserPass -> {
                    output.write(byteArrayOf(0x05, 0x02))
                    output.flush()
                    Method.USER_PASS
                }
                else -> {
                    output.write(byteArrayOf(0x05, 0xFF.toByte()))
                    output.flush()
                    throw IOException("SOCKS client offered neither NO AUTH nor USER/PASS")
                }
            }
        }

        fun acceptUsernamePassword(
            input: DataInputStream,
            output: DataOutputStream,
            expectedUser: String = TunnelEndpoints.SOCKS_OPENVPN_USER,
            expectedPass: String = TunnelEndpoints.SOCKS_OPENVPN_PASS,
        ) {
            val authVer = input.readUnsignedByte()
            if (authVer != 0x01) throw IOException("SOCKS auth ver=$authVer")
            val uLen = input.readUnsignedByte()
            val user = ByteArray(uLen).also { input.readFully(it) }
                .toString(StandardCharsets.UTF_8)
            val pLen = input.readUnsignedByte()
            val pass = ByteArray(pLen).also { input.readFully(it) }
                .toString(StandardCharsets.UTF_8)
            val ok = user == expectedUser && pass == expectedPass
            output.write(byteArrayOf(0x01, if (ok) 0x00 else 0x01))
            output.flush()
            if (!ok) throw IOException("SOCKS username/password rejected")
        }

        fun readConnectRequest(input: DataInputStream): Dest {
            val reqVer = input.readUnsignedByte()
            val cmd = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()
            if (reqVer != 0x05 || cmd != 0x01) {
                throw IOException("SOCKS unsupported request ver=$reqVer cmd=$cmd")
            }
            val host = when (atyp) {
                0x01 -> {
                    val raw = ByteArray(4)
                    input.readFully(raw)
                    InetAddress.getByAddress(raw).hostAddress
                        ?: throw IOException("SOCKS IPv4 parse failed")
                }
                0x03 -> {
                    val n = input.readUnsignedByte()
                    val raw = ByteArray(n)
                    input.readFully(raw)
                    String(raw, StandardCharsets.UTF_8)
                }
                0x04 -> {
                    val raw = ByteArray(16)
                    input.readFully(raw)
                    InetAddress.getByAddress(raw).hostAddress
                        ?: throw IOException("SOCKS IPv6 parse failed")
                }
                else -> throw IOException("SOCKS bad atyp=$atyp")
            }
            val port = input.readUnsignedShort()
            if (!TorNetPolicy.isValidSocksDestination(host) || !TorNetPolicy.isValidPort(port)) {
                throw IOException("SOCKS invalid destination $host:$port")
            }
            return Dest(host, port)
        }

        /** Full NO-AUTH + CONNECT for unit tests. */
        fun acceptNoAuthConnect(
            input: DataInputStream,
            output: DataOutputStream,
        ): Dest {
            val method = negotiateMethod(input, output)
            if (method != Method.NO_AUTH) {
                throw IOException("expected NO AUTH, got $method")
            }
            return readConnectRequest(input)
        }
    }
}
