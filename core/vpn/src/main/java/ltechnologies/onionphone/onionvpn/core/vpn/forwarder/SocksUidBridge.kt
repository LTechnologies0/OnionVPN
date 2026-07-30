package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.Process
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.LockSupport
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import timber.log.Timber

/**
 * Loopback SOCKS5 in front of Tor apps SocksPort:
 * hev (no per-stream auth) → this bridge → Tor with IsolateSOCKSAuth `u{uid}`/`p{uid}`.
 *
 * UID comes from [TcpFlowUidIndex] (TunDnsMux SYN stamp). Automap virtual IPs are
 * remapped to `.onion`/`.exit` hostnames via [DnsHostnameCache] for SOCKS5A.
 */
class SocksUidBridge(
    context: Context,
    private val listenPort: Int = TunnelEndpoints.SOCKS_UID_BRIDGE_PORT,
    private val protectSocket: ((Socket) -> Boolean)? = null,
    private val onFatal: ((Throwable) -> Unit)? = null,
) {
    private val ownerResolver = ConnectionOwnerResolver(context)
    private val running = AtomicBoolean(false)
    private val torSocksPort = AtomicInteger(0)
    private val serverRef = AtomicReference<ServerSocket?>(null)
    private var acceptThread: Thread? = null
    private var clientExecutor = newClientExecutor()
    private val denyLogSample = AtomicLong(0)

    val isRunning: Boolean get() = running.get()
    val boundPort: Int get() = listenPort

    fun updateTorSocks(port: Int) {
        torSocksPort.set(port.coerceAtLeast(0))
        Timber.i("SocksUidBridge upstream Tor SOCKS :%d listen=:%d", torSocksPort.get(), listenPort)
    }

    fun start(torSocks: Int) {
        updateTorSocks(torSocks)
        if (!running.compareAndSet(false, true)) return
        if (clientExecutor.isShutdown || clientExecutor.isTerminated) {
            clientExecutor = newClientExecutor()
        }
        TcpFlowUidIndex.clear()
        val server = try {
            ServerSocket(listenPort, 64, InetAddress.getByName(TunnelEndpoints.LOOPBACK))
        } catch (e: Exception) {
            running.set(false)
            Timber.e(e, "SocksUidBridge bind failed :$listenPort")
            onFatal?.invoke(e)
            throw e
        }
        serverRef.set(server)
        acceptThread = Thread({
            Timber.i(
                "SocksUidBridge listening socks5://%s:%d → Tor :%d",
                TunnelEndpoints.LOOPBACK,
                listenPort,
                torSocksPort.get(),
            )
            while (running.get()) {
                try {
                    val client = server.accept()
                    try {
                        clientExecutor.execute { handleClient(client) }
                    } catch (_: java.util.concurrent.RejectedExecutionException) {
                        runCatching { client.close() }
                    }
                } catch (_: SocketException) {
                    if (!running.get()) break
                } catch (e: Exception) {
                    if (running.get()) VpnForwarderDebug.socksLog(e) { "SocksUidBridge accept error" }
                }
            }
        }, "onionvpn-uid-socks-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        updateTorSocks(0)
        runCatching { serverRef.getAndSet(null)?.close() }
        acceptThread?.interrupt()
        acceptThread = null
        clientExecutor.shutdownNow()
        TcpFlowUidIndex.clear()
        Timber.i("SocksUidBridge stopped")
    }

    private fun handleClient(client: Socket) {
        client.use { c ->
            c.soTimeout = 60_000
            c.tcpNoDelay = true
            val input = DataInputStream(c.getInputStream())
            val output = DataOutputStream(c.getOutputStream())
            try {
                negotiateNoAuth(input, output)
                val (host, port) = readConnect(input, output) ?: return
                val uid = resolveUidForConnect(host, port)
                if (!ConnectionOwnerResolver.isValidUid(uid)) {
                    if ((denyLogSample.incrementAndGet() and 0x3F) == 0L) {
                        VpnForwarderDebug.socksLog {
                            "SocksUidBridge deny — no UID for $host:$port"
                        }
                    }
                    reply(output, 0x02) // not allowed
                    return
                }
                val torPort = torSocksPort.get()
                if (torPort <= 0) {
                    reply(output, 0x01)
                    return
                }
                val socksHost = rewriteAutomapHost(host) ?: run {
                    VpnForwarderDebug.socksLog { "SocksUidBridge drop Automap IP without hostname $host" }
                    reply(output, 0x04)
                    return
                }
                val user = TunnelEndpoints.socksUserForUid(uid)
                val pass = TunnelEndpoints.socksPassForUid(uid)
                val upstream = Socks5Client(
                    proxyHost = TunnelEndpoints.LOOPBACK,
                    proxyPort = torPort,
                    username = user,
                    password = pass,
                    protect = protectSocket,
                ).connect(socksHost, port)
                reply(output, 0x00)
                VpnForwarderDebug.socksLog { "SocksUidBridge uid=$uid $user → $socksHost:$port" }
                pipe(c, upstream)
            } catch (e: Exception) {
                VpnForwarderDebug.socksLog(e) { "SocksUidBridge client failed" }
                runCatching { reply(output, 0x01) }
            }
        }
    }

    private fun resolveUidForConnect(host: String, port: Int): Int {
        // Peek (non-consuming): parallel streams to the same dest must not steal the stamp.
        TcpFlowUidIndex.peekIpv4Host(host, port)?.uid?.let { return it }
        // Retry: SYN stamp may race hev's SOCKS open under load.
        repeat(UID_RETRY) {
            LockSupport.parkNanos(UID_PARK_NS)
            TcpFlowUidIndex.peekIpv4Host(host, port)?.uid?.let { return it }
        }
        return Process.INVALID_UID
    }

    private fun rewriteAutomapHost(host: String): String? {
        if (!TunnelEndpoints.isAutomapVirtualIpv4(host)) return host
        val name = DnsHostnameCache.lookup(host) ?: return null
        return if (TunnelEndpoints.isOnionLikeHostname(name)) name else null
    }

    private fun negotiateNoAuth(input: DataInputStream, output: DataOutputStream) {
        val ver = input.readUnsignedByte()
        if (ver != 0x05) throw IOException("not SOCKS5")
        val nMethods = input.readUnsignedByte()
        input.skipBytes(nMethods)
        output.writeByte(0x05)
        output.writeByte(0x00) // NO AUTH — hev has no per-stream credentials
        output.flush()
    }

    private fun readConnect(
        input: DataInputStream,
        output: DataOutputStream,
    ): Pair<String, Int>? {
        val reqVer = input.readUnsignedByte()
        val cmd = input.readUnsignedByte()
        input.readUnsignedByte()
        val atyp = input.readUnsignedByte()
        if (reqVer != 0x05 || cmd != 0x01) {
            reply(output, 0x07)
            return null
        }
        val host = when (atyp) {
            0x01 -> {
                val b = ipv4Scratch.get()
                input.readFully(b)
                InetAddress.getByAddress(b).hostAddress ?: "0.0.0.0"
            }
            0x03 -> {
                val n = input.readUnsignedByte()
                val b = ByteArray(n)
                input.readFully(b)
                String(b, StandardCharsets.US_ASCII)
            }
            0x04 -> {
                input.skipBytes(16)
                reply(output, 0x08) // address type not supported (IPv6 blackhole policy)
                return null
            }
            else -> {
                reply(output, 0x08)
                return null
            }
        }
        val port = input.readUnsignedShort()
        return host to port
    }

    private fun reply(output: DataOutputStream, status: Int) {
        output.writeByte(0x05)
        output.writeByte(status)
        output.writeByte(0x00)
        output.writeByte(0x01)
        output.write(replyAddrScratch.get())
        output.writeShort(0)
        output.flush()
    }

    private fun pipe(a: Socket, b: Socket) {
        b.tcpNoDelay = true
        val t = Thread({
            try {
                a.getInputStream().copyTo(b.getOutputStream())
            } catch (_: Exception) {
            } finally {
                runCatching { b.shutdownOutput() }
                runCatching { a.close() }
                runCatching { b.close() }
            }
        }, "onionvpn-uid-pipe")
        t.isDaemon = true
        t.start()
        try {
            b.getInputStream().copyTo(a.getOutputStream())
        } catch (_: Exception) {
        } finally {
            runCatching { a.shutdownOutput() }
            runCatching { b.close() }
            runCatching { a.close() }
        }
        t.join(5_000)
    }

    private fun newClientExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            0,
            96,
            60L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(512),
            { r -> Thread(r, "onionvpn-uid-socks").apply { isDaemon = true } },
            // Never run handleClient on accept thread (would stall accept under load).
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    companion object {
        private const val UID_RETRY = 5
        private const val UID_PARK_NS = 3_000_000L // 3ms × 5 ≈ 15ms race window
        private val ipv4Scratch = ThreadLocal.withInitial { ByteArray(4) }
        private val replyAddrScratch = ThreadLocal.withInitial { ByteArray(4) }
    }
}
