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
import java.util.concurrent.Semaphore
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.LockSupport
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.observability.MemoryHygiene
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import timber.log.Timber

/**
 * Loopback SOCKS5 in front of Tor apps SocksPort:
 * hev (no per-stream auth) → this bridge → Tor with IsolateSOCKSAuth `u{uid}`/`p{uid}`.
 *
 * UID comes from [TcpFlowUidIndex] (TunDnsMux SYN stamp). Automap virtual IPs are
 * remapped to `.onion`/`.exit` hostnames via [DnsHostnameCache] for SOCKS5A.
 *
 * Handshake workers return immediately after CONNECT succeeds; bidirectional pipes run
 * on a separate cached pool so Signal reconnect storms cannot pin all handshake threads
 * for the lifetime of each TCP flow (that left ESTAB sockets with Recv-Q=3 unread).
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
    private var pipeExecutor = newPipeExecutor()
    /** Cap in-flight Tor CONNECT handshakes so cold exits don't pile forever. */
    private val torConnectSlots = Semaphore(MAX_INFLIGHT_CONNECT)
    private val denyLogSample = AtomicLong(0)
    private val pipeSlots = Semaphore(MAX_PIPE_HALF_SLOTS)

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
        if (pipeExecutor.isShutdown || pipeExecutor.isTerminated) {
            pipeExecutor = newPipeExecutor()
        }
        TcpFlowUidIndex.clear()
        val server = try {
            // Larger backlog: Signal reconnect storms open many SYN before workers drain.
            ServerSocket(listenPort, 256, InetAddress.getByName(TunnelEndpoints.LOOPBACK))
        } catch (e: Exception) {
            running.set(false)
            Timber.e(e, "SocksUidBridge bind failed :$listenPort")
            onFatal?.invoke(e)
            throw e
        }
        serverRef.set(server)
        val acceptServer = server
        acceptThread = Thread({
            Timber.i(
                "SocksUidBridge listening socks5://%s:%d → Tor :%d",
                TunnelEndpoints.LOOPBACK,
                listenPort,
                torSocksPort.get(),
            )
            // Lifetime pinned to this ServerSocket — never spin after stop()/restart.
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
                    if (!acceptServer.isClosed) {
                        VpnForwarderDebug.socksLog(e) { "SocksUidBridge accept error" }
                    }
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
        acceptThread?.let { t ->
            t.interrupt()
            runCatching { t.join(2_000L) }
        }
        acceptThread = null
        clientExecutor.shutdownNow()
        pipeExecutor.shutdownNow()
        runCatching { clientExecutor.awaitTermination(2, TimeUnit.SECONDS) }
        runCatching { pipeExecutor.awaitTermination(2, TimeUnit.SECONDS) }
        TcpFlowUidIndex.clear()
        Timber.i("SocksUidBridge stopped")
        MemoryHygiene.afterHeavyWork("socks_uid_bridge_stop")
    }

    private fun handleClient(client: Socket) {
        var handedOff = false
        try {
            client.soTimeout = 15_000
            client.tcpNoDelay = true
            val input = DataInputStream(client.getInputStream())
            val output = DataOutputStream(client.getOutputStream())
            try {
                negotiateNoAuth(input, output)
                val (host, port) = readConnect(input, output) ?: return
                val uid = resolveUidForConnect(host, port)
                if (!ConnectionOwnerResolver.isValidUid(uid)) {
                    // Fail-closed: never merge distinct apps into FALLBACK IsolateSOCKSAuth.
                    if ((denyLogSample.incrementAndGet() and 0x1F) == 0L) {
                        VpnForwarderDebug.socksLog {
                            "SocksUidBridge UID miss $host:$port — refuse CONNECT"
                        }
                    }
                    reply(output, 0x01)
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
                if (!torConnectSlots.tryAcquire()) {
                    VpnForwarderDebug.socksLog {
                        "SocksUidBridge CONNECT backlog full — reject $socksHost:$port"
                    }
                    reply(output, 0x01)
                    return
                }
                // Reserve pipe threads BEFORE Tor CONNECT + SOCKS success — otherwise we
                // reply 0x00 to hev, then fail startPipe and RST mid-TLS (Speedtest SSL timeout).
                if (!pipeSlots.tryAcquire(2)) {
                    torConnectSlots.release()
                    VpnForwarderDebug.socksLog { "SocksUidBridge pipe pool full — reject $socksHost:$port" }
                    reply(output, 0x01)
                    return
                }
                val upstream = try {
                    try {
                        Socks5Client(
                            proxyHost = TunnelEndpoints.LOOPBACK,
                            proxyPort = torPort,
                            username = user,
                            password = pass,
                            // Signal aborts TLS long before Tor's 120s SocksTimeout; free workers.
                            handshakeTimeoutMs = BRIDGE_HANDSHAKE_MS,
                            protect = protectSocket,
                        ).connect(socksHost, port)
                    } finally {
                        torConnectSlots.release()
                    }
                } catch (e: Exception) {
                    pipeSlots.release(2)
                    throw e
                }
                // Clear read deadline for the bidirectional pipe (Tor cells can idle >60s).
                client.soTimeout = 0
                upstream.soTimeout = 0
                // SOCKS success MUST be fully written before any pipe thread touches
                // client.getOutputStream() — otherwise Tor→client bytes race the reply
                // and hev treats TLS as a broken SOCKS header (Speedtest read/SSL timeouts).
                reply(output, 0x00)
                Timber.i("SocksUidBridge uid=%d %s → %s:%d", uid, user, socksHost, port)
                if (!startPipe(client, upstream, slotsAcquired = true)) {
                    runCatching { upstream.close() }
                    return
                }
                handedOff = true
            } catch (e: Exception) {
                // hev/Happy Eyeballs cancels racing sockets mid-greeting — not a bridge failure.
                if (!isBenignClientAbort(e)) {
                    VpnForwarderDebug.socksLog(e) { "SocksUidBridge client failed" }
                    runCatching { reply(output, 0x01) }
                }
            }
        } finally {
            if (!handedOff) {
                runCatching { client.close() }
            }
        }
    }

    /** Client closed before SOCKS CONNECT completed (race cancel, app kill, RST). */
    private fun isBenignClientAbort(e: Throwable): Boolean {
        var cur: Throwable? = e
        while (cur != null) {
            when (cur) {
                is java.io.EOFException -> return true
                is SocketException -> {
                    val m = cur.message?.lowercase().orEmpty()
                    if (m.contains("reset") || m.contains("broken pipe") ||
                        m.contains("closed") || m.contains("connection abort")
                    ) {
                        return true
                    }
                }
                is java.net.SocketTimeoutException -> return true
            }
            cur = cur.cause
        }
        return false
    }

    private fun resolveUidForConnect(host: String, port: Int): Int {
        // Peek (non-consuming): parallel streams to the same dest must not steal the stamp.
        TcpFlowUidIndex.peekHost(host, port)?.uid?.let { uid ->
            if (ConnectionOwnerResolver.isValidUid(uid)) return uid
        }
        // Retry: SYN stamp may race hev's SOCKS open (async owner-uid resolve).
        repeat(UID_RETRY) {
            LockSupport.parkNanos(UID_PARK_NS)
            TcpFlowUidIndex.peekHost(host, port)?.uid?.let { uid ->
                if (ConnectionOwnerResolver.isValidUid(uid)) return uid
            }
        }
        return Process.INVALID_UID
    }

    /**
     * Automap virtual IP → `.onion`/`.exit` SOCKS5A hostname.
     *
     * Clearnet: pin to DNSCrypt **IPv4** (never SOCKS5A-rewrite IP→hostname). Exit-side
     * re-resolve of hostnames was picking AAAA paths and stalling OkHttp TLS (Speedtest
     * RetrieveServerListTask / SSL handshake timed out) even after PreferIPv6 was removed.
     */
    private fun rewriteAutomapHost(host: String): String? {
        if (TunnelEndpoints.isAutomapVirtual(host)) {
            DnsHostnameCache.lookup(host)?.let { name ->
                if (TunnelEndpoints.isOnionLikeHostname(name)) return name
            }
            repeat(AUTOMAP_RETRY) {
                LockSupport.parkNanos(AUTOMAP_PARK_NS)
                DnsHostnameCache.lookup(host)?.let { name ->
                    if (TunnelEndpoints.isOnionLikeHostname(name)) return name
                }
            }
            return null
        }
        // Already an IPv4 literal from hev — keep it (DNSCrypt A-only path).
        if (TunnelEndpoints.parseIpv4Literal(host) != null) return host
        // Clearnet IPv6 literal: prefer cached IPv4 for the same name (Happy Eyeballs).
        if (host.indexOf(':') >= 0) {
            DnsHostnameCache.lookup(host)?.let { name ->
                DnsHostnameCache.ipv4ForHostname(name)?.let { return it }
            }
            return host
        }
        // Hostname CONNECT — pin to torrified A-record when known.
        DnsHostnameCache.ipv4ForHostname(host)?.let { return it }
        repeat(DNS_REWRITE_RETRY) {
            LockSupport.parkNanos(DNS_REWRITE_PARK_NS)
            DnsHostnameCache.ipv4ForHostname(host)?.let { return it }
        }
        return host
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
        // Always drain DST.ADDR+PORT before reject replies (SOCKS5 framing).
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
                val b = ByteArray(16)
                input.readFully(b)
                InetAddress.getByAddress(b).hostAddress?.substringBefore('%')
                    ?: throw IOException("bad IPv6")
            }
            else -> {
                reply(output, 0x08)
                return null
            }
        }
        val port = input.readUnsignedShort()
        if (reqVer != 0x05 || cmd != 0x01) {
            runCatching { reply(output, 0x07) }
            return null
        }
        if (!TorNetPolicy.isValidSocksDestination(host) || !TorNetPolicy.isValidPort(port)) {
            runCatching { reply(output, 0x01) }
            return null
        }
        // Never SOCKS-CONNECT Automap/literal into clearnet — rewrite or refuse.
        val ipv4 = TunnelEndpoints.parseIpv4Literal(host)
        if (ipv4 != null && TorNetPolicy.mustBlackholeIpv4Destination(ipv4)) {
            runCatching { reply(output, 0x02) }
            return null
        }
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

    /**
     * @param slotsAcquired when true, caller already holds 2 [pipeSlots] (must release on failure).
     * @return false if pipe pool saturated / reject (caller closes sockets).
     */
    private fun startPipe(
        client: Socket,
        upstream: Socket,
        slotsAcquired: Boolean = false,
    ): Boolean {
        upstream.tcpNoDelay = true
        client.tcpNoDelay = true
        if (!slotsAcquired && !pipeSlots.tryAcquire(2)) {
            VpnForwarderDebug.socksLog { "SocksUidBridge pipe pool full — drop CONNECT" }
            return false
        }
        val closed = AtomicBoolean(false)
        fun closeBoth() {
            if (!closed.compareAndSet(false, true)) return
            runCatching { client.shutdownOutput() }
            runCatching { upstream.shutdownOutput() }
            runCatching { client.close() }
            runCatching { upstream.close() }
        }
        val pipeStartedAt = System.nanoTime()
        try {
            // Two directions on the pipe pool — handshake worker returns immediately.
            pipeExecutor.execute {
                try {
                    copyStream(
                        client.getInputStream(),
                        upstream.getOutputStream(),
                        label = "c→t",
                        startedAtNs = pipeStartedAt,
                    )
                    runCatching { upstream.shutdownOutput() }
                } catch (_: Exception) {
                } finally {
                    closeBoth()
                    pipeSlots.release()
                }
            }
            pipeExecutor.execute {
                try {
                    copyStream(
                        upstream.getInputStream(),
                        client.getOutputStream(),
                        label = "t→c",
                        startedAtNs = pipeStartedAt,
                    )
                    runCatching { client.shutdownOutput() }
                } catch (_: Exception) {
                } finally {
                    closeBoth()
                    pipeSlots.release()
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            pipeSlots.release(2)
            closeBoth()
            return false
        }
        return true
    }

    /** Larger than InputStream.copyTo's 8 KiB default — less syscall churn under Tor cell rates. */
    private fun copyStream(
        input: java.io.InputStream,
        output: java.io.OutputStream,
        label: String = "",
        startedAtNs: Long = 0L,
    ) {
        val buf = ByteArray(PIPE_BUF)
        var first = true
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (n == 0) continue
            output.write(buf, 0, n)
            // Flush every chunk — TLS ClientHello/ServerHello must not sit in DOS/Nagle.
            output.flush()
            if (first) {
                first = false
                if (label.isNotEmpty() && startedAtNs > 0L) {
                    val ms = (System.nanoTime() - startedAtNs) / 1_000_000L
                    Timber.i("SocksUidBridge pipe first-byte %s %dB +%dms", label, n, ms)
                }
            }
        }
        output.flush()
    }

    /** Handshake-only pool: must not stay busy for the lifetime of TCP pipes. */
    private fun newClientExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            4,
            64,
            60L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(64),
            { r -> Thread(r, "onionvpn-uid-socks").apply { isDaemon = true } },
            // Never run handleClient on accept thread (would stall accept under load).
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    /**
     * Pipe pool — must scale on burst (Speedtest download opens many :8080 streams).
     * A small bounded queue left copy tasks queued for seconds while ClientHello sat in
     * the socket → Ookla "Hello handshake failed" / Download stage ERROR.
     * SynchronousQueue + high max creates threads immediately up to [MAX_PIPE_THREADS].
     */
    private fun newPipeExecutor(): ThreadPoolExecutor =
        ThreadPoolExecutor(
            16,
            MAX_PIPE_THREADS,
            60L,
            TimeUnit.SECONDS,
            java.util.concurrent.SynchronousQueue(),
            { r -> Thread(r, "onionvpn-uid-pipe").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        ).apply { allowCoreThreadTimeOut(true) }

    companion object {
        private const val UID_RETRY = 24
        private const val UID_PARK_NS = 5_000_000L // 5ms × 24 ≈ 120ms then refuse
        private const val AUTOMAP_RETRY = 40
        private const val AUTOMAP_PARK_NS = 5_000_000L // 5ms × 40 ≈ 200ms DNS→cache race
        /** Clearnet IP→hostname: DNSCrypt reply often races hev SOCKS open (~50–100ms). */
        private const val DNS_REWRITE_RETRY = 24
        private const val DNS_REWRITE_PARK_NS = 5_000_000L // 5ms × 24 ≈ 120ms
        private const val PIPE_BUF = 64 * 1024
        private const val MAX_INFLIGHT_CONNECT = 96
        /** One thread per pipe half; Speedtest download alone can want 8–16×2 streams. */
        private const val MAX_PIPE_THREADS = 256
        /** Two slots per CONNECT (each direction). */
        private const val MAX_PIPE_HALF_SLOTS = 512
        /** Match C Tor SocksTimeout (120s) — Arti cold circuits regularly exceed 25s. */
        private const val BRIDGE_HANDSHAKE_MS = 120_000
        private val ipv4Scratch = ThreadLocal.withInitial { ByteArray(4) }
        private val replyAddrScratch = ThreadLocal.withInitial { ByteArray(4) }
    }
}
