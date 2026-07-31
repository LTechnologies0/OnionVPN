package ltechnologies.onionphone.onionvpn.core.vpn.pac

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.Socks5Client
import timber.log.Timber

/**
 * Loopback SOCKS5 bridge for PAC clients:
 * 1. Accept CONNECT (hostname or IPv4)
 * 2. Resolve hostnames via **DNSCrypt** (not Tor DNSPort / exit DNS)
 * 3. CONNECT by IP through Tor apps SocksPort
 *
 * Chrome/Edge always do SOCKS remote DNS against whatever SOCKS they dial —
 * pointing PAC at raw Tor SOCKS would use Tor DNS. This bridge fixes that.
 *
 * `.onion` hostnames skip DNSCrypt and are passed to Tor as SOCKS5 hostname.
 */
class DnsCryptSocksBridge(
    private val listenPort: Int = TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT,
) {
    private val running = AtomicBoolean(false)
    private val torSocksPort = AtomicInteger(0)
    private val dnsCryptPort = AtomicInteger(0)
    private val serverRef = AtomicReference<ServerSocket?>(null)
    private var acceptThread: Thread? = null

    fun updateUpstream(torSocks: Int, dnsCrypt: Int) {
        torSocksPort.set(torSocks.coerceAtLeast(0))
        dnsCryptPort.set(dnsCrypt.coerceAtLeast(0))
        Timber.i(
            "PAC DNSCrypt→Tor bridge upstream torSocks=%d dnsCrypt=%d listen=%d",
            torSocksPort.get(),
            dnsCryptPort.get(),
            listenPort,
        )
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val server = try {
            ServerSocket(listenPort, 32, InetAddress.getByName(TunnelEndpoints.LOOPBACK))
        } catch (e: Exception) {
            running.set(false)
            Timber.e(e, "PAC SOCKS bridge bind failed :$listenPort")
            throw e
        }
        serverRef.set(server)
        acceptThread = Thread({
            Timber.i(
                "PAC SOCKS bridge listening socks5://%s:%d (DNS via DNSCrypt)",
                TunnelEndpoints.LOOPBACK,
                listenPort,
            )
            while (running.get()) {
                try {
                    val client = server.accept()
                    Thread({ handleClient(client) }, "onionvpn-pac-socks").apply {
                        isDaemon = true
                        start()
                    }
                } catch (_: SocketException) {
                    if (!running.get()) break
                } catch (e: Exception) {
                    if (running.get()) Timber.d(e, "PAC SOCKS accept error")
                }
            }
        }, "onionvpn-pac-socks-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        updateUpstream(0, 0)
        runCatching { serverRef.getAndSet(null)?.close() }
        acceptThread?.interrupt()
        acceptThread = null
        Timber.i("PAC SOCKS bridge stopped")
    }

    private fun handleClient(client: Socket) {
        client.use { c ->
            c.soTimeout = 30_000
            c.tcpNoDelay = true
            val input = DataInputStream(c.getInputStream())
            val output = DataOutputStream(c.getOutputStream())
            try {
                // Greeting
                val ver = input.readUnsignedByte()
                if (ver != 0x05) throw IOException("not SOCKS5")
                val nMethods = input.readUnsignedByte()
                input.skipBytes(nMethods)
                // No auth — PAC clients rarely send IsolateSOCKSAuth credentials.
                output.writeByte(0x05)
                output.writeByte(0x00)
                output.flush()

                val reqVer = input.readUnsignedByte()
                val cmd = input.readUnsignedByte()
                input.readUnsignedByte() // rsv
                val atyp = input.readUnsignedByte()
                // Drain DST.ADDR+PORT before any reply — Chrome UDP ASSOCIATE probes
                // leave those bytes queued; answering early desyncs and resets the socket.
                val dest = try {
                    readAddress(input, atyp)
                } catch (_: Exception) {
                    safeReply(output, REP_ATYP_NOT_SUPPORTED)
                    return
                }
                if (reqVer != 0x05 || cmd != CMD_CONNECT) {
                    // BIND / UDP ASSOCIATE unsupported (TCP-only Tor path).
                    Timber.v("PAC SOCKS reject cmd=0x%02x (CONNECT only)", cmd)
                    safeReply(output, REP_COMMAND_NOT_SUPPORTED)
                    return
                }
                val (host, port) = dest
                val torPort = torSocksPort.get()
                val dnsPort = dnsCryptPort.get()
                if (torPort <= 0 || dnsPort <= 0) {
                    safeReply(output, REP_GENERAL_FAILURE)
                    return
                }

                val clientUid = resolveClientUid(c)
                val (socksUser, socksPass) = pacSocksAuth(clientUid)
                val resolvedIp: String
                val remote: Socket = if (TunnelEndpoints.isOnionLikeHostname(host)) {
                    resolvedIp = ""
                    if (!FirewallBridge.engine.allowSocksConnect(
                            uid = clientUid,
                            destHost = host,
                            destIp = "",
                            destPort = port,
                        )
                    ) {
                        safeReply(output, REP_NOT_ALLOWED)
                        return
                    }
                    Socks5Client(
                        proxyHost = TunnelEndpoints.LOOPBACK,
                        proxyPort = torPort,
                        username = socksUser,
                        password = socksPass,
                    ).connect(host, port)
                } else {
                    val connectHost = when (atyp) {
                        ATYP_IPV4, ATYP_IPV6 -> host
                        else -> {
                            val ip = DnsCryptResolver.resolveIpv4(
                                hostname = host,
                                dnsCryptHost = TunnelEndpoints.LOOPBACK,
                                dnsCryptPort = dnsPort,
                            )
                            ip.hostAddress ?: ip.hostName
                        }
                    }
                    resolvedIp = connectHost
                    if (!FirewallBridge.engine.allowSocksConnect(
                            uid = clientUid,
                            destHost = host,
                            destIp = resolvedIp,
                            destPort = port,
                        )
                    ) {
                        safeReply(output, REP_NOT_ALLOWED)
                        return
                    }
                    Socks5Client(
                        proxyHost = TunnelEndpoints.LOOPBACK,
                        proxyPort = torPort,
                        username = socksUser,
                        password = socksPass,
                    ).connect(resolvedIp, port)
                }

                safeReply(output, REP_SUCCEEDED)
                c.soTimeout = 0
                remote.soTimeout = 0
                pipe(c, remote)
            } catch (e: Exception) {
                if (isBenignSessionEnd(e)) {
                    Timber.v("PAC SOCKS session end: %s", e.javaClass.simpleName)
                } else {
                    Timber.d(e, "PAC SOCKS bridge session failed")
                }
                safeReply(output, REP_GENERAL_FAILURE)
            }
        }
    }

    private fun readAddress(input: DataInputStream, atyp: Int): Pair<String, Int> {
        return when (atyp) {
            ATYP_IPV4 -> {
                val addr = ByteArray(4)
                input.readFully(addr)
                val port = input.readUnsignedShort()
                InetAddress.getByAddress(addr).hostAddress!! to port
            }
            ATYP_DOMAIN -> {
                val n = input.readUnsignedByte()
                val name = ByteArray(n)
                input.readFully(name)
                val port = input.readUnsignedShort()
                String(name, StandardCharsets.US_ASCII) to port
            }
            ATYP_IPV6 -> {
                val addr = ByteArray(16)
                input.readFully(addr)
                val port = input.readUnsignedShort()
                InetAddress.getByAddress(addr).hostAddress!!.substringBefore('%') to port
            }
            else -> throw IOException("bad atyp=$atyp")
        }
    }

    /** Best-effort SOCKS reply; ignores peer closes (Broken pipe / Connection reset). */
    private fun safeReply(output: DataOutputStream, status: Int) {
        try {
            reply(output, status, InetAddress.getByName("0.0.0.0"), 0)
        } catch (_: IOException) {
            // Client already gone — normal after UDP ASSOCIATE / abort probes.
        }
    }

    private fun reply(output: DataOutputStream, status: Int, bind: InetAddress, port: Int) {
        output.writeByte(0x05)
        output.writeByte(status)
        output.writeByte(0x00)
        val raw = bind.address
        if (raw.size == 4) {
            output.writeByte(ATYP_IPV4)
            output.write(raw)
        } else {
            output.writeByte(ATYP_IPV4)
            output.write(byteArrayOf(0, 0, 0, 0))
        }
        output.writeShort(port)
        output.flush()
    }

    /**
     * Probes / browsers often open SOCKS then hang up, or race DNSCrypt before
     * the stub is listening — not actionable failures.
     */
    private fun isBenignSessionEnd(e: Throwable): Boolean {
        when (e) {
            is java.io.EOFException -> return true
            is SocketException -> return true
            is java.net.SocketTimeoutException -> return true
            is java.net.UnknownHostException -> return true
        }
        val msg = e.message?.lowercase() ?: return false
        return "broken pipe" in msg ||
            "connection reset" in msg ||
            "connection abort" in msg ||
            "poll timed out" in msg
    }

    private fun pipe(a: Socket, b: Socket) {
        val t = Thread({
            try {
                a.getInputStream().copyTo(b.getOutputStream())
            } catch (_: Exception) {
            } finally {
                runCatching { b.shutdownOutput() }
                runCatching { a.close() }
                runCatching { b.close() }
            }
        }, "onionvpn-pac-pipe")
        t.isDaemon = true
        t.start()
        try {
            b.getInputStream().copyTo(a.getOutputStream())
        } catch (_: Exception) {
        } finally {
            runCatching { a.shutdownOutput() }
            runCatching { a.close() }
            runCatching { b.close() }
        }
        t.join(5_000)
    }

    private fun resolveClientUid(client: Socket): Int =
        FirewallBridge.resolveSocksClientUid?.invoke(client) ?: -1

    /**
     * Per-client IsolateSOCKSAuth so PAC helpers do not share one circuit pool
     * (Tor path-spec / X-Tor-Stream-Isolation analogue via SOCKS username).
     */
    private fun pacSocksAuth(uid: Int): Pair<String, String> {
        return if (uid >= 0) {
            "pac$uid" to "p$uid"
        } else {
            TunnelEndpoints.SOCKS_PAC_USER to TunnelEndpoints.SOCKS_PAC_PASS
        }
    }

    companion object {
        private const val CMD_CONNECT = 0x01
        private const val ATYP_IPV4 = 0x01
        private const val ATYP_DOMAIN = 0x03
        private const val ATYP_IPV6 = 0x04
        private const val REP_SUCCEEDED = 0x00
        private const val REP_GENERAL_FAILURE = 0x01
        private const val REP_NOT_ALLOWED = 0x02
        private const val REP_COMMAND_NOT_SUPPORTED = 0x07
        private const val REP_ATYP_NOT_SUPPORTED = 0x08
    }
}
