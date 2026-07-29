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
                if (reqVer != 0x05 || cmd != 0x01) {
                    reply(output, 0x07, InetAddress.getByName("0.0.0.0"), 0)
                    return
                }
                val (host, port) = readAddress(input, atyp)
                val torPort = torSocksPort.get()
                val dnsPort = dnsCryptPort.get()
                if (torPort <= 0 || dnsPort <= 0) {
                    reply(output, 0x01, InetAddress.getByName("0.0.0.0"), 0)
                    return
                }

                val remote: Socket = if (TunnelEndpoints.isOnionLikeHostname(host)) {
                    // Onion / .exit → Tor SOCKS5A (DNSCrypt has no HSDir / Automap).
                    Socks5Client(
                        proxyHost = TunnelEndpoints.LOOPBACK,
                        proxyPort = torPort,
                        username = TunnelEndpoints.SOCKS_PAC_USER,
                        password = TunnelEndpoints.SOCKS_PAC_PASS,
                    ).connect(host, port)
                } else {
                    val ip = DnsCryptResolver.resolveIpv4(
                        hostname = host,
                        dnsCryptHost = TunnelEndpoints.LOOPBACK,
                        dnsCryptPort = dnsPort,
                    )
                    Socks5Client(
                        proxyHost = TunnelEndpoints.LOOPBACK,
                        proxyPort = torPort,
                        username = TunnelEndpoints.SOCKS_PAC_USER,
                        password = TunnelEndpoints.SOCKS_PAC_PASS,
                    ).connect(ip.hostAddress ?: ip.hostName, port)
                }

                reply(output, 0x00, InetAddress.getByName("0.0.0.0"), 0)
                c.soTimeout = 0
                remote.soTimeout = 0
                pipe(c, remote)
            } catch (e: Exception) {
                Timber.d(e, "PAC SOCKS bridge session failed")
                runCatching {
                    reply(output, 0x01, InetAddress.getByName("0.0.0.0"), 0)
                }
            }
        }
    }

    private fun readAddress(input: DataInputStream, atyp: Int): Pair<String, Int> {
        return when (atyp) {
            0x01 -> {
                val addr = ByteArray(4)
                input.readFully(addr)
                val port = input.readUnsignedShort()
                InetAddress.getByAddress(addr).hostAddress!! to port
            }
            0x03 -> {
                val n = input.readUnsignedByte()
                val name = ByteArray(n)
                input.readFully(name)
                val port = input.readUnsignedShort()
                String(name, StandardCharsets.US_ASCII) to port
            }
            0x04 -> {
                input.skipBytes(16)
                input.readUnsignedShort()
                throw IOException("IPv6 not supported on PAC bridge")
            }
            else -> throw IOException("bad atyp=$atyp")
        }
    }

    private fun reply(output: DataOutputStream, status: Int, bind: InetAddress, port: Int) {
        output.writeByte(0x05)
        output.writeByte(status)
        output.writeByte(0x00)
        val raw = bind.address
        if (raw.size == 4) {
            output.writeByte(0x01)
            output.write(raw)
        } else {
            output.writeByte(0x01)
            output.write(byteArrayOf(0, 0, 0, 0))
        }
        output.writeShort(port)
        output.flush()
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
}
