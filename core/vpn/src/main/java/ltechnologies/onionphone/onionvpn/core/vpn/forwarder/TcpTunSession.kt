package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.io.InputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random
import timber.log.Timber

/**
 * One TCP flow: app (TUN) ↔ SOCKS5 (Tor) with per-UID isolation credentials.
 */
internal class TcpTunSession(
    val key: Long,
    val clientIp: Int,
    val clientPort: Int,
    val remoteIp: Int,
    val remotePort: Int,
    /** SOCKS CONNECT target: IPv4 string or `.onion` / `.exit` hostname (Automap). */
    private val remoteHost: String,
    val uid: Int,
    private val socksHost: String,
    private val socksPort: Int,
    private val socksUser: String,
    private val socksPass: String,
    private val protect: ((Socket) -> Boolean)?,
    private val writeToTun: (ByteArray) -> Unit,
    private val onClosed: (TcpTunSession) -> Unit,
) {
    private val alive = AtomicBoolean(true)
    private var socket: Socket? = null
    private var readerThread: Thread? = null

    /** Our seq (as "server" toward the app). */
    @Volatile private var ourSeq: Int = Random.nextInt()

    /** Next expected client seq. */
    @Volatile private var clientSeq: Int = 0

    @Volatile private var established = false

    fun handlePacket(packet: ByteArray, meta: TcpPacketBuilder.TcpMeta) {
        if (!alive.get()) return
        if (meta.rst) {
            close(sendRst = false)
            return
        }
        if (meta.synOnly) {
            clientSeq = meta.seq + 1
            openSocksAsync()
            return
        }
        if (meta.fin) {
            clientSeq = meta.seq + 1 + meta.payloadLength
            sendTcp(TcpPacketBuilder.FLAG_ACK, payload = Empty)
            close(sendRst = false, sendFin = true)
            return
        }
        if (meta.payloadLength > 0 && established) {
            clientSeq = meta.seq + meta.payloadLength
            try {
                socket?.getOutputStream()?.write(packet, meta.payloadOffset, meta.payloadLength)
                socket?.getOutputStream()?.flush()
            } catch (e: Exception) {
                Timber.d(e, "TCP session write to SOCKS failed")
                close(sendRst = true)
                return
            }
            sendTcp(TcpPacketBuilder.FLAG_ACK, payload = Empty)
        } else if (meta.ackFlag && meta.payloadLength == 0) {
            // pure ACK
        }
    }

    private fun openSocksAsync() {
        Thread({
            try {
                val sock = Socks5Client(
                    proxyHost = socksHost,
                    proxyPort = socksPort,
                    username = socksUser,
                    password = socksPass,
                    protect = protect,
                ).connect(remoteHost, remotePort)
                if (!alive.get()) {
                    sock.close()
                    return@Thread
                }
                socket = sock
                // SYN-ACK to app
                sendTcp(TcpPacketBuilder.FLAG_SYN or TcpPacketBuilder.FLAG_ACK, payload = Empty)
                ourSeq += 1
                established = true
                startReader(sock.getInputStream())
            } catch (e: Exception) {
                Timber.d(e, "SOCKS connect failed uid=$uid $remoteHost:$remotePort")
                close(sendRst = true)
            }
        }, "onionvpn-socks-$clientPort").apply {
            isDaemon = true
            start()
        }
    }

    private fun startReader(input: InputStream) {
        readerThread = Thread({
            val buf = ByteArray(32 * 1024)
            try {
                while (alive.get()) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    sendTcp(TcpPacketBuilder.FLAG_ACK or TcpPacketBuilder.FLAG_PSH, buf, 0, n)
                    ourSeq += n
                }
            } catch (_: Exception) {
            } finally {
                close(sendRst = false, sendFin = true)
            }
        }, "onionvpn-socks-r-$clientPort").apply {
            isDaemon = true
            start()
        }
    }

    private fun sendTcp(
        flags: Int,
        payload: ByteArray = Empty,
        offset: Int = 0,
        length: Int = payload.size,
    ) {
        val pkt = TcpPacketBuilder.build(
            srcIp = remoteIp,
            dstIp = clientIp,
            srcPort = remotePort,
            dstPort = clientPort,
            seq = ourSeq,
            ack = clientSeq,
            flags = flags,
            payload = payload,
            payloadOffset = offset,
            payloadLength = length,
        )
        writeToTun(pkt)
    }

    fun close(sendRst: Boolean = false, sendFin: Boolean = false) {
        if (!alive.compareAndSet(true, false)) return
        try {
            if (sendRst) {
                sendTcp(TcpPacketBuilder.FLAG_RST or TcpPacketBuilder.FLAG_ACK)
            } else if (sendFin && established) {
                sendTcp(TcpPacketBuilder.FLAG_FIN or TcpPacketBuilder.FLAG_ACK)
                ourSeq += 1
            }
        } catch (_: Exception) {
        }
        runCatching { socket?.close() }
        socket = null
        onClosed(this)
    }

    companion object {
        private val Empty = ByteArray(0)

        fun flowKey(srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int): Long =
            ((srcIp.toLong() and 0xffffffffL) shl 32) or
                ((srcPort.toLong() and 0xffffL) shl 16) or
                (dstPort.toLong() and 0xffffL) xor (dstIp.toLong() and 0xffffffffL)

        fun formatIpv4(ip: Int): String =
            "${(ip ushr 24) and 0xff}.${(ip ushr 16) and 0xff}." +
                "${(ip ushr 8) and 0xff}.${ip and 0xff}"
    }
}
