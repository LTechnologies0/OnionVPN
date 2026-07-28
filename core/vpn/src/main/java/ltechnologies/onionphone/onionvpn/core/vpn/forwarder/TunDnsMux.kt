package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.LockSupport
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import timber.log.Timber

/**
 * Splits VPN TUN traffic:
 * - When [divertDnsToDnsCrypt]: UDP to [vpnDnsAddress]:53 → DNSCrypt on loopback
 * - everything else → firewall check → hev socket (raw IP packet stream)
 *
 * DoS / ARM notes:
 * - DNS work uses a **bounded** pool + queue (never unbounded LinkedBlockingQueue).
 * - Per-worker reused DatagramSocket + reply buffers (ThreadLocal) — no open/close per query.
 * - Packet handoff uses a small free-list of MTU buffers.
 * - No per-packet [FileOutputStream.flush].
 */
class TunDnsMux(
    private val tunFd: ParcelFileDescriptor,
    private val hevFd: ParcelFileDescriptor,
    private val dnsCryptHost: String,
    private val dnsCryptPort: Int,
    private val vpnDnsAddress: String,
    private val divertDnsToDnsCrypt: Boolean = true,
    private val onFatal: ((Throwable) -> Unit)? = null,
) {
    private val running = AtomicBoolean(false)
    private var tunToHev: Thread? = null
    private var hevToTun: Thread? = null
    private val tunWriteLock = Any()
    private val hevWriteLock = Any()

    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private var hevIn: FileInputStream? = null
    private var hevOut: FileOutputStream? = null

    private val dnsCryptAddress: InetAddress = InetAddress.getByName(dnsCryptHost)
    private val packetPool = ArrayBlockingQueue<ByteArray>(DNS_QUEUE_CAP)

    private val dnsExecutor = ThreadPoolExecutor(
        DNS_CORE_THREADS,
        DNS_MAX_THREADS,
        30L,
        TimeUnit.SECONDS,
        ArrayBlockingQueue(DNS_QUEUE_CAP),
        { r -> Thread(r, "onionvpn-dns").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy(),
    ).apply {
        allowCoreThreadTimeOut(true)
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val vpnDns = InetAddress.getByName(vpnDnsAddress).address
        val localTunOut = FileOutputStream(tunFd.fileDescriptor)
        val localHevOut = FileOutputStream(hevFd.fileDescriptor)
        tunOut = localTunOut
        hevOut = localHevOut

        tunToHev = Thread({
            val localTunIn = FileInputStream(tunFd.fileDescriptor)
            tunIn = localTunIn
            val buf = ByteArray(MTU)
            try {
                while (running.get()) {
                    val n = localTunIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            LockSupport.parkNanos(EMPTY_READ_PARK_NS)
                            continue
                        }
                        divertDnsToDnsCrypt && isDnsQueryToVpnDns(buf, n, vpnDns) -> {
                            val packet = borrowPacket(buf, n)
                            dnsExecutor.execute {
                                try {
                                    handleDnsQuery(packet, n, localTunOut)
                                } finally {
                                    recyclePacket(packet)
                                }
                            }
                        }
                        isDnsQueryToVpnDns(buf, n, vpnDns) -> {
                            writeHev(localHevOut, buf, n)
                        }
                        !FirewallBridge.engine.allowOutbound(buf, n) -> {
                            // Drop
                        }
                        else -> writeHev(localHevOut, buf, n)
                    }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    Timber.w(error, "TunDnsMux tun→hev stopped")
                    onFatal?.invoke(error)
                }
            }
        }, "onionvpn-tun-hev").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
            start()
        }

        hevToTun = Thread({
            val localHevIn = FileInputStream(hevFd.fileDescriptor)
            hevIn = localHevIn
            val buf = ByteArray(MTU)
            try {
                while (running.get()) {
                    val n = localHevIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            LockSupport.parkNanos(EMPTY_READ_PARK_NS)
                            continue
                        }
                        else -> synchronized(tunWriteLock) {
                            if (!running.get()) return@synchronized
                            localTunOut.write(buf, 0, n)
                        }
                    }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    Timber.w(error, "TunDnsMux hev→tun stopped")
                    onFatal?.invoke(error)
                }
            }
        }, "onionvpn-hev-tun").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
            start()
        }

        Timber.i(
            "TunDnsMux started dns=$vpnDnsAddress divertDns=$divertDnsToDnsCrypt " +
                "→ $dnsCryptHost:$dnsCryptPort pool=$DNS_CORE_THREADS..$DNS_MAX_THREADS q=$DNS_QUEUE_CAP",
        )
    }

    fun stop() {
        running.set(false)
        dnsExecutor.shutdownNow()
        runCatching { tunIn?.close() }
        runCatching { hevIn?.close() }
        runCatching { tunOut?.close() }
        runCatching { hevOut?.close() }
        tunIn = null
        hevIn = null
        tunOut = null
        hevOut = null
        runCatching { tunFd.close() }
        runCatching { hevFd.close() }
        tunToHev?.interrupt()
        hevToTun?.interrupt()
        tunToHev = null
        hevToTun = null
        packetPool.clear()
        runCatching {
            if (!dnsExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                Timber.w("DNS executor did not terminate cleanly")
            }
        }
    }

    private fun borrowPacket(src: ByteArray, n: Int): ByteArray {
        val packet = packetPool.poll() ?: ByteArray(MTU)
        System.arraycopy(src, 0, packet, 0, n)
        return packet
    }

    private fun recyclePacket(packet: ByteArray) {
        if (packet.size == MTU) {
            packetPool.offer(packet)
        }
    }

    private fun writeHev(hevOut: FileOutputStream, buf: ByteArray, n: Int) {
        synchronized(hevWriteLock) {
            if (!running.get()) return
            hevOut.write(buf, 0, n)
        }
    }

    private fun isDnsQueryToVpnDns(packet: ByteArray, length: Int, vpnDns: ByteArray): Boolean {
        if (length < 28) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return false
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (length < ihl + 8) return false
        if (packet[9].toInt() and 0xff != PROTO_UDP) return false
        for (i in 0 until 4) {
            if (packet[16 + i] != vpnDns[i]) return false
        }
        val destPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or (packet[ihl + 3].toInt() and 0xff)
        return destPort == 53
    }

    private fun handleDnsQuery(packet: ByteArray, length: Int, tunOut: FileOutputStream) {
        if (!running.get()) return
        try {
            val ihl = (packet[0].toInt() and 0x0f) * 4
            val dnsOffset = ihl + 8
            if (length <= dnsOffset) return

            val scratch = dnsScratch.get()
            val socket = scratch.socket()
            val queryLen = length - dnsOffset
            socket.send(
                DatagramPacket(
                    packet,
                    dnsOffset,
                    queryLen,
                    dnsCryptAddress,
                    dnsCryptPort,
                ),
            )
            val response = DatagramPacket(scratch.responseBuf, scratch.responseBuf.size)
            socket.receive(response)

            val replyLen = buildDnsReplyInto(
                request = packet,
                requestLen = length,
                dnsPayload = scratch.responseBuf,
                dnsLen = response.length,
                out = scratch.replyBuf,
            ) ?: return
            synchronized(tunWriteLock) {
                if (!running.get()) return
                tunOut.write(scratch.replyBuf, 0, replyLen)
            }
        } catch (error: Exception) {
            if (running.get()) {
                when (error) {
                    is java.net.SocketTimeoutException ->
                        Timber.d("DNSCrypt forward timeout — query dropped")
                    is java.net.ConnectException ->
                        Timber.d(error, "DNSCrypt stub refused — query dropped")
                    is java.net.PortUnreachableException ->
                        Timber.d(error, "DNSCrypt port unreachable — query dropped")
                    else ->
                        Timber.d(error, "DNSCrypt forward failed — query dropped")
                }
            }
        }
    }

    /** @return reply length, or null if too large */
    private fun buildDnsReplyInto(
        request: ByteArray,
        requestLen: Int,
        dnsPayload: ByteArray,
        dnsLen: Int,
        out: ByteArray,
    ): Int? {
        val ihl = (request[0].toInt() and 0x0f) * 4
        val totalLen = ihl + 8 + dnsLen
        if (totalLen > MTU || dnsLen < 0 || totalLen > out.size || requestLen < ihl + 8) return null

        System.arraycopy(request, 0, out, 0, ihl)
        for (i in 0 until 4) {
            out[12 + i] = request[16 + i]
            out[16 + i] = request[12 + i]
        }
        out[10] = 0
        out[11] = 0
        out[2] = (totalLen ushr 8).toByte()
        out[3] = (totalLen and 0xff).toByte()
        val ipSum = checksum(out, 0, ihl)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xff).toByte()

        out[ihl] = request[ihl + 2]
        out[ihl + 1] = request[ihl + 3]
        out[ihl + 2] = request[ihl]
        out[ihl + 3] = request[ihl + 1]
        val udpLen = 8 + dnsLen
        out[ihl + 4] = (udpLen ushr 8).toByte()
        out[ihl + 5] = (udpLen and 0xff).toByte()
        out[ihl + 6] = 0
        out[ihl + 7] = 0

        System.arraycopy(dnsPayload, 0, out, ihl + 8, dnsLen)
        return totalLen
    }

    private fun checksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }

    private class DnsScratch {
        val responseBuf = ByteArray(DNS_RESPONSE_CAP)
        val replyBuf = ByteArray(MTU)
        private var socket: DatagramSocket? = null

        fun socket(): DatagramSocket {
            val existing = socket
            if (existing != null && !existing.isClosed) return existing
            return DatagramSocket().also {
                it.soTimeout = DNS_TIMEOUT_MS
                socket = it
            }
        }
    }

    companion object {
        private const val MTU = 1280
        private const val PROTO_UDP = 17
        private const val DNS_TIMEOUT_MS = 8_000
        private const val DNS_RESPONSE_CAP = 2048
        private const val EMPTY_READ_PARK_NS = 200_000L // 0.2ms
        private val DNS_CORE_THREADS =
            Runtime.getRuntime().availableProcessors().coerceIn(2, 4)
        private val DNS_MAX_THREADS = (DNS_CORE_THREADS + 2).coerceAtMost(6)
        private const val DNS_QUEUE_CAP = 64

        private val dnsScratch = ThreadLocal.withInitial { DnsScratch() }
    }
}
