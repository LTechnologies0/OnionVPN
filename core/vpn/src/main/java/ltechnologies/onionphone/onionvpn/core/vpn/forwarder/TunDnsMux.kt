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
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import timber.log.Timber

/**
 * Splits VPN TUN traffic:
 * - When [divertDnsToDnsCrypt]: UDP to [vpnDnsAddress]:53 → DNSCrypt on loopback
 * - everything else → firewall check → hev socket (raw IP packet stream)
 *
 * DoS / ARM notes:
 * - DNS work uses a **bounded** pool + queue (never [Executors.newFixedThreadPool]'s
 *   unbounded LinkedBlockingQueue).
 * - No per-packet [FileOutputStream.flush] (fsync storm on mobile storage).
 * - Packet copies only for async DNS; SYN/TCP path reuses the read buffer under
 *   the single tun→hev thread (firewall must not retain the array).
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

    /**
     * DNSCrypt forwards: small fixed pool sized for big.LITTLE phones, bounded queue.
     * DiscardOldest under flood — prefer fresh queries over backlog OOM.
     */
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
                            // Non-blocking quirk — brief yield, not a tight spin.
                            Thread.yield()
                            continue
                        }
                        divertDnsToDnsCrypt && isDnsQueryToVpnDns(buf, n, vpnDns) -> {
                            val packet = buf.copyOf(n)
                            dnsExecutor.execute { handleDnsQuery(packet, localTunOut) }
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
                            Thread.yield()
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
        runCatching {
            if (!dnsExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                Timber.w("DNS executor did not terminate cleanly")
            }
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

    private fun handleDnsQuery(packet: ByteArray, tunOut: FileOutputStream) {
        if (!running.get()) return
        try {
            val ihl = (packet[0].toInt() and 0x0f) * 4
            val dnsOffset = ihl + 8
            if (packet.size <= dnsOffset) return

            val query = packet.copyOfRange(dnsOffset, packet.size)
            DatagramSocket().use { socket ->
                socket.soTimeout = DNS_TIMEOUT_MS
                socket.send(
                    DatagramPacket(
                        query,
                        query.size,
                        InetAddress.getByName(dnsCryptHost),
                        dnsCryptPort,
                    ),
                )
                val responseBuf = ByteArray(DNS_RESPONSE_CAP)
                val response = DatagramPacket(responseBuf, responseBuf.size)
                socket.receive(response)

                val reply = buildDnsReply(packet, responseBuf, response.length) ?: return
                synchronized(tunWriteLock) {
                    if (!running.get()) return
                    tunOut.write(reply)
                }
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

    private fun buildDnsReply(
        request: ByteArray,
        dnsPayload: ByteArray,
        dnsLen: Int,
    ): ByteArray? {
        val ihl = (request[0].toInt() and 0x0f) * 4
        val totalLen = ihl + 8 + dnsLen
        if (totalLen > MTU || dnsLen < 0) return null
        val out = ByteArray(totalLen)

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
        return out
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

    companion object {
        private const val MTU = 1280
        private const val PROTO_UDP = 17
        private const val DNS_TIMEOUT_MS = 8_000
        private const val DNS_RESPONSE_CAP = 2048
        private val DNS_CORE_THREADS =
            Runtime.getRuntime().availableProcessors().coerceIn(2, 4)
        private val DNS_MAX_THREADS = (DNS_CORE_THREADS + 2).coerceAtMost(6)
        private const val DNS_QUEUE_CAP = 64
    }
}
