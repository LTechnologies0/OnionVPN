package ltechnologies.onionphone.onionvpn.core.vpn

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import timber.log.Timber

/**
 * Splits VPN TUN traffic:
 * - UDP to [vpnDnsAddress]:53 → DNSCrypt on loopback (async, non-blocking)
 * - everything else → hev socket (raw IP packet stream)
 */
class TunDnsMux(
    private val tunFd: ParcelFileDescriptor,
    private val hevFd: ParcelFileDescriptor,
    private val dnsCryptHost: String,
    private val dnsCryptPort: Int,
    private val vpnDnsAddress: String,
) {
    private val running = AtomicBoolean(false)
    private var tunToHev: Thread? = null
    private var hevToTun: Thread? = null
    private val tunWriteLock = Any()
    private val hevWriteLock = Any()
    private val dnsExecutor = Executors.newFixedThreadPool(8) { r ->
        Thread(r, "onionvpn-dns").apply { isDaemon = true }
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val vpnDns = InetAddress.getByName(vpnDnsAddress).address
        val tunOut = FileOutputStream(tunFd.fileDescriptor)
        val hevOut = FileOutputStream(hevFd.fileDescriptor)

        tunToHev = Thread({
            val tunIn = FileInputStream(tunFd.fileDescriptor)
            val buf = ByteArray(MTU)
            try {
                while (running.get()) {
                    val n = tunIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            Thread.sleep(1)
                            continue
                        }
                        isDnsQueryToVpnDns(buf, n, vpnDns) -> {
                            val packet = buf.copyOf(n)
                            try {
                                dnsExecutor.execute { handleDnsQuery(packet, tunOut) }
                            } catch (_: RejectedExecutionException) {
                                Timber.w("DNS executor saturated, dropping query")
                            }
                        }
                        else -> synchronized(hevWriteLock) {
                            hevOut.write(buf, 0, n)
                            hevOut.flush()
                        }
                    }
                }
            } catch (error: Exception) {
                if (running.get()) Timber.w(error, "TunDnsMux tun→hev stopped")
            }
        }, "onionvpn-tun-hev").apply {
            isDaemon = true
            start()
        }

        hevToTun = Thread({
            val hevIn = FileInputStream(hevFd.fileDescriptor)
            val buf = ByteArray(MTU)
            try {
                while (running.get()) {
                    val n = hevIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            Thread.sleep(1)
                            continue
                        }
                        else -> synchronized(tunWriteLock) {
                            tunOut.write(buf, 0, n)
                            tunOut.flush()
                        }
                    }
                }
            } catch (error: Exception) {
                if (running.get()) Timber.w(error, "TunDnsMux hev→tun stopped")
            }
        }, "onionvpn-hev-tun").apply {
            isDaemon = true
            start()
        }

        Timber.i("TunDnsMux started dns=$vpnDnsAddress → $dnsCryptHost:$dnsCryptPort")
    }

    fun stop() {
        running.set(false)
        dnsExecutor.shutdownNow()
        runCatching { tunFd.close() }
        runCatching { hevFd.close() }
        tunToHev?.interrupt()
        hevToTun?.interrupt()
        tunToHev = null
        hevToTun = null
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
                val responseBuf = ByteArray(2048)
                val response = DatagramPacket(responseBuf, responseBuf.size)
                socket.receive(response)

                val reply = buildDnsReply(packet, responseBuf, response.length) ?: return
                synchronized(tunWriteLock) {
                    if (!running.get()) return
                    tunOut.write(reply)
                    tunOut.flush()
                }
                Timber.d("TunDnsMux DNS reply %d bytes", reply.size)
            }
        } catch (error: Exception) {
            Timber.e(error, "DNSCrypt forward failed — query dropped")
        }
    }

    private fun buildDnsReply(
        request: ByteArray,
        dnsPayload: ByteArray,
        dnsLen: Int,
    ): ByteArray? {
        val ihl = (request[0].toInt() and 0x0f) * 4
        val totalLen = ihl + 8 + dnsLen
        if (totalLen > MTU) return null
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
        private const val MTU = 1500
        private const val PROTO_UDP = 17
        private const val DNS_TIMEOUT_MS = 12_000
    }
}
