package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.locks.LockSupport
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import timber.log.Timber

/**
 * Dial RFC1918 on a real LAN uplink (Wi‑Fi / Ethernet / USB), never cellular and never TUN.
 *
 * [android.net.VpnService.protect] alone is not enough when the default route is cellular
 * while the node lives on Wi‑Fi — protected sockets follow the process default network and
 * Cake→192.168.x never reaches the LAN host (0 hits on socat).
 */
object LanClearnetDial {
    /** Last good Wi‑Fi/Eth/USB NOT_VPN Network (OEM often hides Wi‑Fi from allNetworks under VPN). */
    @Volatile
    private var cachedLanNetwork: Network? = null

    fun noteLanUplink(network: Network?) {
        cachedLanNetwork = network
    }

    /**
     * protect → bind to LAN-capable [Network] → connect.
     * One retry on protect/bind/connect failure (VPN churn / Wi‑Fi flap).
     */
    fun connect(
        context: Context,
        protect: (Socket) -> Boolean,
        host: String,
        port: Int,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS,
    ): Socket {
        if (!TorNetPolicy.isLanRoutableIpv4Literal(host)) {
            throw IOException("LAN dial refused — dest not RFC1918 ($host)")
        }
        if (port !in 1..65535) {
            throw IOException("LAN dial refused — bad port $port")
        }
        val cm = context.applicationContext
            .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        var last: Exception? = null
        repeat(2) { attempt ->
            val upstream = Socket()
            try {
                upstream.tcpNoDelay = true
                // Fail-closed: no Wi‑Fi/Ethernet → never cellular protect-only.
                val lanNet = selectLanUplink(cm)
                    ?: throw IOException("LAN dial refused — no Wi‑Fi/Ethernet uplink")
                // Bind to LAN Network FIRST. Some OEMs (Samsung/MIUI/ColorOS) EPERM
                // bindSocket after VpnService.protect; NOT_VPN bind alone avoids TUN loop.
                try {
                    lanNet.bindSocket(upstream)
                } catch (e: Exception) {
                    runCatching { upstream.close() }
                    throw IOException("LAN dial refused — bindSocket failed", e)
                }
                // Defense-in-depth: protect after bind (ignore soft failure — already bound).
                if (!protect(upstream)) {
                    Timber.w("LAN dial: protect after bind returned false (continuing on bound Network)")
                }
                upstream.connect(InetSocketAddress(host, port), timeoutMs)
                return upstream
            } catch (e: Exception) {
                last = e
                runCatching { upstream.close() }
                if (attempt == 0) {
                    LockSupport.parkNanos(RETRY_PARK_NS)
                }
            }
        }
        throw last ?: IOException("LAN dial failed")
    }

    /**
     * Prefer Ethernet, then validated Wi‑Fi, then any Wi‑Fi/USB — never cellular / VPN.
     * RFC1918 is not reachable via mobile data.
     */
    fun selectLanUplink(cm: ConnectivityManager?): Network? {
        if (cm == null) return null
        cachedLanNetwork?.let { cached ->
            val caps = cm.getNetworkCapabilities(cached)
            if (caps != null && isLanCapable(caps)) return cached
        }
        data class Candidate(val network: Network, val score: Int)

        val candidates = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!isLanCapable(caps)) return@mapNotNull null
            var score = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 100
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) score += 60
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) score += 50
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_USB)
            ) {
                score += 40
            }
            Candidate(network, score)
        }
        return candidates.maxByOrNull { it.score }?.network?.also { noteLanUplink(it) }
    }

    private fun isLanCapable(caps: NetworkCapabilities): Boolean {
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return false
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return false
        val wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        val eth = caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        val usb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            caps.hasTransport(NetworkCapabilities.TRANSPORT_USB)
        return wifi || eth || usb
    }

    private const val DEFAULT_TIMEOUT_MS = 15_000
    private const val RETRY_PARK_NS = 50_000_000L // 50ms
}
