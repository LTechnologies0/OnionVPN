package ltechnologies.onionphone.onionvpn.core.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import androidx.core.content.getSystemService
import timber.log.Timber

/**
 * Multi-level routing hardening (Android VpnService docs):
 *
 * 1. Apps → TUN (VpnService.Builder routes)
 * 2. hev → Tor SOCKS (loopback, self-excluded)
 * 3. Tor → **underlying** Wi‑Fi/cellular via [VpnService.setUnderlyingNetworks]
 *
 * Declaring the upstream network helps the system reason about VPN capacity and
 * avoids stale routing when Wi‑Fi ↔ cell handoffs occur. Tor itself is also
 * self-excluded via [VpnService.Builder.addDisallowedApplication].
 *
 * @see <a href="https://developer.android.com/develop/connectivity/vpn">VPN guide</a>
 */
class UnderlyingNetworkTracker(
    private val context: Context,
    private val vpnService: VpnService,
    private val onUnderlyingChanged: (() -> Unit)? = null,
) {
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        stop()
        val cm = context.getSystemService<ConnectivityManager>() ?: run {
            Timber.e("UnderlyingNetworkTracker: ConnectivityManager unavailable")
            return
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = publish(cm)
            override fun onLost(network: Network) = publish(cm)
            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities,
            ) = publish(cm)
        }
        try {
            cm.registerNetworkCallback(request, cb)
            callback = cb
            publish(cm)
            Timber.i("UnderlyingNetworkTracker started")
        } catch (error: Exception) {
            Timber.e(error, "Failed to register underlying NetworkCallback")
        }
    }

    fun stop() {
        val cm = context.getSystemService<ConnectivityManager>()
        callback?.let { cb ->
            runCatching { cm?.unregisterNetworkCallback(cb) }
        }
        callback = null
        runCatching { vpnService.setUnderlyingNetworks(null) }
    }

    private fun publish(cm: ConnectivityManager) {
        val best = selectBestUnderlying(cm)
        try {
            vpnService.setUnderlyingNetworks(best?.let { arrayOf(it) })
            if (best != null) {
                val caps = cm.getNetworkCapabilities(best)
                Timber.d(
                    "setUnderlyingNetworks net=$best wifi=%s cell=%s validated=%s",
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
                    caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                )
            } else {
                Timber.w("No underlying non-VPN network — setUnderlyingNetworks(null)")
            }
            onUnderlyingChanged?.invoke()
        } catch (error: Exception) {
            Timber.e(error, "setUnderlyingNetworks failed")
        }
    }

    /**
     * Prefer validated Wi‑Fi, then validated cellular, then any INTERNET+NOT_VPN.
     * Never select TRANSPORT_VPN (would create a routing loop for upstream).
     */
    private fun selectBestUnderlying(cm: ConnectivityManager): Network? {
        data class Candidate(val network: Network, val score: Int)

        val candidates = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null

            var score = 0
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) score += 100
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) score += 50
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) score += 20
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
            ) {
                score += 5
            }
            Candidate(network, score)
        }
        return candidates.maxByOrNull { it.score }?.network
    }
}
