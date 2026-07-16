package ltechnologies.onionphone.onionvpn.core.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnEstablishResult
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import timber.log.Timber

class OnionVpnService : VpnService() {
    private var tunForwarder: TunForwarder? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "onionvpn-vpn").apply { isDaemon = true }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: return START_NOT_STICKY
        executor.execute {
            when (action) {
                ACTION_START -> applyProfile(intent, startForwarder = true)
                ACTION_BLOCK -> applyProfile(intent, startForwarder = false)
                // Tear down TUN without stopSelf — a following START must not race onDestroy.
                ACTION_STOP -> stopTunnel(destroyService = false)
                ACTION_DESTROY -> stopTunnel(destroyService = true)
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        executor.execute { stopTunnel() }
        executor.shutdown()
        super.onDestroy()
    }

    override fun onRevoke() {
        Timber.w("VPN permission revoked")
        stopTunnel()
        super.onRevoke()
    }

    private fun applyProfile(intent: Intent, startForwarder: Boolean) {
        val preferences = TunnelPreferences(
            routeAllTrafficThroughTor = intent.getBooleanExtra(EXTRA_ROUTE_ALL, true),
            killSwitchEnabled = intent.getBooleanExtra(EXTRA_KILL_SWITCH, true),
        )
        val mode = intent.getStringExtra(EXTRA_PROFILE_MODE)
            ?.let { runCatching { VpnProfileMode.valueOf(it) }.getOrNull() }
            ?: if (startForwarder) VpnProfileMode.Connected else VpnProfileMode.Blocking
        val torSocksPort = intent.getIntExtra(EXTRA_TOR_SOCKS_PORT, TunnelEndpoints.DEFAULT_TOR_SOCKS_PORT)
        val dnsCryptPort = intent.getIntExtra(EXTRA_DNSCRYPT_PORT, TunnelEndpoints.DEFAULT_DNSCRYPT_LISTEN_PORT)
        val generation = intent.getIntExtra(EXTRA_GENERATION, -1)
        val dnsMode = intent.getStringExtra(EXTRA_DNS_MODE)
            ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
            ?: DnsResolverMode.DNSCRYPT_MUX

        // Drop any stale "established" flag before re-bind so waiters cannot race.
        isEstablished.value = false
        activeGeneration.value = -1
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1

        stopForwarder()
        tunInterface?.close()
        tunInterface = null

        val result = establish(preferences, mode)
        when (result) {
            is VpnEstablishResult.Success -> {
                if (startForwarder && mode == VpnProfileMode.Connected) {
                    startForwarder(torSocksPort, dnsCryptPort, dnsMode)
                }
                profileMode.value = mode
                if (generation >= 0) {
                    activeGeneration.value = generation
                }
                isEstablished.value = true
                Timber.i(
                    "VPN established mode=$mode killSwitch=${preferences.killSwitchEnabled} " +
                        "socks=$torSocksPort dnscrypt=$dnsCryptPort gen=$generation",
                )
            }
            is VpnEstablishResult.Failure -> {
                Timber.e("VPN establish failed: ${result.reason}")
                isEstablished.value = false
                profileMode.value = null
            }
        }
    }

    private fun establish(
        preferences: TunnelPreferences,
        mode: VpnProfileMode,
    ): VpnEstablishResult {
        val builder = VpnProfileBuilder.configure(this, preferences, mode)
        val tun = builder.establish()
            ?: return VpnEstablishResult.Failure("VpnService.Builder.establish() returned null")
        tunInterface = tun
        return VpnEstablishResult.Success(mode)
    }

    private fun startForwarder(torSocksPort: Int, dnsCryptPort: Int, dnsMode: DnsResolverMode) {
        val tun = tunInterface ?: return
        val forwarder = HevSocks5TunForwarder(applicationContext, dnsMode)
        tunForwarder = forwarder
        forwarderSocksPort.value = torSocksPort
        forwarderDnsCryptPort.value = dnsCryptPort
        forwarder.start(
            tunFd = tun,
            socksHost = TunnelEndpoints.LOOPBACK,
            socksPort = torSocksPort,
            dnsCryptPort = dnsCryptPort,
        )
    }

    private fun stopForwarder() {
        tunForwarder?.stop()
        tunForwarder = null
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1
    }

    private fun stopTunnel(destroyService: Boolean = true) {
        stopForwarder()
        tunInterface?.close()
        tunInterface = null
        isEstablished.value = false
        activeGeneration.value = -1
        profileMode.value = null
        if (destroyService) {
            stopSelf()
        }
    }

    companion object {
        const val ACTION_START = "ltechnologies.onionphone.onionvpn.START"
        const val ACTION_BLOCK = "ltechnologies.onionphone.onionvpn.BLOCK"
        const val ACTION_STOP = "ltechnologies.onionphone.onionvpn.STOP"
        const val ACTION_DESTROY = "ltechnologies.onionphone.onionvpn.DESTROY"
        const val EXTRA_ROUTE_ALL = "route_all"
        const val EXTRA_KILL_SWITCH = "kill_switch"
        const val EXTRA_PROFILE_MODE = "profile_mode"
        const val EXTRA_TOR_SOCKS_PORT = "tor_socks_port"
        const val EXTRA_DNSCRYPT_PORT = "dnscrypt_port"
        const val EXTRA_GENERATION = "vpn_generation"
        const val EXTRA_DNS_MODE = "dns_mode"

        private val generationSeq = AtomicInteger(0)

        /** Call before [ACTION_START] so waiters ignore a previous establish. */
        fun nextGeneration(): Int {
            isEstablished.value = false
            activeGeneration.value = -1
            return generationSeq.incrementAndGet()
        }

        private val isEstablished = MutableStateFlow(false)
        val vpnEstablished: StateFlow<Boolean> = isEstablished.asStateFlow()

        private val activeGeneration = MutableStateFlow(-1)
        val vpnGeneration: StateFlow<Int> = activeGeneration.asStateFlow()

        private val forwarderSocksPort = MutableStateFlow(-1)
        private val forwarderDnsCryptPort = MutableStateFlow(-1)
        val hevSocksPort: StateFlow<Int> = forwarderSocksPort.asStateFlow()
        val hevDnsCryptPort: StateFlow<Int> = forwarderDnsCryptPort.asStateFlow()

        private val profileMode = MutableStateFlow<VpnProfileMode?>(null)
        val vpnProfileMode: StateFlow<VpnProfileMode?> = profileMode.asStateFlow()
    }
}
