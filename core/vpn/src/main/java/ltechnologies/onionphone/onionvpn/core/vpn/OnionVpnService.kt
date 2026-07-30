package ltechnologies.onionphone.onionvpn.core.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnEstablishResult
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.HevSocks5TunForwarder
import ltechnologies.onionphone.onionvpn.core.vpn.net.UnderlyingNetworkTracker
import ltechnologies.onionphone.onionvpn.core.vpn.profile.TunForwarder
import ltechnologies.onionphone.onionvpn.core.vpn.profile.VpnProfileBuilder
import timber.log.Timber

/**
 * Android [VpnService] data plane — builds TUN profiles and runs hev → SocksUidBridge → Tor.
 *
 * Sequential applyProfile:
 * 1. Parse intent prefs/mode/ports/generation
 * 2. [VpnProfileBuilder.configure] + establish TUN (before closing old)
 * 3. Start [HevSocks5TunForwarder] (TunDnsMux + hev TCP + per-UID SOCKS bridge)
 * 4. [UnderlyingNetworkTracker] for SIGNAL ACTIVE on net change
 *
 * Coordinator: [ltechnologies.onionphone.onionvpn.service.TunnelForegroundService].
 */
class OnionVpnService : VpnService() {
    private var tunForwarder: TunForwarder? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var underlyingTracker: UnderlyingNetworkTracker? = null
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "onionvpn-vpn").apply { isDaemon = true }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always-on / sticky restart: OS may deliver null action — fail-closed Blocking TUN
        // then ask the coordinator to bring Tor up (Orbot/Mullvad pattern).
        if (intent?.action.isNullOrEmpty()) {
            executor.execute {
                Timber.i("VPN started with empty action — establishing Blocking profile (always-on/sticky)")
                applyBlockingDefaults()
                notifyCoordinator(ACTION_ALWAYS_ON)
            }
            return START_STICKY
        }
        val action = intent?.action ?: return START_STICKY
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
        // Run teardown on the VPN thread and wait — shutdown() alone can drop stopTunnel.
        try {
            executor.submit { stopTunnel() }.get(8, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: Exception) {
            Timber.w(e, "VPN onDestroy stopTunnel wait failed — forcing local cleanup")
            runCatching { stopTunnel() }
        }
        executor.shutdown()
        super.onDestroy()
    }

    override fun onRevoke() {
        Timber.w("VPN permission revoked — tearing down and notifying coordinator")
        executor.execute {
            stopTunnel(destroyService = false)
            notifyCoordinator(ACTION_REVOKED)
        }
        super.onRevoke()
    }

    /**
     * Seamless profile swap (Mullvad/Orbot): establish the new TUN **before** closing the old
     * one so Android never has a window with no VPN routes (clearnet leak).
     */
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
        val torDnsPort = intent.getIntExtra(EXTRA_TOR_DNS_PORT, TunnelEndpoints.DEFAULT_TOR_DNS_PORT)
        val generation = intent.getIntExtra(EXTRA_GENERATION, -1)
        val dnsMode = intent.getStringExtra(EXTRA_DNS_MODE)
            ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
            ?: DnsResolverMode.DNSCRYPT_MUX

        // Signal waiters that a rebind is in progress without dropping routes yet.
        isEstablished.value = false
        activeGeneration.value = -1
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1

        val previousTun = tunInterface
        val previousForwarder = tunForwarder
        tunForwarder = null

        // Stop draining the old TUN first — packets blackhole (fail-closed) while we swap.
        previousForwarder?.stop()

        val result = establish(preferences, mode)
        when (result) {
            is VpnEstablishResult.Success -> {
                // New TUN owns routes — safe to close the previous fd.
                if (previousTun != null && previousTun !== tunInterface) {
                    previousTun.close()
                }
                if (startForwarder && mode == VpnProfileMode.Connected) {
                    startForwarder(torSocksPort, dnsCryptPort, torDnsPort, dnsMode)
                    startUnderlyingTracking()
                } else {
                    stopUnderlyingTracking()
                }
                profileMode.value = mode
                if (generation >= 0) {
                    activeGeneration.value = generation
                }
                isEstablished.value = true
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    alwaysOnActive.value = isAlwaysOn
                    lockdownActive.value = isLockdownEnabled
                }
                Timber.i(
                    "VPN established mode=$mode killSwitch=${preferences.killSwitchEnabled} " +
                        "socks=$torSocksPort dnscrypt=$dnsCryptPort torDns=$torDnsPort gen=$generation " +
                        "alwaysOn=${alwaysOnActive.value} lockdown=${lockdownActive.value}",
                )
            }
            is VpnEstablishResult.Failure -> {
                Timber.e("VPN establish failed: ${result.reason}")
                // Keep previous TUN if still open so we do not open a clearnet window.
                if (previousTun != null && tunInterface == null) {
                    tunInterface = previousTun
                    isEstablished.value = true
                    Timber.w("Restored previous TUN after failed rebind")
                } else {
                    previousTun?.close()
                    isEstablished.value = false
                    profileMode.value = null
                }
            }
        }
    }

    private fun applyBlockingDefaults() {
        val preferences = TunnelPreferences(killSwitchEnabled = true)
        isEstablished.value = false
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1
        stopForwarder()
        val previousTun = tunInterface
        val result = establish(preferences, VpnProfileMode.Blocking)
        when (result) {
            is VpnEstablishResult.Success -> {
                previousTun?.close()
                profileMode.value = VpnProfileMode.Blocking
                stopUnderlyingTracking()
                val gen = generationSeq.incrementAndGet()
                activeGeneration.value = gen
                isEstablished.value = true
            }
            is VpnEstablishResult.Failure -> {
                Timber.e("Always-on Blocking establish failed: ${result.reason}")
                if (previousTun != null && tunInterface == null) {
                    tunInterface = previousTun
                    isEstablished.value = true
                } else {
                    previousTun?.close()
                }
            }
        }
    }

    private fun establish(
        preferences: TunnelPreferences,
        mode: VpnProfileMode,
    ): VpnEstablishResult {
        return try {
            val builder = VpnProfileBuilder.configure(this, preferences, mode)
            val tun = builder.establish()
                ?: return VpnEstablishResult.Failure(
                    TunnelFailure.VpnEstablish(
                        "VpnService.Builder.establish() returned null " +
                            "(permission revoked or always-on conflict)",
                    ).userMessage,
                )
            tunInterface = tun
            VpnEstablishResult.Success(mode)
        } catch (error: SecurityException) {
            Timber.e(error, "VPN establish SecurityException")
            VpnEstablishResult.Failure(
                TunnelFailure.VpnEstablish("VPN security permission denied", error).userMessage,
            )
        } catch (error: IllegalStateException) {
            Timber.e(error, "VPN establish IllegalStateException")
            VpnEstablishResult.Failure(
                TunnelFailure.VpnEstablish(
                    "VPN establish illegal state (self-exclusion / builder): ${error.message}",
                    error,
                ).userMessage,
            )
        } catch (error: Exception) {
            Timber.e(error, "VPN establish threw")
            VpnEstablishResult.Failure(TunnelFailure.fromThrowable(error, "vpn.establish").userMessage)
        }
    }

    private fun startForwarder(
        torSocksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
        dnsMode: DnsResolverMode,
    ) {
        val tun = tunInterface ?: return
        // hev → SocksUidBridge → Tor with per-UID IsolateSOCKSAuth (native TCP + circuit UX).
        val forwarder = HevSocks5TunForwarder(
            context = applicationContext,
            dnsMode = dnsMode,
            protectSocket = { socket -> protect(socket) },
            onFatal = { error ->
                Timber.e(error, "TUN forwarder died — signalling fail-closed")
                forwarderAlive.value = false
            },
        )
        tunForwarder = forwarder
        forwarderSocksPort.value = torSocksPort
        forwarderDnsCryptPort.value = dnsCryptPort
        forwarderAlive.value = true
        forwarder.start(
            tunFd = tun,
            socksHost = TunnelEndpoints.LOOPBACK,
            socksPort = torSocksPort,
            dnsCryptPort = dnsCryptPort,
            torDnsPort = torDnsPort,
        )
    }

    private fun startUnderlyingTracking() {
        if (underlyingTracker == null) {
            underlyingTracker = UnderlyingNetworkTracker(
                applicationContext,
                this,
                onUnderlyingChanged = { onUnderlyingNetworkChanged?.invoke() },
            )
        }
        underlyingTracker?.start()
    }

    private fun stopUnderlyingTracking() {
        underlyingTracker?.stop()
        underlyingTracker = null
    }

    private fun stopForwarder() {
        tunForwarder?.stop()
        tunForwarder = null
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1
        forwarderAlive.value = false
    }

    private fun stopTunnel(destroyService: Boolean = true) {
        stopUnderlyingTracking()
        stopForwarder()
        tunInterface?.close()
        tunInterface = null
        isEstablished.value = false
        activeGeneration.value = -1
        profileMode.value = null
        alwaysOnActive.value = false
        lockdownActive.value = false
        if (destroyService) {
            stopSelf()
        }
    }

    /**
     * Notify [TunnelForegroundService] without a hard module dependency — uses the
     * public action strings mirrored in the app module.
     */
    private fun notifyCoordinator(action: String) {
        val coordinatorAction = when (action) {
            ACTION_REVOKED -> "ltechnologies.onionphone.onionvpn.tunnel.REVOKED"
            ACTION_ALWAYS_ON -> "ltechnologies.onionphone.onionvpn.tunnel.ALWAYS_ON"
            else -> return
        }
        runCatching {
            startService(
                Intent().setClassName(
                    packageName,
                    "ltechnologies.onionphone.onionvpn.service.TunnelForegroundService",
                ).setAction(coordinatorAction),
            )
        }.onFailure { error ->
            Timber.w(error, "Could not notify tunnel coordinator ($coordinatorAction)")
        }
    }

    companion object {
        const val ACTION_START = "ltechnologies.onionphone.onionvpn.START"
        const val ACTION_BLOCK = "ltechnologies.onionphone.onionvpn.BLOCK"
        const val ACTION_STOP = "ltechnologies.onionphone.onionvpn.STOP"
        const val ACTION_DESTROY = "ltechnologies.onionphone.onionvpn.DESTROY"
        private const val ACTION_REVOKED = "revoked"
        private const val ACTION_ALWAYS_ON = "always_on"
        const val EXTRA_ROUTE_ALL = "route_all"
        const val EXTRA_KILL_SWITCH = "kill_switch"
        const val EXTRA_PROFILE_MODE = "profile_mode"
        const val EXTRA_TOR_SOCKS_PORT = "tor_socks_port"
        const val EXTRA_DNSCRYPT_PORT = "dnscrypt_port"
        const val EXTRA_TOR_DNS_PORT = "tor_dns_port"
        const val EXTRA_GENERATION = "vpn_generation"
        const val EXTRA_DNS_MODE = "dns_mode"

        private val generationSeq = AtomicInteger(0)

        /** Invoked when Wi‑Fi/cell underlying network changes — wake Tor (SIGNAL ACTIVE). */
        @Volatile
        var onUnderlyingNetworkChanged: (() -> Unit)? = null

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

        private val forwarderAlive = MutableStateFlow(true)
        val tunForwarderAlive: StateFlow<Boolean> = forwarderAlive.asStateFlow()

        /** After a successful hev rebind, clear the dead-forwarder latch. */
        fun markForwarderAlive() {
            forwarderAlive.value = true
        }

        private val alwaysOnActive = MutableStateFlow(false)
        val vpnAlwaysOn: StateFlow<Boolean> = alwaysOnActive.asStateFlow()

        private val lockdownActive = MutableStateFlow(false)
        val vpnLockdown: StateFlow<Boolean> = lockdownActive.asStateFlow()
    }
}
