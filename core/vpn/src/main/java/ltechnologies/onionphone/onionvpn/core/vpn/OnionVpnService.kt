package ltechnologies.onionphone.onionvpn.core.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode
import ltechnologies.onionphone.onionvpn.core.model.VpnEstablishResult
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.HevSocks5TunForwarder
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.OnionmasqTunForwarder
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDataPlaneFactory
import ltechnologies.onionphone.onionvpn.core.vpn.net.UnderlyingNetworkTracker
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.OnionmasqCircuitRepository
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
import ltechnologies.onionphone.onionvpn.core.vpn.profile.TunForwarder
import ltechnologies.onionphone.onionvpn.core.vpn.profile.VpnProfileBuilder
import org.torproject.onionmasq.ISocketProtect
import org.torproject.onionmasq.OnionMasq
import org.torproject.onionmasq.events.BootstrapEvent
import timber.log.Timber

/**
 * Android [VpnService] data plane — hev→SOCKS or onionmasq→Arti.
 *
 * Implements [ISocketProtect] so onionmasq can [VpnService.protect] Arti/PT sockets.
 */
class OnionVpnService : VpnService() {
    private var tunForwarder: TunForwarder? = null
    private var tunInterface: ParcelFileDescriptor? = null
    private var underlyingTracker: UnderlyingNetworkTracker? = null
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "onionvpn-vpn").apply { isDaemon = true }
    }
    private val protectBinder = object : android.os.Binder(), ISocketProtect {
        override fun protect(socket: Int): Boolean = this@OnionVpnService.protect(socket)
    }

    override fun onBind(intent: Intent?): IBinder? {
        // System VPN binding must use VpnService's binder; OnionMasq.bindVPNService uses a plain bind.
        if (intent?.action == SERVICE_INTERFACE) {
            return super.onBind(intent)
        }
        return protectBinder
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        // Do not bind onionmasq here: OnionMasq.init() has not run yet (getInstance throws).
        // OnionmasqTunForwarder rebinds after init.
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Always-on / sticky restart: OS may deliver null/empty action, or the sample Tor VPN
        // action "android.net.VpnService" (not SERVICE_INTERFACE bind — that is onBind only).
        val action = intent?.action
        if (action.isNullOrEmpty() || action == SERVICE_INTERFACE || action == "android.net.VpnService") {
            executor.execute {
                Timber.i(
                    "VPN system/always-on start action=%s — Blocking profile + coordinator",
                    action ?: "null",
                )
                applyBlockingDefaults()
                // Promote coordinator FGS immediately (VPN guide API 26+).
                notifyCoordinator(ACTION_ALWAYS_ON)
            }
            return START_STICKY
        }
        executor.execute {
            when (action) {
                ACTION_START -> applyProfile(intent, startForwarder = true)
                ACTION_BLOCK -> applyProfile(intent, startForwarder = false)
                // Tear down TUN without stopSelf — a following START must not race onDestroy.
                ACTION_STOP -> stopTunnel(destroyService = false)
                ACTION_DESTROY -> stopTunnel(destroyService = true)
            }
        }
        // User/coordinator teardown must not sticky-restart and leave hev/vpn threads alive.
        return when (action) {
            ACTION_STOP, ACTION_DESTROY -> START_NOT_STICKY
            else -> START_STICKY
        }
    }

    override fun onDestroy() {
        runCatching { OnionMasq.unbindVPNService() }
        // Avoid deadlock if onDestroy runs on the VPN executor thread after stopSelf().
        if (Thread.currentThread().name == "onionvpn-vpn") {
            runCatching { stopTunnel(destroyService = false) }
        } else {
            try {
                executor.submit { stopTunnel(destroyService = false) }
                    .get(8, java.util.concurrent.TimeUnit.SECONDS)
            } catch (e: Exception) {
                Timber.w(e, "VPN onDestroy stopTunnel wait failed — forcing local cleanup")
                runCatching { stopTunnel(destroyService = false) }
            }
        }
        executor.shutdownNow()
        runCatching {
            if (!executor.awaitTermination(3, java.util.concurrent.TimeUnit.SECONDS)) {
                Timber.w("VPN executor did not terminate cleanly")
            }
        }
        if (instance === this) {
            instance = null
        }
        super.onDestroy()
    }

    /**
     * Same-process teardown for [TunnelVpnBridge] — avoids racing Always-On / sticky
     * [startService] delivery that previously left TunDnsMux threads alive after Idle.
     */
    private fun teardownSync(destroyService: Boolean) {
        if (Thread.currentThread().name == "onionvpn-vpn") {
            stopTunnel(destroyService = destroyService)
            return
        }
        try {
            executor.submit { stopTunnel(destroyService = destroyService) }
                .get(15, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: Exception) {
            Timber.w(e, "teardownSync wait failed — forcing local cleanup")
            runCatching { stopTunnel(destroyService = destroyService) }
        }
    }

    /**
     * VPN interface is already deactivated when this runs (Android docs). Tear down
     * synchronously before [super.onRevoke] (default stopSelf) — Orbot ordering.
     * [protect] returns false after revoke; do not assume Arti uplink still works.
     */
    override fun onRevoke() {
        Timber.w("VPN permission revoked — synchronous teardown then super.onRevoke")
        try {
            executor.submit {
                stopTunnel(destroyService = false)
                notifyCoordinator(ACTION_REVOKED)
            }.get(8, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: Exception) {
            Timber.w(e, "onRevoke stopTunnel wait failed — forcing local cleanup")
            runCatching { stopTunnel(destroyService = false) }
            notifyCoordinator(ACTION_REVOKED)
        }
        super.onRevoke()
    }

    /**
     * Seamless profile swap (Mullvad/Orbot): establish the new TUN **before** closing the old
     * one so Android never has a window with no VPN routes (clearnet leak).
     */
    private fun applyProfile(intent: Intent, startForwarder: Boolean) {
        val preferences = preferencesFromVpnIntent(intent)
        val mode = intent.getStringExtra(EXTRA_PROFILE_MODE)
            ?.let { runCatching { VpnProfileMode.valueOf(it) }.getOrNull() }
            ?: if (startForwarder) VpnProfileMode.Connected else VpnProfileMode.Blocking
        val torSocksPort = intent.getIntExtra(EXTRA_TOR_SOCKS_PORT, TunnelEndpoints.DEFAULT_TOR_SOCKS_PORT)
        val dnsCryptPort = intent.getIntExtra(EXTRA_DNSCRYPT_PORT, TunnelEndpoints.DEFAULT_DNSCRYPT_LISTEN_PORT)
        val torDnsPort = intent.getIntExtra(EXTRA_TOR_DNS_PORT, TunnelEndpoints.DEFAULT_TOR_DNS_PORT)
        val synthesizeOnionAutomap = intent.getBooleanExtra(EXTRA_SYNTHESIZE_ONION_AUTOMAP, false)
        val generation = intent.getIntExtra(EXTRA_GENERATION, -1)
        val dnsMode = intent.getStringExtra(EXTRA_DNS_MODE)
            ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
            ?: DnsResolverMode.DNSCRYPT_MUX
        val tunDataPlane = intent.getStringExtra(EXTRA_TUN_DATA_PLANE)
            ?.let { runCatching { TunDataPlane.valueOf(it) }.getOrNull() }
            ?: TunDataPlane.HEV_SOCKS
        val torEngine = intent.getStringExtra(EXTRA_TOR_ENGINE)
            ?.let {
                runCatching {
                    ltechnologies.onionphone.onionvpn.core.model.TorEngine.valueOf(it)
                }.getOrNull()
            }
            ?: ltechnologies.onionphone.onionvpn.core.model.TorEngine.LITTLE_T
        val bridgeLines = intent.getStringExtra(EXTRA_BRIDGE_LINES)
        val exitCountry = intent.getStringExtra(EXTRA_EXIT_COUNTRY)
        val allowAdbClearnetLeak = preferences.allowAdbClearnetLeak

        // Signal waiters that a rebind is in progress without dropping routes yet.
        isRebinding.value = true
        isEstablished.value = false
        activeGeneration.value = -1
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1

        // Platform seamless handover: keep old TUN+forwarder until new establish() succeeds.
        // Closing/stopping the old plane first opens a clearnet or blackhole window.
        val previousTun = tunInterface
        val previousForwarder = tunForwarder

        val result = establish(preferences, mode)
        when (result) {
            is VpnEstablishResult.Success -> {
                // New iface owns egress (platform handover). Release old bridge port, then
                // bind the new forwarder — SocksUidBridge listen port is process-global.
                previousForwarder?.stop()
                if (tunForwarder === previousForwarder) tunForwarder = null
                var forwarderOk = true
                if (startForwarder && mode == VpnProfileMode.Connected) {
                    // Bind uplink BEFORE onionmasq/hev runProxy — empty underlying nets
                    // fail-closed and starve Arti guard connects (Tor VPN order).
                    startUnderlyingTracking()
                    try {
                        startForwarder(
                            torSocksPort,
                            dnsCryptPort,
                            torDnsPort,
                            dnsMode,
                            synthesizeOnionAutomap,
                            tunDataPlane = tunDataPlane,
                            torEngine = torEngine,
                            bridgeLines = bridgeLines,
                            exitCountry = exitCountry,
                            allowAdbClearnetLeak = allowAdbClearnetLeak,
                        )
                    } catch (error: Exception) {
                        // Previous forwarder already stopped — fail-closed blackhole TUN,
                        // never leave isRebinding=true (watchdog/validation would freeze).
                        // Clear published socks/DNS ports so wait/validators cannot see a
                        // stale "live" bridge after start() threw mid-bind.
                        forwarderOk = false
                        stopForwarder()
                        stopUnderlyingTracking()
                        Timber.e(error, "startForwarder failed after TUN establish — blackhole fail-closed")
                        OpTrace.error("vpn", "startForwarder failed", error)
                    }
                } else {
                    // Blocking / no-forwarder Connected: previous plane already stopped.
                    // Must clear updater+alive — otherwise downtime restore republishes
                    // hevSocksPort>0 while TUN is blackhole (no SocksUidBridge).
                    stopUnderlyingTracking()
                    stopForwarder()
                }
                if (previousTun != null && previousTun !== tunInterface) {
                    previousTun.close()
                }
                profileMode.value = mode
                if (generation >= 0) {
                    activeGeneration.value = generation
                }
                isEstablished.value = true
                isRebinding.value = false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    alwaysOnActive.value = isAlwaysOn
                    lockdownActive.value = isLockdownEnabled
                }
                Timber.i(
                    "VPN established mode=$mode killSwitch=${preferences.killSwitchEnabled} " +
                        "socks=$torSocksPort dnscrypt=$dnsCryptPort torDns=$torDnsPort gen=$generation " +
                        "forwarderOk=$forwarderOk alwaysOn=${alwaysOnActive.value} lockdown=${lockdownActive.value}",
                )
                OpTrace.info(
                    "vpn",
                    "established mode=$mode socks=$torSocksPort dnscrypt=$dnsCryptPort " +
                        "torDns=$torDnsPort gen=$generation forwarderOk=$forwarderOk",
                )
            }
            is VpnEstablishResult.Failure -> {
                OpTrace.error("vpn", "establish failed: ${result.reason}")
                Timber.e("VPN establish failed: ${result.reason}")
                // establish() only assigns tunInterface on success — previous plane untouched.
                if (previousTun != null && tunInterface == null) {
                    tunInterface = previousTun
                }
                if (previousForwarder != null && tunForwarder == null) {
                    tunForwarder = previousForwarder
                }
                if (previousTun != null) {
                    isEstablished.value = true
                    Timber.w("Kept previous TUN+forwarder after failed rebind")
                } else {
                    isEstablished.value = false
                    profileMode.value = null
                }
                isRebinding.value = false
            }
        }
    }

    private fun applyBlockingDefaults() {
        val preferences = TunnelPreferences(killSwitchEnabled = true)
        // Same generation contract as ACTION_BLOCK so FGS waiters see rebinding.
        nextGeneration()
        isEstablished.value = false
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1
        val previousTun = tunInterface
        val previousForwarder = tunForwarder
        val result = establish(preferences, VpnProfileMode.Blocking)
        when (result) {
            is VpnEstablishResult.Success -> {
                // Blocking owns routes — stop drain + clear publish gate after new iface is up.
                previousForwarder?.stop()
                if (tunForwarder === previousForwarder) tunForwarder = null
                stopForwarder()
                if (previousTun != null && previousTun !== tunInterface) {
                    previousTun.close()
                }
                profileMode.value = VpnProfileMode.Blocking
                stopUnderlyingTracking()
                activeGeneration.value = generationSeq.get()
                isEstablished.value = true
                isRebinding.value = false
            }
            is VpnEstablishResult.Failure -> {
                Timber.e("Always-on Blocking establish failed: ${result.reason}")
                if (previousTun != null && tunInterface == null) {
                    tunInterface = previousTun
                    tunForwarder = previousForwarder
                    isEstablished.value = true
                }
                isRebinding.value = false
            }
        }
    }

    private fun establish(
        preferences: TunnelPreferences,
        mode: VpnProfileMode,
    ): VpnEstablishResult {
        return OpTrace.step("vpn", "establish mode=$mode", ProcessLogLevel.INFO) {
            try {
                // Tor sample: fail-closed Connected establish when Private DNS hostname/DoT active.
                // Opportunistic-only is soft (inspector); hard gate matches SystemLeakInspector.
                if (mode == VpnProfileMode.Connected && isStrictPrivateDnsEnforced()) {
                    return@step VpnEstablishResult.Failure(
                        TunnelFailure.VpnEstablish(
                            "Private DNS (DoT) is enforced — set Private DNS → Off before connecting",
                        ).userMessage,
                    )
                }
                // Always-on owned by another app → refuse (cannot establish under their VPN).
                if (mode == VpnProfileMode.Connected) {
                    val foreign = foreignAlwaysOnOwner()
                    if (foreign != null) {
                        return@step VpnEstablishResult.Failure(
                            TunnelFailure.VpnEstablish(
                                "Always-on VPN is owned by $foreign — switch it to OnionVPN first",
                            ).userMessage,
                        )
                    }
                }
                // Strict OS lockdown pref: fail Connected unless lockdown is on (API 29+).
                if (mode == VpnProfileMode.Connected &&
                    preferences.requireOsLockdown &&
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                    !isLockdownEnabled
                ) {
                    return@step VpnEstablishResult.Failure(
                        TunnelFailure.VpnEstablish(
                            "Strict OS lockdown required — enable Always-on VPN + " +
                                "“Block connections without VPN” for OnionVPN",
                        ).userMessage,
                    )
                }
                // INCLUDE × lockdown: cannot mix allow-list with Tor-native BYPASS disallow;
                // under lockdown omitted apps are offline (never Orbot #774 skip-BYPASS).
                if (mode == VpnProfileMode.Connected &&
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                    VpnProfileBuilder.includeConflictsWithLockdown(
                        preferences,
                        lockdownEnabled = isLockdownEnabled,
                    )
                ) {
                    return@step VpnEstablishResult.Failure(
                        TunnelFailure.VpnEstablish(
                            VpnProfileBuilder.INCLUDE_LOCKDOWN_BLOCK_REASON,
                        ).userMessage,
                    )
                }
                val builder = VpnProfileBuilder.configure(this, preferences, mode)
                val tun = builder.establish()
                    ?: return@step VpnEstablishResult.Failure(
                        TunnelFailure.VpnEstablish(
                            "VpnService.Builder.establish() returned null " +
                                "(permission revoked or always-on conflict)",
                        ).userMessage,
                    )
                tunInterface = tun
                VpnEstablishResult.Success(mode)
            } catch (error: SecurityException) {
                OpTrace.error("vpn", "establish SecurityException", error)
                Timber.e(error, "VPN establish SecurityException")
                VpnEstablishResult.Failure(
                    TunnelFailure.VpnEstablish("VPN security permission denied", error).userMessage,
                )
            } catch (error: IllegalStateException) {
                OpTrace.error("vpn", "establish IllegalStateException", error)
                Timber.e(error, "VPN establish IllegalStateException")
                VpnEstablishResult.Failure(
                    TunnelFailure.VpnEstablish(
                        "VPN establish illegal state (self-exclusion / builder): ${error.message}",
                        error,
                    ).userMessage,
                )
            } catch (error: Exception) {
                OpTrace.error("vpn", "establish threw", error)
                Timber.e(error, "VPN establish threw")
                VpnEstablishResult.Failure(TunnelFailure.fromThrowable(error, "vpn.establish").userMessage)
            }
        }
    }

    /** Match ConnectivityHandler.onCapabilitiesChanged — VALIDATED, not forced true. */
    private fun currentValidatedUplink(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    /**
     * Strict Private DNS: DoT active on any network (incl. non-VPN) or mode=hostname.
     * Opportunistic alone is not hard-fail (matches SystemLeakInspector).
     */
    private fun isStrictPrivateDnsEnforced(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        val mode = runCatching {
            android.provider.Settings.Global.getString(contentResolver, "private_dns_mode")
        }.getOrNull().orEmpty()
        if (mode.equals("hostname", ignoreCase = true)) return true
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        return cm.allNetworks.any { network ->
            val lp = cm.getLinkProperties(network) ?: return@any false
            lp.isPrivateDnsActive && !lp.privateDnsServerName.isNullOrBlank()
        }
    }

    /** Package that owns Always-on VPN if it is not us; null if unset or ours. */
    private fun foreignAlwaysOnOwner(): String? {
        val pkg = runCatching {
            android.provider.Settings.Secure.getString(contentResolver, "always_on_vpn_app")
        }.getOrNull()?.takeIf { it.isNotBlank() && it.contains('.') } ?: return null
        return pkg.takeIf { it != packageName }
    }

    private fun startForwarder(
        torSocksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
        dnsMode: DnsResolverMode,
        synthesizeOnionAutomap: Boolean = false,
        tunDataPlane: TunDataPlane = TunDataPlane.HEV_SOCKS,
        torEngine: ltechnologies.onionphone.onionvpn.core.model.TorEngine =
            ltechnologies.onionphone.onionvpn.core.model.TorEngine.LITTLE_T,
        bridgeLines: String? = null,
        exitCountry: String? = null,
        allowAdbClearnetLeak: Boolean = false,
    ) {
        OpTrace.debug(
            "vpn",
            "startForwarder plane=$tunDataPlane engine=$torEngine socks=$torSocksPort " +
                "dnscrypt=$dnsCryptPort torDns=$torDnsPort",
        )
        val tun = tunInterface ?: return
        val effective = TunDataPlaneFactory.resolve(
            context = applicationContext,
            requested = tunDataPlane,
            engine = torEngine,
        )
        Timber.i(
            "VPN forwarder effectivePlane=$effective (requested=$tunDataPlane engine=$torEngine)",
        )

        val forwarder: TunForwarder = if (effective == TunDataPlane.ONIONMASQ) {
            circuitRepository.reset()
            onionmasqBootstrapReady.value = false
            onionmasqSawReadyForTraffic.set(false)
            onionmasqSawBootstrap100.set(false)
            OnionmasqTunForwarder(
                context = applicationContext,
                dnsMode = dnsMode,
                bridgeLines = bridgeLines,
                exitCountryCode = exitCountry,
                allowAdbClearnetLeak = allowAdbClearnetLeak,
                protectSocket = { socket -> protect(socket) },
                onFatal = { error ->
                    Timber.e(error, "onionmasq forwarder died — signalling fail-closed")
                    forwarderAlive.value = false
                    forwarderSocksPort.value = -1
                    forwarderDnsCryptPort.value = -1
                    onionmasqBootstrapReady.value = false
                },
                onBootstrap = { event: BootstrapEvent ->
                    // Tor VPN: CONNECTED when ready_for_traffic AND pct==100 (same event).
                    // Sticky across events so split emissions still converge.
                    if (event.isReadyForTraffic) onionmasqSawReadyForTraffic.set(true)
                    if (event.bootstrapPercent >= 100) onionmasqSawBootstrap100.set(true)
                    if (onionmasqSawReadyForTraffic.get() && onionmasqSawBootstrap100.get()) {
                        onionmasqBootstrapReady.value = true
                    } else {
                        Timber.d(
                            "onionmasq bootstrap partial ready=%s pct=%d — waiting for both",
                            event.isReadyForTraffic,
                            event.bootstrapPercent,
                        )
                    }
                    // ConnectivityHandler may have fired while isRunning==false; seed uplink
                    // from real VALIDATED state — never force true while offline (Tor VPN parity).
                    if (OnionMasq.isInitialized() && OnionMasq.isRunning()) {
                        val online = currentValidatedUplink()
                        runCatching {
                            org.torproject.onionmasq.OnionMasqJni.setInternetConnectivity(online)
                        }.onFailure { Timber.d(it, "seed setInternetConnectivity($online)") }
                    }
                    onOnionmasqBootstrap?.invoke(event)
                },
                onOnionmasqEvent = { event ->
                    circuitRepository.handleEvent(event)
                    onOnionmasqEvent?.invoke(event)
                },
            )
        } else {
            HevSocks5TunForwarder(
                context = applicationContext,
                dnsMode = dnsMode,
                protectSocket = { socket -> protect(socket) },
                onFatal = { error ->
                    Timber.e(error, "TUN forwarder died — signalling fail-closed")
                    forwarderAlive.value = false
                    forwarderSocksPort.value = -1
                    forwarderDnsCryptPort.value = -1
                },
            )
        }
        tunForwarder = forwarder
        // onionmasq Automap bridge starts with upstream=0 until sidecar is wired —
        // never publish the allocated apps SocksPort as "live" before setTorSocksUpstream.
        forwarderSocksPort.value = if (effective == TunDataPlane.ONIONMASQ) -1 else torSocksPort
        forwarderDnsCryptPort.value = dnsCryptPort
        forwarderAlive.value = true
        activeDataPlane.value = effective
        torSocksUpstreamUpdater = { port ->
            when (val f = tunForwarder) {
                is HevSocks5TunForwarder -> f.updateTorSocks(port)
                is OnionmasqTunForwarder -> f.updateTorSocks(port)
            }
        }
        forwarder.start(
            tunFd = tun,
            socksHost = TunnelEndpoints.LOOPBACK,
            socksPort = torSocksPort,
            dnsCryptPort = dnsCryptPort,
            torDnsPort = torDnsPort,
            synthesizeOnionAutomap = synthesizeOnionAutomap,
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
        torSocksUpstreamUpdater = null
        tunForwarder?.stop()
        tunForwarder = null
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1
        forwarderAlive.value = false
        onionmasqBootstrapReady.value = false
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
        onionmasqBootstrapReady.value = false
        activeDataPlane.value = TunDataPlane.HEV_SOCKS
        forwarderSocksPort.value = -1
        forwarderDnsCryptPort.value = -1
        forwarderAlive.value = false
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
        val intent = Intent().setClassName(
            packageName,
            "ltechnologies.onionphone.onionvpn.service.TunnelForegroundService",
        ).setAction(coordinatorAction)
        // Always-On / Private Space reopen: FGS start can be dropped once — retry briefly.
        var lastError: Throwable? = null
        repeat(4) { attempt ->
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    @Suppress("DEPRECATION")
                    startService(intent)
                }
                return
            } catch (e: Exception) {
                lastError = e
                Timber.w(e, "notifyCoordinator attempt %d failed ($coordinatorAction)", attempt + 1)
                try {
                    Thread.sleep(250L * (attempt + 1))
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return
                }
            }
        }
        Timber.e(lastError, "Could not notify tunnel coordinator ($coordinatorAction) after retries")
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
        /** App-side `.onion` Automap when using Arti (no native AutomapHostsOnResolve). */
        const val EXTRA_SYNTHESIZE_ONION_AUTOMAP = "synthesize_onion_automap"
        const val EXTRA_GENERATION = "vpn_generation"
        const val EXTRA_DNS_MODE = "dns_mode"
        const val EXTRA_VPN_APP_MODE = "vpn_app_mode"
        const val EXTRA_VPN_APP_PACKAGES = "vpn_app_packages"
        const val EXTRA_ALLOW_ADB_CLEARNET_LEAK = "allow_adb_clearnet_leak"
        const val EXTRA_REQUIRE_OS_LOCKDOWN = "require_os_lockdown"
        const val EXTRA_TUN_DATA_PLANE = "tun_data_plane"
        const val EXTRA_TOR_ENGINE = "tor_engine"
        const val EXTRA_BRIDGE_LINES = "bridge_lines"
        const val EXTRA_EXIT_COUNTRY = "exit_country"

        private val generationSeq = AtomicInteger(0)

        /** Live instance for same-process [teardownInProcess] (null when unbound). */
        @Volatile
        private var instance: OnionVpnService? = null

        /**
         * Tear down TUN/forwarder in-process (preferred over [ACTION_DESTROY] intents).
         * Falls back to no-op if the service was never created.
         */
        fun teardownInProcess(destroyService: Boolean) {
            val svc = instance
            if (svc == null) {
                Timber.i("teardownInProcess — no OnionVpnService instance")
                // Clear sticky flags so waiters do not hang on a dead session.
                isEstablished.value = false
                forwarderSocksPort.value = -1
                forwarderDnsCryptPort.value = -1
                forwarderAlive.value = false
                profileMode.value = null
                return
            }
            svc.teardownSync(destroyService)
        }

        fun preferencesFromVpnIntent(intent: Intent): TunnelPreferences {
            val mode = intent.getStringExtra(EXTRA_VPN_APP_MODE)
                ?.let { runCatching { VpnAppRoutingMode.valueOf(it) }.getOrNull() }
                ?: VpnAppRoutingMode.ALL
            val packages = intent.getStringArrayExtra(EXTRA_VPN_APP_PACKAGES)
                ?.filter { it.isNotBlank() }
                ?.toSet()
                ?: emptySet()
            return TunnelPreferences(
                routeAllTrafficThroughTor = intent.getBooleanExtra(EXTRA_ROUTE_ALL, true),
                killSwitchEnabled = intent.getBooleanExtra(EXTRA_KILL_SWITCH, true),
                vpnAppRoutingMode = mode,
                vpnAppPackages = packages,
                allowAdbClearnetLeak = intent.getBooleanExtra(EXTRA_ALLOW_ADB_CLEARNET_LEAK, false),
                // Must be explicit: TunnelPreferences default is true (release fail-closed).
                // Omitting the extra previously forced Strict OS lockdown on every Connected
                // establish even when DataStore had require_os_lockdown=false (Waydroid/debug).
                requireOsLockdown = intent.getBooleanExtra(EXTRA_REQUIRE_OS_LOCKDOWN, false),
            )
        }

        /** Invoked when Wi‑Fi/cell underlying network changes — wake Tor (SIGNAL ACTIVE). */
        @Volatile
        var onUnderlyingNetworkChanged: (() -> Unit)? = null

        /** Call before [ACTION_START] so waiters ignore a previous establish. */
        fun nextGeneration(): Int {
            isRebinding.value = true
            isEstablished.value = false
            activeGeneration.value = -1
            return generationSeq.incrementAndGet()
        }

        private val isEstablished = MutableStateFlow(false)
        val vpnEstablished: StateFlow<Boolean> = isEstablished.asStateFlow()

        private val isRebinding = MutableStateFlow(false)
        /** True while TUN is being swapped — validation must not treat as hard leak. */
        val vpnRebinding: StateFlow<Boolean> = isRebinding.asStateFlow()

        private val activeGeneration = MutableStateFlow(-1)
        val vpnGeneration: StateFlow<Int> = activeGeneration.asStateFlow()

        private val forwarderSocksPort = MutableStateFlow(-1)
        private val forwarderDnsCryptPort = MutableStateFlow(-1)
        val hevSocksPort: StateFlow<Int> = forwarderSocksPort.asStateFlow()
        val hevDnsCryptPort: StateFlow<Int> = forwarderDnsCryptPort.asStateFlow()

        private val profileMode = MutableStateFlow<VpnProfileMode?>(null)
        val vpnProfileMode: StateFlow<VpnProfileMode?> = profileMode.asStateFlow()

        private val forwarderAlive = MutableStateFlow(false)
        val tunForwarderAlive: StateFlow<Boolean> = forwarderAlive.asStateFlow()

        private val activeDataPlane = MutableStateFlow(TunDataPlane.HEV_SOCKS)
        val vpnDataPlane: StateFlow<TunDataPlane> = activeDataPlane.asStateFlow()

        private val onionmasqBootstrapReady = MutableStateFlow(false)
        val onionmasqReady: StateFlow<Boolean> = onionmasqBootstrapReady.asStateFlow()
        private val onionmasqSawReadyForTraffic = AtomicBoolean(false)
        private val onionmasqSawBootstrap100 = AtomicBoolean(false)

        val circuitRepository = OnionmasqCircuitRepository()

        @Volatile
        var onOnionmasqBootstrap: ((BootstrapEvent) -> Unit)? = null

        @Volatile
        var onOnionmasqEvent: ((org.torproject.onionmasq.events.OnionmasqEvent) -> Unit)? = null

        /**
         * Live updater for [HevSocks5TunForwarder.updateTorSocks] /
         * [OnionmasqTunForwarder.updateTorSocks] while TUN is up.
         * Cleared on forwarder stop.
         */
        @Volatile
        private var torSocksUpstreamUpdater: ((Int) -> Unit)? = null

        /**
         * Pause (0) or restore Tor SocksPort on the UID bridge without restarting hev.
         * Call from Tor downtime hooks so apps never dial Tor during DisableNetwork.
         */
        fun setTorSocksUpstream(port: Int) {
            val p = port.coerceAtLeast(0)
            val updater = torSocksUpstreamUpdater
            if (updater == null) {
                // No live bridge — never publish a positive socks as "wired Automap upstream".
                forwarderSocksPort.value = -1
                return
            }
            updater.invoke(p)
            // Publish 0→-1 so validators / waitForConnected treat pause as down
            // (bridge refuses CONNECT when upstream is 0).
            forwarderSocksPort.value = if (p > 0) p else -1
        }

        /**
         * Historical latch clear after VPN wait. Kept as no-op: [startForwarder] sets
         * alive; [onFatal] / [stopForwarder] clear it. Forcing true after wait hid
         * dead-plane races (stale ports while alive=false).
         */
        fun markForwarderAlive() {
            // no-op
        }

        /**
         * [VpnService.protect] for OpenVPN PROTECTFD (ics-openvpn management).
         * No-op / false when the VPN service instance is not alive.
         */
        fun protectSocket(fd: Int): Boolean =
            instance?.protect(fd) ?: false

        private val alwaysOnActive = MutableStateFlow(false)
        val vpnAlwaysOn: StateFlow<Boolean> = alwaysOnActive.asStateFlow()

        private val lockdownActive = MutableStateFlow(false)
        val vpnLockdown: StateFlow<Boolean> = lockdownActive.asStateFlow()
    }
}
