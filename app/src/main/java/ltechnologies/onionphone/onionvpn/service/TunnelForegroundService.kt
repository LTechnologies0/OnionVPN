package ltechnologies.onionphone.onionvpn.service

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.IBinder
import android.os.PowerManager
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import ltechnologies.onionphone.onionvpn.BuildConfig
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelPortAllocator
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.model.observability.MemoryHygiene
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlHealth
import ltechnologies.onionphone.onionvpn.OnionVpnApplication
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.validation.TunnelValidator
import ltechnologies.onionphone.onionvpn.core.validation.path.TorPathValidator
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.dns.OnionAutomapAllocator
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.ArtiSocksRoleMux
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDataPlaneFactory
import ltechnologies.onionphone.onionvpn.core.vpn.net.TorBandwidthSampler
import ltechnologies.onionphone.onionvpn.core.vpn.pac.PacProxyServer
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.service.lifecycle.TunnelStabilityRecovery
import ltechnologies.onionphone.onionvpn.service.lifecycle.TunnelThroughputTracker
import ltechnologies.onionphone.onionvpn.threat.repo.DomainReputationRepository
import timber.log.Timber
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Foreground coordinator — InviZible control/data-plane split:
 *
 * 1. Blocking TUN first when kill-switch is on (Mullvad: never clearnet during bootstrap)
 * 2. Tor bootstrap (SOCKS + DNSPort on loopback)
 * 3. DNSCrypt (upstream via Tor SOCKS, bootstrap via Tor DNSPort)
 * 4. VPN TUN Connected (hev-socks5 → Tor SOCKS; DNS via TunDnsMux or FakeDNS)
 * 5. Validation (Android APIs + runtime probes)
 */
@AndroidEntryPoint
class TunnelForegroundService : Service() {
    @Inject lateinit var tor: TorProcessManager
    @Inject lateinit var dnsCrypt: DnsCryptProcessManager
    @Inject lateinit var preferencesStore: TunnelPreferencesStore
    @Inject lateinit var firewallEngine: InteractiveFirewallEngine
    @Inject lateinit var domainReputation: DomainReputationRepository
    @Inject lateinit var circuitLifecycle: ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lifecycleMutex = Mutex()
    /** PARTIAL_WAKE_LOCK while tunnel up (OnionShare/onionwrapper pattern). */
    private var tunnelWakeLock: PowerManager.WakeLock? = null
    private var tunnelJob: Job? = null
    private var validationJob: Job? = null
    private var throughputJob: Job? = null
    private var forwarderWatchJob: Job? = null
    private var newNymJob: Job? = null
    @Volatile private var identityRefreshing: Boolean = false
    private var preferences = TunnelPreferences()
    private var runtimePorts: TunnelRuntimePorts? = null
    private val bandwidthSampler by lazy { TorBandwidthSampler(applicationInfo.uid) }
    private val throughputTracker by lazy { TunnelThroughputTracker(bandwidthSampler) }
    private val stabilityRecovery by lazy { TunnelStabilityRecovery(tor, scope) }
    private val throughputText: String get() = throughputTracker.displayText
    private val notifications by lazy { TunnelNotifications(this) }
    private var lastNotificationText: String? = null
    private var lastNotificationUpdateMs: Long = 0L
    private val vpnBridge by lazy { TunnelVpnBridge(this) }
    private val artiSocksRoleMux = ArtiSocksRoleMux()
    private val pacServer by lazy { PacProxyServer() }
    @Volatile private var pendingNetworkRecover = false
    @Volatile private var pendingForwarderCheck = false
    @Volatile private var lastHardNetworkRecoverMs = 0L
    @Volatile private var softNetworkFailStreak = 0

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        notifications.createChannel()
        tor.onClientDnsCacheClear = {
            // Tor CLEARDNSCACHE / NEWNYM parity: drop app Automap + DNSCrypt sticky IPs
            // so a new circuit cannot reuse prior hostname→IP bindings.
            DnsHostnameCache.clear()
            OnionAutomapAllocator.clear()
            scope.launch(Dispatchers.IO) {
                dnsCrypt.clearQueryCache().onFailure {
                    Timber.w(it, "DNSCrypt query cache clear failed")
                }
            }
        }
        // Tor control-spec: DisableNetwork closes outbound sockets. Pause bridges first
        // so SOCKS CONNECT never races Tor (avoids status=1 / "DisableNetwork set" spam).
        tor.onTorDowntimeChanged = { down ->
            val ports = runtimePorts
            if (down) {
                Timber.i("Tor downtime: pause SOCKS bridges")
                OnionVpnService.setTorSocksUpstream(0)
                pacServer.updateUpstream(0, ports?.dnsCryptListenPort ?: 0)
            } else {
                val socks = ports?.torSocksPort ?: 0
                val dns = ports?.dnsCryptListenPort ?: 0
                Timber.i("Tor downtime end: restore SOCKS bridges socks=%d dnscrypt=%d", socks, dns)
                if (socks > 0) {
                    OnionVpnService.setTorSocksUpstream(socks)
                    pacServer.updateUpstream(socks, dns)
                }
            }
        }
        OnionVpnService.onUnderlyingNetworkChanged = {
            // Never block the main looper with ControlPort / Arti I/O.
            scope.launch(Dispatchers.IO) {
                recoverUnderlyingNetwork(fromPending = false)
            }
        }
        OnionVpnService.onOnionmasqEvent = { event ->
            when (event) {
                is org.torproject.onionmasq.events.NewConnectionEvent -> {
                    val hops = event.circuit?.joinToString(">") { r ->
                        r.country_code ?: "?"
                    }.orEmpty()
                    Timber.i(
                        "onionmasq conn uid=%d %s→%s tor=%s hops=%s",
                        event.appId,
                        event.proxySrc,
                        event.proxyDst,
                        event.torDst,
                        hops,
                    )
                    ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer.append(
                        ltechnologies.onionphone.onionvpn.logging.LogSource.TOR,
                        "onionmasq: uid=${event.appId} ${event.torDst} [$hops]",
                        isError = false,
                    )
                }
                is org.torproject.onionmasq.events.FailedConnectionEvent -> {
                    Timber.w(
                        "onionmasq fail uid=%d %s→%s err=%s",
                        event.appId,
                        event.proxySrc,
                        event.proxyDst,
                        event.error,
                    )
                    ltechnologies.onionphone.onionvpn.logging.TunnelLogBuffer.append(
                        ltechnologies.onionphone.onionvpn.logging.LogSource.TOR,
                        "onionmasq fail uid=${event.appId} ${event.torDst}: ${event.error}",
                        isError = true,
                    )
                }
                is org.torproject.onionmasq.events.BootstrapEvent -> {
                    Timber.i(
                        "onionmasq bootstrap %d%% ready=%s %s",
                        event.bootstrapPercent,
                        event.isReadyForTraffic,
                        event.bootstrapStatus,
                    )
                    // Dual TorClient: arti-mobile status can sit at ~15% while onionmasq
                    // finishes microdescs — surface onionmasq progress during VPN bring-up.
                    val phase = _snapshot.value.phase
                    if (phase == TunnelPhase.StartingVpn || phase == TunnelPhase.Validating) {
                        val summary = event.bootstrapStatus?.takeIf { it.isNotBlank() }
                            ?: _snapshot.value.torBootstrapSummary
                        _snapshot.update { prev ->
                            prev.copy(
                                torBootstrapProgress = event.bootstrapPercent.coerceIn(0, 100),
                                torBootstrapSummary = summary,
                            )
                        }
                    }
                }
                else -> Unit
            }
        }
    }

    private suspend fun recoverUnderlyingNetwork(fromPending: Boolean) {
        val phase = _snapshot.value.phase
        if (phase != TunnelPhase.Connected) {
            Timber.i("Underlying network change ignored — phase=%s", phase)
            return
        }
        if (tor.isInMaintenance) {
            pendingNetworkRecover = true
            Timber.i("Underlying network change deferred — Tor maintenance")
            return
        }
        pendingNetworkRecover = false
        val soft = tor.onNetworkChanged()
        if (soft.isSuccess) {
            softNetworkFailStreak = 0
            return
        }
        Timber.w(soft.exceptionOrNull(), "Tor soft network recovery failed")
        softNetworkFailStreak++
        val now = System.currentTimeMillis()
        if (softNetworkFailStreak < 2 || now - lastHardNetworkRecoverMs < HARD_NETWORK_RECOVER_COOLDOWN_MS) {
            Timber.i(
                "Hard recover deferred — streak=%d cooldown=%dms fromPending=%s",
                softNetworkFailStreak,
                HARD_NETWORK_RECOVER_COOLDOWN_MS,
                fromPending,
            )
            pendingNetworkRecover = true
            return
        }
        if (tor.isInMaintenance || _snapshot.value.phase != TunnelPhase.Connected) {
            pendingNetworkRecover = true
            Timber.i("Hard recover skipped — phase/maintenance changed")
            return
        }
        lastHardNetworkRecoverMs = now
        softNetworkFailStreak = 0
        tor.recoverNetworkHard().onFailure {
            Timber.w(it, "Tor hard network recovery failed")
            pendingNetworkRecover = true
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                // Promote FGS synchronously (OnionShare ShareService) — avoids
                // ForegroundServiceDidNotStartInTimeException if work is deferred.
                notifications.startForeground(TunnelPhase.StartingTor, throughputText)
                preferences = preferencesFromIntent(intent)
                scope.launch {
                    lifecycleMutex.withLock {
                        if (tunnelJob?.isActive == true) {
                            Timber.w("Ignoring duplicate START — tunnel already starting")
                            return@withLock
                        }
                        if (!_snapshot.value.canStart) {
                            Timber.w("Ignoring START — phase=%s", _snapshot.value.phase)
                            return@withLock
                        }
                        tunnelJob = scope.launch { runStartSequence() }
                    }
                }
                return START_STICKY
            }
            ACTION_STOP -> {
                val phase = _snapshot.value.phase
                if (phase == TunnelPhase.Idle || phase == TunnelPhase.Stopping) {
                    Timber.w("Ignoring STOP — phase=%s", phase)
                    return START_NOT_STICKY
                }
                newNymJob?.cancel()
                newNymJob = null
                identityRefreshing = false
                scope.launch { runStopSequence(userInitiated = true) }
                return START_NOT_STICKY
            }
            ACTION_NEWNYM -> {
                if (newNymJob?.isActive == true || identityRefreshing) {
                    Timber.w("Ignoring duplicate NEWNYM")
                    return START_STICKY
                }
                if (_snapshot.value.phase != TunnelPhase.Connected) {
                    Timber.w("NEWNYM ignored — phase=%s", _snapshot.value.phase)
                    return START_STICKY
                }
                newNymJob = scope.launch {
                    identityRefreshing = true
                    updateSnapshot(TunnelPhase.Connected)
                    validationJob?.cancel()
                    validationJob = null
                    val result = try {
                        if (OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ) {
                            // Dual TorClient interim: rotate onionmasq app circuits AND
                            // arti-mobile (DNSCrypt / probe IsolationTokens).
                            // Gate init — native refreshCircuits expect()-aborts pre-init.
                            if (org.torproject.onionmasq.OnionMasq.isInitialized() &&
                                org.torproject.onionmasq.OnionMasq.isRunning()
                            ) {
                                runCatching {
                                    org.torproject.onionmasq.OnionMasq.refreshCircuits()
                                }.onSuccess {
                                    Timber.i("New identity via onionmasq refreshCircuits()")
                                }.onFailure { err ->
                                    Timber.w(err, "onionmasq refreshCircuits failed")
                                }
                            } else {
                                Timber.w("onionmasq refreshCircuits skipped — not running")
                            }
                            if (ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                                    .OnionmasqSocksSidecar.INTERIM_USES_ARTI_MOBILE
                            ) {
                                tor.newNym().onSuccess {
                                    Timber.i("New identity also rotated interim arti-mobile")
                                }
                            } else {
                                Result.success(Unit)
                            }
                        } else {
                            tor.newNym()
                        }
                    } finally {
                        identityRefreshing = false
                    }
                    result.onSuccess {
                        Timber.i(
                            "New identity via %s",
                            when {
                                OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ &&
                                    ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                                        .OnionmasqSocksSidecar.INTERIM_USES_ARTI_MOBILE ->
                                    "onionmasq refreshCircuits + arti-mobile NEWNYM"
                                OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ ->
                                    "onionmasq refreshCircuits"
                                tor.engine.capabilities.classicControlPlane -> "control NEWNYM"
                                else -> "Arti restart"
                            },
                        )
                        updateSnapshot(_snapshot.value.phase)
                    }
                    result.onFailure { err ->
                        Timber.e(err, "NEWNYM failed")
                        updateSnapshot(
                            _snapshot.value.phase,
                            lastError = TunnelFailure.userMessageOf(err, "newnym"),
                        )
                    }
                    if (_snapshot.value.phase == TunnelPhase.Connected) {
                        startPeriodicValidation()
                    }
                }
                return START_STICKY
            }
            ACTION_APPLY_CIRCUIT_TIMING -> {
                val dirt = intent.getIntExtra(EXTRA_TOR_MAX_DIRTINESS, preferences.torMaxCircuitDirtinessSec)
                val period = intent.getIntExtra(EXTRA_TOR_NEW_CIRCUIT, preferences.torNewCircuitPeriodSec)
                preferences = preferences.copy(
                    torMaxCircuitDirtinessSec = dirt,
                    torNewCircuitPeriodSec = period,
                )
                scope.launch {
                    if (_snapshot.value.phase != TunnelPhase.Connected) {
                        Timber.i("Circuit timing ignored — phase=%s", _snapshot.value.phase)
                        return@launch
                    }
                    if (!preferences.torEngine.capabilities.liveCircuitTiming &&
                        !preferences.torEngine.capabilities.liveSetConf
                    ) {
                        Timber.i("Circuit timing ignored on %s", preferences.torEngine)
                        return@launch
                    }
                    tor.applyCircuitTimingLive(dirt, period)
                        .onSuccess { Timber.i("Live circuit timing applied dirt=%d period=%d", dirt, period) }
                        .onFailure { Timber.w(it, "Live circuit timing SETCONF failed") }
                }
                return START_STICKY
            }
            ACTION_REVOKED -> {
                Timber.w("VPN revoked by system — fail-closed teardown")
                scope.launch {
                    lifecycleMutex.withLock {
                        tunnelJob?.cancel()
                        tunnelJob = null
                        newNymJob?.cancel()
                        newNymJob = null
                        identityRefreshing = false
                        validationJob?.cancel()
                        validationJob = null
                        stopThroughputUpdates()
                        dnsCrypt.stop()
                        tor.stop()
                        releaseTunnelWakeLock()
                        updateSnapshot(
                            phase = TunnelPhase.Error,
                            torRunning = false,
                            dnsCryptRunning = false,
                            vpnEstablished = false,
                            lastError = "VPN permission revoked — traffic unprotected until reconnect",
                        )
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
                return START_NOT_STICKY
            }
            ACTION_ALWAYS_ON -> {
                // Sync FGS promotion before any await (same as ACTION_START).
                notifications.startForeground(TunnelPhase.StartingTor, throughputText)
                val phase = _snapshot.value.phase
                if (tunnelJob?.isActive == true) {
                    return START_STICKY
                }
                if (phase == TunnelPhase.Connected || phase == TunnelPhase.Validating ||
                    phase == TunnelPhase.StartingTor || phase == TunnelPhase.StartingDnsCrypt ||
                    phase == TunnelPhase.StartingVpn
                ) {
                    Timber.w("Ignoring ALWAYS_ON — already up phase=%s", phase)
                    return START_STICKY
                }
                // Blocking TUN already up from OnionVpnService; bring Tor path online.
                tunnelJob = scope.launch {
                    preferences = preferencesStore.preferences.first()
                    runStartSequence()
                }
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        OnionVpnService.onUnderlyingNetworkChanged = null
        throughputJob?.cancel()
        scope.cancel()
        releaseTunnelWakeLock()
        super.onDestroy()
    }

    private suspend fun runStartSequence() {
        lifecycleMutex.withLock {
            try {
                startTunnel()
            } catch (error: CancellationException) {
                val phase = _snapshot.value.phase
                if (phase == TunnelPhase.StartingTor ||
                    phase == TunnelPhase.StartingDnsCrypt ||
                    phase == TunnelPhase.StartingVpn ||
                    phase == TunnelPhase.Validating
                ) {
                    Timber.w("Tunnel start cancelled during %s", phase)
                    updateSnapshot(
                        TunnelPhase.Error,
                        lastError = "Tunnel start cancelled",
                    )
                }
                throw error
            } catch (error: Exception) {
                Timber.e(error, "Tunnel start crashed")
                val failure = TunnelFailure.fromThrowable(
                    error,
                    context = "tunnel.start",
                    bootstrapProgress = tor.controlStatus.value.bootstrapProgress,
                )
                handleFailure(
                    message = failure.userMessage,
                    fromValidation = false,
                    stopTorProcesses = failure.stopTor,
                )
            }
        }
    }

    private suspend fun startTunnel() {
        OpTrace.info("tunnel", "startTunnel begin engine=${preferences.torEngine}")
        acquireTunnelWakeLock(BOOTSTRAP_WAKELOCK_TIMEOUT_MS)
        preferences = applyDebugBridgeOverride(preferences)
        preferences = applyDebugEngineOverride(preferences)
        DiagnosticsGate.setNoLogsEnabled(preferences.noLogsEnabled)
        // Cancel Tor-bound downloads before we tear down / recycle SOCKS ports.
        domainReputation.onTorUnavailable()

        // Always own the default route BEFORE Tor bootstrap (constant kill-switch).
        if (VpnService.prepare(this) == null) {
            updateSnapshot(TunnelPhase.StartingVpn)
            OpTrace.stepSuspending("tunnel", "blocking_tun", ProcessLogLevel.INFO) {
                val blockingGen = OnionVpnService.nextGeneration()
                vpnBridge.startBlocking(preferences, blockingGen)
                if (!vpnBridge.waitForBlocking(blockingGen)) {
                    handleFailure("Kill-switch Blocking TUN failed to establish", fromValidation = false)
                    return@stepSuspending
                }
                OpTrace.info("tunnel", "Kill-switch Blocking TUN up before Tor bootstrap")
            }
            if (_snapshot.value.phase == TunnelPhase.Error) {
                return
            }
        }

        updateSnapshot(TunnelPhase.StartingTor)

        val ports = OpTrace.step("tunnel", "allocate_ports") {
            TunnelPortAllocator.allocate(preferences.torEngine)
        }
        runtimePorts = ports
        OpTrace.info(
            "tunnel",
            "ports engine=${preferences.torEngine} socks=${ports.torSocksPort} " +
                "dns=${ports.torDnsPort} dnscrypt=${ports.dnsCryptListenPort}",
        )
        Timber.i(
            "Allocated tunnel ports engine=${preferences.torEngine} socks=${ports.torSocksPort} " +
                "dnscryptSocks=${ports.torDnsCryptSocksPort} " +
                "probeSocks=${ports.torProbeSocksPort} " +
                "httpTunnel=${ports.torHttpTunnelPort} dns=${ports.torDnsPort} " +
                "dnscrypt=${ports.dnsCryptListenPort} dnsMode=${preferences.dnsResolverMode}",
        )
        OpTrace.step("tunnel", "pac_start") {
            runCatching {
                pacServer.start()
                pacServer.updateUpstream(ports.torSocksPort, ports.dnsCryptListenPort)
            }.onFailure {
                OpTrace.error("tunnel", "PAC server failed to start", it)
                Timber.e(it, "PAC server failed to start")
            }
        }

        val bootstrapUiJob = scope.launch {
            while (isActive) {
                delay(500)
                updateSnapshot(TunnelPhase.StartingTor, torRunning = tor.isRunning())
            }
        }
        // Resolve onionmasq vs hev before Tor start so prefs/UI stay honest.
        val effectivePlane = TunDataPlaneFactory.resolve(
            this,
            preferences.tunDataPlane,
            preferences.torEngine,
        )
        if (effectivePlane != preferences.tunDataPlane) {
            preferences = preferences.copy(tunDataPlane = effectivePlane)
            Timber.w("TUN data plane coerced to %s", effectivePlane)
        }

        val torResult = try {
            OpTrace.stepSuspending("tunnel", "tor_start", ProcessLogLevel.INFO) {
                tor.start(ports, preferences)
            }
        } finally {
            bootstrapUiJob.cancel()
        }
        if (torResult.isFailure) {
            val err = torResult.exceptionOrNull() ?: Exception("Tor failed")
            val failure = TunnelFailure.fromThrowable(
                err,
                context = "tor.start",
                bootstrapProgress = tor.controlStatus.value.bootstrapProgress,
            )
            handleFailure(failure.userMessage, fromValidation = false, stopTorProcesses = failure.stopTor)
            return
        }
        domainReputation.onTorReady()
        if (preferences.torEngine == TorEngine.ARTI) {
            // DNSCrypt IsolationTokens: arti-mobile role mux until onionmasq SOCKS sidecar
            // is available post-VPN (see OnionmasqSocksSidecar.INTERIM_USES_ARTI_MOBILE).
            OpTrace.step("tunnel", "arti_socks_role_mux") {
                artiSocksRoleMux.start(ports)
            }
        }

        updateSnapshot(TunnelPhase.StartingDnsCrypt, torRunning = true)
        val dnsResult = OpTrace.stepSuspending("tunnel", "dnscrypt_start", ProcessLogLevel.INFO) {
            dnsCrypt.start(preferences.dnsCryptServerName, ports, preferences)
        }
        if (dnsResult.isFailure) {
            val err = dnsResult.exceptionOrNull() ?: Exception("DNSCrypt failed")
            val failure = TunnelFailure.fromThrowable(err, context = "dnscrypt.start")
            handleFailure(
                message = failure.userMessage,
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }
        val useDnsCrypt = true
        pacServer.updateUpstream(ports.torSocksPort, ports.dnsCryptListenPort)
        updateSnapshot(TunnelPhase.StartingVpn, dnsCryptRunning = true)

        if (VpnService.prepare(this) != null) {
            handleFailure(
                TunnelFailure.VpnEstablish("VPN permission not granted — approve OnionVPN in system VPN dialog").userMessage,
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }

        val vpnGeneration = OnionVpnService.nextGeneration()
        OpTrace.stepSuspending("tunnel", "connected_tun", ProcessLogLevel.INFO) {
            vpnBridge.startConnected(preferences, ports, vpnGeneration)
            val vpnReady = vpnBridge.waitForConnected(vpnGeneration, ports)
            if (!vpnReady) {
                handleFailure(
                    TunnelFailure.VpnEstablish(
                        "VPN interface not established (timeout or establish() null)",
                    ).userMessage,
                    fromValidation = false,
                    stopTorProcesses = false,
                )
            }
        }
        // Blocking is also a terminal path for start (kill-switch engaged).
        val afterTun = _snapshot.value.phase
        if (afterTun == TunnelPhase.Error || afterTun == TunnelPhase.Blocking) return

        if (effectivePlane == TunDataPlane.ONIONMASQ) {
            // Cold microdesc fetch often exceeds 20s; wait for ready_for_traffic only.
            val ready = OnionVpnService.onionmasqReady.value ||
                withTimeoutOrNull(ONIONMASQ_BOOTSTRAP_TIMEOUT_MS) {
                    OnionVpnService.onionmasqReady.first { it }
                } == true
            val sidecar = ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.OnionmasqSocksSidecar.socksPortOrZero()
            Timber.i(
                "onionmasq bootstrapReady=%s socksSidecar=%d interimArtiMobile=%s",
                ready,
                sidecar,
                ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.OnionmasqSocksSidecar.INTERIM_USES_ARTI_MOBILE,
            )
            if (!ready) {
                handleFailure(
                    message = "onionmasq not ready for traffic (bootstrap timeout) — fail-closed",
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return
            }
        }

        val hevSocks = OnionVpnService.hevSocksPort.value
        val hevDns = OnionVpnService.hevDnsCryptPort.value
        val dnsPortExpected = if (useDnsCrypt) ports.dnsCryptListenPort else hevDns
        if (!vpnBridge.hevPortsMatch(ports, useDnsCrypt)) {
            handleFailure(
                message = "TUN forwarder port desync (plane=$effectivePlane socks=$hevSocks dns=$hevDns; " +
                    "expected socks=${ports.torSocksPort} dns=$dnsPortExpected)",
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }

        updateSnapshot(TunnelPhase.Validating, vpnEstablished = true)
        // Seed firewall prefs before Connected packets (ASK/DENY must not flip mid-flow).
        firewallEngine.start()
        // Wake Tor if dormant so DNSPort / SOCKS5A probes don't Poll/connect timeout.
        maybeSignalActive()
        val validations = runValidation(ports)
        val hardFails = validations.filter { TunnelValidator.isHardKillSwitchFailure(it) }
        val softFails = validations.filter {
            it.status == ValidationStatus.Fail && !TunnelValidator.isHardKillSwitchFailure(it)
        }

        softFails.forEach { check ->
            Timber.e("Soft FAIL (Tor kept) [${check.id}] ${check.label}: ${check.detail}")
        }

        if (hardFails.isNotEmpty()) {
            hardFails.forEach { check ->
                Timber.e("Hard FAIL [${check.id}] ${check.label}: ${check.detail}")
            }
            val summary = hardFails.joinToString("; ") { "${it.label}: ${it.detail}" }
            val torDead = hardFails.any { it.id == "tor.socks" } || !tor.isRunning()
            handleFailure(
                message = "Validation failed — $summary",
                fromValidation = true,
                validations = validations,
                stopTorProcesses = torDead,
            )
            return
        }

        // Hold CPU while Connected (OnionShare holds wake lock while Tor network on).
        acquireTunnelWakeLock(timeoutMs = null)

        updateSnapshot(
            phase = TunnelPhase.Connected,
            validations = validations,
            torRunning = true,
            dnsCryptRunning = useDnsCrypt && dnsCrypt.isRunning(),
            vpnEstablished = true,
        )
        // Wake Tor if we previously SIGNAL DORMANT from kill-switch Blocking (C Tor only).
        maybeSignalActive()
        if (preferences.torEngine.capabilities.liveCircuitTiming ||
            preferences.torEngine.capabilities.liveSetConf
        ) {
            tor.applyCircuitTimingLive(
                preferences.torMaxCircuitDirtinessSec,
                preferences.torNewCircuitPeriodSec,
            )
        }
        if (preferences.torEngine.capabilities.circuitInspection) {
            circuitLifecycle.start()
        } else {
            circuitLifecycle.stop()
        }
        startPeriodicValidation()
        startForwarderWatchdog()
        startThroughputUpdates()
        if (DiagnosticsGate.enabled()) {
            OnionVpnApplication.profiler(application)?.start()
        }
        OpTrace.info("tunnel", "Connected — diagnostics=${DiagnosticsGate.enabled()}")
        MemoryHygiene.afterHeavyWork("tunnel_connected")
    }

    private suspend fun runValidation(ports: TunnelRuntimePorts) = try {
        OpTrace.stepSuspending("tunnel", "validate", ProcessLogLevel.INFO) {
            withTimeout(VALIDATION_TIMEOUT_MS) {
                tor.refreshControlInfo()
                TunnelValidator.validateAll(
                    context = applicationContext,
                    torConfigFile = tor.runtimeConfigFile,
                    dnsCryptConfigFile = dnsCrypt.configFile,
                    vpnEstablished = OnionVpnService.vpnEstablished.value,
                    killSwitchEnabled = preferences.killSwitchEnabled,
                    runtimePorts = ports,
                    dnsResolverMode = preferences.dnsResolverMode,
                    torEngine = preferences.torEngine,
                ) + TorControlHealth.validate(
                    status = tor.controlStatus.value,
                    engine = preferences.torEngine,
                )
            }
        }
    } catch (error: Exception) {
        OpTrace.error("tunnel", "Validation timed out or failed", error)
        Timber.e(error, "Validation timed out or failed")
        // Soft timeout must not alone Block — but never promote on SOCKS TCP alone.
        // Re-run a fast hard-gate (wiring + routes + Private DNS / Always-on owner).
        val hardGate = runCatching {
            withTimeout(HARD_GATE_TIMEOUT_MS) {
                TunnelValidator.validateHardGate(
                    context = applicationContext,
                    dnsCryptConfigFile = dnsCrypt.configFile,
                    vpnEstablished = OnionVpnService.vpnEstablished.value,
                    killSwitchEnabled = preferences.killSwitchEnabled,
                    runtimePorts = ports,
                    dnsResolverMode = preferences.dnsResolverMode,
                )
            }
        }.getOrElse { gateError ->
            Timber.e(gateError, "Hard-gate after timeout failed")
            listOf(
                TorPathValidator.validateSocksOnly(socksPort = ports.torProbeSocksPort),
            )
        }
        listOf(
            ValidationCheck(
                id = "validation.timeout",
                label = "Tunnel validation",
                status = ValidationStatus.Fail,
                detail = error.message ?: "Validation failed",
                tripsKillSwitch = false,
            ),
        ) + hardGate
    }

    private suspend fun handleFailure(
        message: String,
        fromValidation: Boolean,
        validations: List<ValidationCheck> = emptyList(),
        /** Only stop Tor when SOCKS/process is dead — never nuke a live Tor path for soft faults. */
        stopTorProcesses: Boolean = true,
        alreadyHoldingLifecycleLock: Boolean = false,
    ) {
        if (alreadyHoldingLifecycleLock) {
            handleFailureLocked(message, fromValidation, validations, stopTorProcesses)
        } else {
            lifecycleMutex.withLock {
                handleFailureLocked(message, fromValidation, validations, stopTorProcesses)
            }
        }
    }

    private suspend fun handleFailureLocked(
        message: String,
        fromValidation: Boolean,
        validations: List<ValidationCheck>,
        stopTorProcesses: Boolean,
    ) {
        val phase = _snapshot.value.phase
        if (phase == TunnelPhase.Stopping || phase == TunnelPhase.Idle) {
            Timber.i("handleFailure ignored — phase=%s", phase)
            return
        }
        val bootstrapping = phase == TunnelPhase.StartingTor ||
            phase == TunnelPhase.StartingDnsCrypt ||
            phase == TunnelPhase.StartingVpn ||
            phase == TunnelPhase.Validating
        // Never leave Starting* stuck: defer only once Connected (NEWNYM / soft recover).
        if (!bootstrapping && (identityRefreshing || tor.isInMaintenance)) {
            Timber.i("handleFailure deferred — identity/maintenance (%s)", message)
            return
        }
        Timber.e("Tunnel failure: $message (stopTor=$stopTorProcesses fromValidation=$fromValidation)")
        // Keep wake lock in Blocking (Tor may still run); only release on full teardown.
        stopThroughputUpdates()

        val canBlock = VpnService.prepare(this) == null
        if (canBlock) {
            enterBlockingMode(message, validations, stopTorProcesses = stopTorProcesses)
            return
        }

        teardownModules(resetSnapshot = false, phase = TunnelPhase.Error, lastError = message, validations = validations)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Kill-switch: Blocking TUN blackholes **app** packets that cannot be Tor-routed.
     * Tor/DNSCrypt stay alive when [stopTorProcesses] is false so correctly-working
     * circuits / bidouilles (self-exclusion, dual SocksPorts, FakeDNS) are not torn down.
     */
    private suspend fun enterBlockingMode(
        message: String,
        validations: List<ValidationCheck>,
        stopTorProcesses: Boolean,
    ) {
        domainReputation.onTorUnavailable()
        updateSnapshot(TunnelPhase.Blocking, lastError = message, validations = validations)
        val gen = OnionVpnService.nextGeneration()
        vpnBridge.startBlocking(preferences, gen)
        if (!vpnBridge.waitForBlocking(gen)) {
            Timber.e("Kill-switch Blocking TUN failed to establish — tearing down")
            teardownModules(
                resetSnapshot = false,
                phase = TunnelPhase.Error,
                lastError = TunnelFailure.VpnEstablish(
                    "Kill-switch could not engage Blocking TUN after: $message",
                ).userMessage,
                validations = validations,
            )
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        if (stopTorProcesses) {
            dnsCrypt.stop()
            tor.stop()
            releaseTunnelWakeLock()
        } else {
            acquireTunnelWakeLock(timeoutMs = null)
            tor.signalDormant()
            Timber.i(
                "Kill-switch Blocking TUN only — engine=%s kept for recovery (dormant=%s)",
                preferences.torEngine,
                preferences.torEngine.capabilities.dormantSignals,
            )
        }
        updateSnapshot(
            phase = TunnelPhase.Blocking,
            torRunning = tor.isRunning(),
            dnsCryptRunning = dnsCrypt.isRunning(),
            vpnEstablished = OnionVpnService.vpnEstablished.value,
            lastError = message,
            validations = validations,
        )
        notifications.update(TunnelPhase.Blocking, throughputText)
    }

    private suspend fun runStopSequence(userInitiated: Boolean) {
        lifecycleMutex.withLock {
            tunnelJob?.cancel()
            tunnelJob = null
            newNymJob?.cancel()
            newNymJob = null
            identityRefreshing = false
            validationJob?.cancel()
            validationJob = null
            stopThroughputUpdates()
            forwarderWatchJob?.cancel()
            forwarderWatchJob = null
            firewallEngine.clearSessionRules()
            teardownModules(
                resetSnapshot = userInitiated,
                phase = TunnelPhase.Stopping,
                lastError = null,
            )
            if (userInitiated) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private suspend fun teardownModules(
        resetSnapshot: Boolean,
        phase: TunnelPhase,
        lastError: String?,
        validations: List<ValidationCheck> = emptyList(),
    ) {
        OpTrace.info("tunnel", "teardown phase=$phase error=${lastError ?: "-"}")
        OnionVpnApplication.profiler(application)?.stop()
        domainReputation.onTorUnavailable()
        updateSnapshot(
            phase,
            lastError = lastError,
            validations = validations,
            clearError = lastError == null,
        )
        validationJob?.cancel()
        validationJob = null
        circuitLifecycle.stop()
        firewallEngine.stop()
        runCatching { pacServer.stop() }
        vpnBridge.destroy()
        vpnBridge.waitUntilDown()
        dnsCrypt.stop()
        artiSocksRoleMux.stop()
        tor.stop()
        releaseTunnelWakeLock()
        MemoryHygiene.afterHeavyWork("tunnel_teardown")
        if (resetSnapshot) {
            runtimePorts = null
            throughputTracker.reset()
            _snapshot.value = TunnelSnapshot()
        }
    }

    private fun startForwarderWatchdog() {
        forwarderWatchJob?.cancel()
        forwarderWatchJob = scope.launch {
            OnionVpnService.tunForwarderAlive.collect { alive ->
                if (!alive && _snapshot.value.phase == TunnelPhase.Connected) {
                    if (tor.isInMaintenance || OnionVpnService.vpnRebinding.value) {
                        pendingForwarderCheck = true
                        Timber.i("TUN forwarder flap ignored — Tor maintenance / VPN rebind")
                        return@collect
                    }
                    pendingForwarderCheck = false
                    lifecycleMutex.withLock {
                        if (_snapshot.value.phase != TunnelPhase.Connected) return@withLock
                        if (tor.isInMaintenance || OnionVpnService.vpnRebinding.value) {
                            pendingForwarderCheck = true
                            Timber.i("TUN forwarder recovery deferred — Tor maintenance / rebind")
                            return@withLock
                        }
                        val ports = runtimePorts
                        if (ports != null && tor.isRunning() && isSocksReachable(ports.torSocksPort)) {
                            Timber.w("TUN forwarder died — Tor SOCKS still up; rebinding forwarder (keep Tor)")
                            val gen = OnionVpnService.nextGeneration()
                            vpnBridge.startConnected(preferences, ports, gen)
                            if (vpnBridge.waitForConnected(gen, ports)) {
                                OnionVpnService.markForwarderAlive()
                                Timber.i("UID forwarder rebound after forwarder death")
                                return@withLock
                            }
                        }
                        if (tor.isInMaintenance) {
                            pendingForwarderCheck = true
                            Timber.i("TUN forwarder kill-switch skipped — Tor maintenance")
                            return@withLock
                        }
                        Timber.e("TUN forwarder dead and Tor path unusable — kill-switch Blocking TUN")
                        handleFailure(
                            message = "TUN forwarder died",
                            fromValidation = true,
                            stopTorProcesses = !tor.isRunning(),
                            alreadyHoldingLifecycleLock = true,
                        )
                    }
                } else if (alive) {
                    pendingForwarderCheck = false
                }
            }
        }
    }

    private fun isSocksReachable(port: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(TunnelEndpoints.LOOPBACK, port), 1_000)
        }
        true
    } catch (_: Exception) {
        false
    }

    private fun startPeriodicValidation() {
        validationJob?.cancel()
        validationJob = scope.launch {
            var ticks = 0
            while (isActive) {
                delay(VALIDATION_INTERVAL_MS)
                if (_snapshot.value.phase != TunnelPhase.Connected) continue
                if (tor.isInMaintenance || OnionVpnService.vpnRebinding.value) {
                    Timber.i("Periodic validation deferred — Tor maintenance / VPN rebind")
                    continue
                }
                val ports = runtimePorts ?: continue
                ticks++
                val checks = if (ticks % FULL_VALIDATION_TICKS == 0) {
                    maybeSignalActive()
                    TunnelValidator.validateAll(
                        context = applicationContext,
                        torConfigFile = tor.runtimeConfigFile,
                        dnsCryptConfigFile = dnsCrypt.configFile,
                        vpnEstablished = OnionVpnService.vpnEstablished.value,
                        killSwitchEnabled = preferences.killSwitchEnabled,
                        runtimePorts = ports,
                        dnsResolverMode = preferences.dnsResolverMode,
                        includeExitIp = true,
                        torEngine = preferences.torEngine,
                    )
                } else {
                    TunnelValidator.validateLite(
                        context = applicationContext,
                        torConfigFile = tor.runtimeConfigFile,
                        dnsCryptConfigFile = dnsCrypt.configFile,
                        vpnEstablished = OnionVpnService.vpnEstablished.value,
                        killSwitchEnabled = preferences.killSwitchEnabled,
                        runtimePorts = ports,
                        dnsResolverMode = preferences.dnsResolverMode,
                        torEngine = preferences.torEngine,
                    )
                }
                // TOCTOU: NEWNYM / hard recover / TUN rebind may have started while probes ran.
                if (tor.isInMaintenance ||
                    OnionVpnService.vpnRebinding.value ||
                    _snapshot.value.phase != TunnelPhase.Connected
                ) {
                    Timber.i(
                        "Periodic validation discarded — maintenance=%s rebind=%s phase=%s",
                        tor.isInMaintenance,
                        OnionVpnService.vpnRebinding.value,
                        _snapshot.value.phase,
                    )
                    continue
                }
                val hardFails = checks.filter {
                    TunnelValidator.isHardKillSwitchFailure(it) &&
                        !(it.id == "vpn.not.established" && OnionVpnService.vpnRebinding.value)
                }
                val softFails = checks.filter {
                    it.status == ValidationStatus.Fail && !TunnelValidator.isHardKillSwitchFailure(it)
                }
                _snapshot.update { it.copy(validations = checks) }
                softFails.forEach { check ->
                    Timber.e("Periodic soft FAIL [${check.id}] ${check.label}: ${check.detail}")
                }
                if (hardFails.isNotEmpty()) {
                    if (tor.isInMaintenance ||
                        OnionVpnService.vpnRebinding.value ||
                        _snapshot.value.phase != TunnelPhase.Connected
                    ) {
                        Timber.i("Periodic hard FAIL ignored — Tor maintenance / rebind / phase changed")
                        continue
                    }
                    hardFails.forEach { check ->
                        Timber.e("Periodic hard FAIL [${check.id}] ${check.label}: ${check.detail}")
                    }
                    val summary = hardFails.joinToString("; ") { it.label }
                    val torDead = hardFails.any { it.id == "tor.socks" } || !tor.isRunning()
                    handleFailure(
                        message = "Leak detected — $summary",
                        fromValidation = true,
                        validations = checks,
                        stopTorProcesses = torDead,
                    )
                    break
                }
            }
        }
    }

    private fun startThroughputUpdates() {
        throughputJob?.cancel()
        throughputTracker.reset()
        var ticks = 0
        throughputJob = scope.launch {
            while (isActive) {
                delay(THROUGHPUT_INTERVAL_MS)
                val phase = _snapshot.value.phase
                if (phase != TunnelPhase.Connected && phase != TunnelPhase.StartingTor) continue
                // Aggregate bandwidth = process-wide traffic/read|written deltas (all circuits).
                // BW events are also global; CIRC_BW/STREAM_BW are never used (per-circuit).
                // Circuit dumps only every ~2 min; lite health every ~10s.
                ticks++
                if (ticks % TRAFFIC_REFRESH_TICKS == 0) {
                    tor.refreshControlTraffic()
                }
                if (ticks % LITE_CONTROL_REFRESH_TICKS == 0 || phase == TunnelPhase.StartingTor) {
                    tor.refreshControlHealthLite()
                }
                val st = tor.controlStatus.value
                if (phase == TunnelPhase.Connected && st.connected) {
                    stabilityRecovery.maybeApply(st)
                }
                if (phase == TunnelPhase.Connected && !tor.isInMaintenance) {
                    if (pendingNetworkRecover) {
                        recoverUnderlyingNetwork(fromPending = true)
                    }
                    if (pendingForwarderCheck &&
                        !OnionVpnService.vpnRebinding.value &&
                        !OnionVpnService.tunForwarderAlive.value
                    ) {
                        pendingForwarderCheck = false
                        Timber.i("Replaying deferred TUN forwarder check after maintenance")
                        // Collector only fires on StateFlow change — nudge false→ already false.
                        // Run the same recovery path inline.
                        lifecycleMutex.withLock {
                            if (_snapshot.value.phase != TunnelPhase.Connected) return@withLock
                            val ports = runtimePorts
                            if (ports != null && tor.isRunning() && isSocksReachable(ports.torSocksPort)) {
                                val gen = OnionVpnService.nextGeneration()
                                vpnBridge.startConnected(preferences, ports, gen)
                                if (vpnBridge.waitForConnected(gen, ports)) {
                                    OnionVpnService.markForwarderAlive()
                                    return@withLock
                                }
                            }
                            handleFailure(
                                message = "TUN forwarder died",
                                fromValidation = true,
                                stopTorProcesses = !tor.isRunning(),
                                alreadyHoldingLifecycleLock = true,
                            )
                        }
                    } else if (OnionVpnService.tunForwarderAlive.value) {
                        pendingForwarderCheck = false
                    }
                }
                val builtLive = circuitLifecycle.liveCircuits.value.count {
                    it.info.status.equals("BUILT", ignoreCase = true)
                }
                val useControlTraffic = preferences.torEngine.capabilities.classicControlPlane &&
                    st.connected
                if (phase == TunnelPhase.Connected && useControlTraffic) {
                    throughputTracker.formatAggregate(
                        st,
                        builtCircuits = if (st.connected) builtLive else st.builtCircuits,
                    )
                } else if (phase == TunnelPhase.Connected) {
                    // Arti / no control traffic: UID TrafficStats is the 1:1 GETINFO traffic stand-in.
                    throughputTracker.sampleUidFallback()
                }
                updateSnapshot(phase)
            }
        }
    }

    private fun stopThroughputUpdates() {
        throughputJob?.cancel()
        throughputJob = null
        throughputTracker.reset()
    }

    /**
     * @param timeoutMs bootstrap budget; null = hold until [releaseTunnelWakeLock]
     *   (Connected / Blocking with Tor — mirrors OnionShare wake lock while network on).
     */
    private fun acquireTunnelWakeLock(timeoutMs: Long?) {
        releaseTunnelWakeLock()
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        tunnelWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OnionVPN:Tunnel").apply {
            setReferenceCounted(false)
            if (timeoutMs != null) {
                acquire(timeoutMs)
            } else {
                @Suppress("DEPRECATION")
                acquire()
            }
        }
    }

    private fun releaseTunnelWakeLock() {
        tunnelWakeLock?.let { lock ->
            if (lock.isHeld) {
                try {
                    lock.release()
                } catch (_: RuntimeException) {
                    // already released
                }
            }
        }
        tunnelWakeLock = null
    }

    private fun updateSnapshot(
        phase: TunnelPhase,
        validations: List<ValidationCheck>? = null,
        torRunning: Boolean? = null,
        dnsCryptRunning: Boolean? = null,
        vpnEstablished: Boolean? = null,
        lastError: String? = _snapshot.value.lastError,
        clearError: Boolean = false,
    ) {
        val caps = preferences.torEngine.capabilities
        val liveCircs = circuitLifecycle.liveCircuits.value
        val liveStreams = circuitLifecycle.liveStreams.value
        val controlUp = caps.classicControlPlane && tor.control.isConnected
        val builtLive = liveCircs.count { it.info.status.equals("BUILT", ignoreCase = true) }
        _snapshot.update { prev ->
            TunnelSnapshotBuilder.build(
                phase = phase,
                preferences = preferences,
                torStatus = tor.controlStatus.value,
                throughputText = throughputText,
                validations = validations ?: prev.validations,
                torRunning = torRunning ?: prev.torRunning,
                dnsCryptRunning = dnsCryptRunning ?: prev.dnsCryptRunning,
                vpnEstablished = vpnEstablished ?: prev.vpnEstablished,
                lastError = if (clearError) null else (lastError ?: prev.lastError),
                runtimePorts = runtimePorts,
                liveBuiltCircuits = if (controlUp) builtLive else -1,
                liveStreamCount = if (controlUp) liveStreams.size else -1,
                torEngine = preferences.torEngine,
                identityRefreshing = identityRefreshing,
            )
        }
        notifications.updateIfChanged(phase, throughputText, lastNotificationText, lastNotificationUpdateMs)
            .also { (text, at) ->
                lastNotificationText = text
                lastNotificationUpdateMs = at
            }
    }

    private fun maybeSignalActive() {
        if (!preferences.torEngine.capabilities.dormantSignals) return
        val st = tor.controlStatus.value
        val controlLive = preferences.torEngine.capabilities.classicControlPlane &&
            tor.control.isConnected
        val artiLive = preferences.torEngine == TorEngine.ARTI &&
            (st.connected || tor.isRunning())
        if (!controlLive && !artiLive) return
        if (st.dormant || st.lastStabilityAction.isNotBlank()) {
            tor.signalActive()
        }
    }

    companion object {
        const val ACTION_START = "ltechnologies.onionphone.onionvpn.tunnel.START"
        const val ACTION_STOP = "ltechnologies.onionphone.onionvpn.tunnel.STOP"
        const val ACTION_NEWNYM = "ltechnologies.onionphone.onionvpn.tunnel.NEWNYM"
        const val ACTION_APPLY_CIRCUIT_TIMING = "ltechnologies.onionphone.onionvpn.tunnel.APPLY_CIRCUIT_TIMING"
        const val ACTION_REVOKED = "ltechnologies.onionphone.onionvpn.tunnel.REVOKED"
        const val ACTION_ALWAYS_ON = "ltechnologies.onionphone.onionvpn.tunnel.ALWAYS_ON"
        const val EXTRA_ROUTE_ALL = "route_all"
        const val EXTRA_KILL_SWITCH = "kill_switch"
        const val EXTRA_DNSCRYPT_SERVER = "dnscrypt_server"
        const val EXTRA_DNS_MODE = "dns_mode"
        const val EXTRA_TOR_ENGINE = "tor_engine"
        const val EXTRA_TOR_BRIDGES = "tor_bridges"
        const val EXTRA_TOR_ENTRY = "tor_entry"
        const val EXTRA_TOR_EXIT = "tor_exit"
        const val EXTRA_TOR_EXCLUDE = "tor_exclude"
        const val EXTRA_TOR_NEW_CIRCUIT = "tor_new_circuit"
        const val EXTRA_TOR_MAX_DIRTINESS = "tor_max_dirtiness"
        const val EXTRA_DNS_NOLOG = "dns_nolog"
        const val EXTRA_DNS_NOFILTER = "dns_nofilter"
        const val EXTRA_DNS_FORCE_TCP = "dns_force_tcp"
        const val EXTRA_DNS_DNSSEC = "dns_dnssec"
        const val EXTRA_NO_LOGS = "no_logs"
        const val EXTRA_VPN_APP_MODE = "vpn_app_mode"
        const val EXTRA_VPN_APP_PACKAGES = "vpn_app_packages"
        const val EXTRA_TUN_DATA_PLANE = "tun_data_plane"

        /** Bootstrap / validation budget before Connected holds the lock open-ended. */
        private const val BOOTSTRAP_WAKELOCK_TIMEOUT_MS = 180_000L
        /**
         * onionmasq (separate TorClient) cold microdesc fetch often exceeds 60–90s.
         * Old gate was ~20s → fail/stuck while circuits were still building.
         */
        private const val ONIONMASQ_BOOTSTRAP_TIMEOUT_MS = 240_000L
        /** Soft fail streak / cooldown before Arti hard restart on link flap. */
        private const val HARD_NETWORK_RECOVER_COOLDOWN_MS = 60_000L
        /** Leak checks — catch Private DNS activation sooner without thrashing Tor. */
        private const val VALIDATION_INTERVAL_MS = 45_000L
        private const val VALIDATION_TIMEOUT_MS = 90_000L
        /** After full validateAll timeout: local wiring + OS leak checks only. */
        private const val HARD_GATE_TIMEOUT_MS = 45_000L
        /** Every N lite validations → one full (includes exit-IP). ~7.5 min at 45s. */
        private const val FULL_VALIDATION_TICKS = 10
        /** UI throughput tick; BW events fill rates without GETINFO each tick. */
        private const val THROUGHPUT_INTERVAL_MS = 2_000L
        /** Min gap between catalog-driven soft/hard Tor recoveries. */
        /** Every 5th throughput tick (~10s) refresh traffic GETINFO. */
        private const val TRAFFIC_REFRESH_TICKS = 5
        /** Every N ticks → lite GETINFO (dormant / liveness). ~10s */
        private const val LITE_CONTROL_REFRESH_TICKS = 5

        private val _snapshot = MutableStateFlow(TunnelSnapshot())
        val snapshot: StateFlow<TunnelSnapshot> = _snapshot.asStateFlow()

        fun preferencesFromIntent(intent: Intent): TunnelPreferences = TunnelPreferences(
            routeAllTrafficThroughTor = intent.getBooleanExtra(EXTRA_ROUTE_ALL, true),
            killSwitchEnabled = true, // constant — ignore intent off
            dnsCryptServerName = intent.getStringExtra(EXTRA_DNSCRYPT_SERVER) ?: "cloudflare",
            dnsResolverMode = intent.getStringExtra(EXTRA_DNS_MODE)
                ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
                ?: DnsResolverMode.DNSCRYPT_MUX,
            torEngine = TorEngine.fromPreference(intent.getStringExtra(EXTRA_TOR_ENGINE)),
            torBridges = intent.getStringExtra(EXTRA_TOR_BRIDGES).orEmpty(),
            torEntryNodes = intent.getStringExtra(EXTRA_TOR_ENTRY).orEmpty(),
            torExitNodes = intent.getStringExtra(EXTRA_TOR_EXIT).orEmpty(),
            torExcludeNodes = intent.getStringExtra(EXTRA_TOR_EXCLUDE).orEmpty(),
            torNewCircuitPeriodSec = intent.getIntExtra(EXTRA_TOR_NEW_CIRCUIT, 30),
            torMaxCircuitDirtinessSec = intent.getIntExtra(EXTRA_TOR_MAX_DIRTINESS, 600),
            dnsCryptRequireNoLog = intent.getBooleanExtra(EXTRA_DNS_NOLOG, true),
            dnsCryptRequireNoFilter = intent.getBooleanExtra(EXTRA_DNS_NOFILTER, false),
            dnsCryptForceTcp = intent.getBooleanExtra(EXTRA_DNS_FORCE_TCP, true),
            dnsCryptRequireDnssec = intent.getBooleanExtra(EXTRA_DNS_DNSSEC, true),
            noLogsEnabled = if (intent.hasExtra(EXTRA_NO_LOGS)) {
                intent.getBooleanExtra(EXTRA_NO_LOGS, true)
            } else {
                !BuildConfig.DEBUG
            },
            vpnAppRoutingMode = intent.getStringExtra(EXTRA_VPN_APP_MODE)
                ?.let { runCatching { VpnAppRoutingMode.valueOf(it) }.getOrNull() }
                ?: VpnAppRoutingMode.ALL,
            vpnAppPackages = intent.getStringExtra(EXTRA_VPN_APP_PACKAGES)
                ?.lineSequence()
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?.toSet()
                ?: emptySet(),
            tunDataPlane = TunDataPlane.fromPreference(intent.getStringExtra(EXTRA_TUN_DATA_PLANE)),
        )
    }

    /**
     * Debug-only: `files/tor/bridges.override.txt` replaces [TunnelPreferences.torBridges]
     * so MCP/adb can inject bridges without unlocking the Settings UI.
     */
    private fun applyDebugBridgeOverride(prefs: TunnelPreferences): TunnelPreferences {
        if (!BuildConfig.DEBUG) return prefs
        val override = File(filesDir, "tor/bridges.override.txt")
        if (!override.isFile || override.length() <= 0L) return prefs
        val text = runCatching { override.readText() }.getOrNull()?.trim().orEmpty()
        if (text.isEmpty()) return prefs
        Timber.i("DEBUG bridges override applied (%d bytes, %d lines)", text.length, text.lines().size)
        return prefs.copy(torBridges = text)
    }

    /**
     * Debug-only: `files/tor/engine.override.txt` with `ARTI` or `LITTLE_T`
     * forces [TunnelPreferences.torEngine] for MCP/adb tests without Settings UI.
     *
     * **One-shot**: the file is deleted after apply so Settings → Apply & restart
     * is not permanently hijacked (a leftover `ARTI` file was forcing Arti forever).
     * Rewrite the file via adb before the next MCP start if you need the override again.
     */
    private fun applyDebugEngineOverride(prefs: TunnelPreferences): TunnelPreferences {
        if (!BuildConfig.DEBUG) return prefs
        val override = File(filesDir, "tor/engine.override.txt")
        if (!override.isFile || override.length() <= 0L) return prefs
        val raw = runCatching { override.readText() }.getOrNull()?.trim().orEmpty()
        if (raw.isEmpty()) {
            runCatching { override.delete() }
            return prefs
        }
        val engine = TorEngine.fromPreference(raw.lineSequence().firstOrNull()?.trim())
        // Consume before start so a UI engine switch on the next Apply wins.
        runCatching { override.delete() }
        Timber.i("DEBUG engine override applied (one-shot) → %s", engine)
        return prefs.copy(torEngine = engine)
    }
}
