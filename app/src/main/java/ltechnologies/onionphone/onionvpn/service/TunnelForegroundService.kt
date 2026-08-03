package ltechnologies.onionphone.onionvpn.service

import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
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
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.TorNativeAppUids
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
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.dns.OnionAutomapAllocator
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.ArtiSocksRoleMux
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDataPlaneFactory
import ltechnologies.onionphone.onionvpn.core.vpn.net.TorBandwidthSampler
import ltechnologies.onionphone.onionvpn.core.vpn.pac.PacProxyServer
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
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
    /** Idempotent teardown for STOP/REVOKED/onDestroy. */
    private val teardownOnce = AtomicBoolean(false)
    /** PARTIAL_WAKE_LOCK while tunnel up (OnionShare/onionwrapper pattern). */
    private var tunnelWakeLock: PowerManager.WakeLock? = null
    private var tunnelJob: Job? = null
    private var validationJob: Job? = null
    private var throughputJob: Job? = null
    private var forwarderWatchJob: Job? = null
    private var newNymJob: Job? = null
    @Volatile private var identityRefreshing: Boolean = false
    /** Soft UI/service debounce for C Tor NEWNYM (Tor defers ~10s, returns 250 OK). */
    @Volatile private var lastLittleTNewNymMs: Long = 0L
    private var preferences = TunnelPreferences()
    private var runtimePorts: TunnelRuntimePorts? = null
    private val bandwidthSampler by lazy { TorBandwidthSampler(applicationInfo.uid) }
    private val throughputTracker by lazy { TunnelThroughputTracker(bandwidthSampler) }
    private val stabilityRecovery by lazy { TunnelStabilityRecovery(tor, scope) }
    private val throughputText: String get() = throughputTracker.displayText
    private val notifications by lazy { TunnelNotifications(this) }
    private var lastNotificationText: String? = null
    private var lastNotificationUpdateMs: Long = 0L
    private var lastNotificationPhase: TunnelPhase? = null
    private val vpnBridge by lazy { TunnelVpnBridge(this) }
    private val artiSocksRoleMux = ArtiSocksRoleMux()
    private var socksDnsBootstrapRelay:
        ltechnologies.onionphone.onionvpn.core.vpn.dns.SocksDnsBootstrapRelay? = null
    /** Bumps SOCKS IsolationToken username after onionmasq NEWNYM (`dnscrypt-nN`). */
    @Volatile private var onionmasqDnsNymEpoch: Int = 0
    /** Match C Tor / Arti ~10.5s NEWNYM rate limit on onionmasq refreshCircuits. */
    @Volatile private var lastOnionmasqNewNymMs: Long = 0L
    private val pacServer by lazy { PacProxyServer() }
    private var torNativePackageReceiver: BroadcastReceiver? = null
    private var torNativePackageRebindJob: Job? = null

    private fun isOnionmasqPlane(): Boolean =
        OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ

    private fun isOnionmasqLive(): Boolean =
        isOnionmasqPlane() &&
            org.torproject.onionmasq.OnionMasq.isInitialized() &&
            org.torproject.onionmasq.OnionMasq.isRunning() &&
            OnionVpnService.onionmasqReady.value

    private fun isDataPlaneTorLive(): Boolean =
        if (isOnionmasqPlane()) isOnionmasqLive() else tor.isRunning()

    /** Start/replace loopback UDP DNS → SOCKS DoH bootstrap (onionmasq / Arti DNSPort gap). */
    private fun ensureSocksDnsBootstrapRelay(
        listenPort: Int,
        socksPort: Int,
        socksUser: String = TunnelEndpoints.SOCKS_DNSCRYPT_USER,
    ) {
        socksDnsBootstrapRelay?.stop()
        val relay = ltechnologies.onionphone.onionvpn.core.vpn.dns.SocksDnsBootstrapRelay(
            listenPort = listenPort,
            socksPort = socksPort,
            socksUser = socksUser,
        )
        relay.start()
        socksDnsBootstrapRelay = relay
    }

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
                // Soft path only (DNSCrypt still running). Hard downtime stops DNSCrypt
                // via onDnsDependentPause and restarts via onDnsDependentResume.
                if (tor.isInMaintenance) {
                    Timber.i("DNSCrypt clearQueryCache skipped — Tor maintenance (resume owns restart)")
                    return@launch
                }
                val onionmasqReady = OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ &&
                    org.torproject.onionmasq.OnionMasq.isInitialized() &&
                    org.torproject.onionmasq.OnionMasq.isRunning() &&
                    ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                        .OnionmasqSocksSidecar.socksPortOrZero() > 0
                if (!onionmasqReady && !tor.isReadyForDnsCryptUpstream()) {
                    Timber.i("DNSCrypt clearQueryCache skipped — Tor upstream not ready")
                    return@launch
                }
                dnsCrypt.clearQueryCache().onFailure {
                    Timber.w(it, "DNSCrypt query cache clear failed")
                }
            }
        }
        tor.onDnsDependentPause = {
            Timber.i("Tor downtime: stop DNSCrypt (upstream Tor SOCKS unavailable)")
            dnsCrypt.stop()
        }
        tor.onDnsDependentResume = resumeDns@{
            val ports = runtimePorts
            if (ports == null) {
                Timber.i("DNSCrypt resume skipped — no ports")
                return@resumeDns
            }
            val sidecar = ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                .OnionmasqSocksSidecar.socksPortOrZero()
            if (OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ) {
                if (sidecar <= 0) {
                    Timber.w("DNSCrypt resume skipped — onionmasq sidecar down")
                    return@resumeDns
                }
                val dnsUser = TunnelEndpoints.dnsCryptSocksUser(onionmasqDnsNymEpoch)
                Timber.i(
                    "Tor downtime end: DNSCrypt via sidecar :%d user=%s (+ DoH relay)",
                    sidecar,
                    dnsUser,
                )
                runCatching {
                    ensureSocksDnsBootstrapRelay(
                        listenPort = ports.torDnsPort,
                        socksPort = sidecar,
                        socksUser = dnsUser,
                    )
                }.onFailure { Timber.e(it, "bootstrap relay resume failed") }
                dnsCrypt.start(
                    preferences.dnsCryptServerName,
                    ports,
                    preferences,
                    socksPortOverride = sidecar,
                    socksUserOverride = dnsUser,
                ).onFailure {
                    Timber.e(it, "DNSCrypt resume after onionmasq downtime failed")
                }
                return@resumeDns
            }
            if (!tor.isRunning() || !tor.isReadyForDnsCryptUpstream()) {
                Timber.w("DNSCrypt resume skipped — Tor upstream not ready yet")
                return@resumeDns
            }
            Timber.i("Tor downtime end: start DNSCrypt on :%d", ports.dnsCryptListenPort)
            dnsCrypt.start(preferences.dnsCryptServerName, ports, preferences).onFailure {
                Timber.e(it, "DNSCrypt resume after Tor downtime failed")
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
                val socks = if (isOnionmasqPlane()) {
                    ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                        .OnionmasqSocksSidecar.socksPortOrZero()
                        .takeIf { it > 0 }
                        ?: ports?.torSocksPort
                        ?: 0
                } else {
                    ports?.torSocksPort ?: 0
                }
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
                is org.torproject.onionmasq.events.DNSConnectivityEvent -> {
                    // Tor sample: enforced Private DNS (hostname) → stop VPN.
                    if (event.hasEnforcedPrivateDNS) {
                        Timber.e(
                            "Private DNS enforced hostname=%s — fail-closed teardown",
                            event.privateDNSHostname,
                        )
                        scope.launch {
                            handleFailure(
                                message = "Private DNS (DoT) enabled — set Private DNS → Off",
                                fromValidation = true,
                                validations = listOf(
                                    ValidationCheck(
                                        id = "android.dns.private",
                                        label = "Android Private DNS (DoT) off",
                                        status = ValidationStatus.Fail,
                                        detail = "DNSConnectivityEvent hostname=${event.privateDNSHostname}",
                                        tripsKillSwitch = true,
                                    ),
                                ),
                                stopTorProcesses = false,
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
        // onionmasq TorClient: mirror ConnectivityHandler — never force true when offline.
        if (isOnionmasqPlane()) {
            pendingNetworkRecover = false
            softNetworkFailStreak = 0
            if (org.torproject.onionmasq.OnionMasq.isInitialized() &&
                org.torproject.onionmasq.OnionMasq.isRunning()
            ) {
                val cm = getSystemService(android.net.ConnectivityManager::class.java)
                val net = cm?.activeNetwork
                val caps = net?.let { cm.getNetworkCapabilities(it) }
                // Match ConnectivityHandler.onCapabilitiesChanged (VALIDATED), not INTERNET-only.
                val online = caps != null &&
                    caps.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                    !caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)
                runCatching {
                    org.torproject.onionmasq.OnionMasqJni.setInternetConnectivity(online)
                }.onFailure { Timber.w(it, "onionmasq setInternetConnectivity after net change") }
                Timber.i(
                    "Underlying network change — onionmasq connectivity=%s (fromPending=%s)",
                    online,
                    fromPending,
                )
            }
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
                        teardownOnce.set(false)
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
                if (OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ) {
                    val wait = lastOnionmasqNewNymMs + ONIONMASQ_NEWNYM_MIN_INTERVAL_MS -
                        System.currentTimeMillis()
                    if (wait > 0) {
                        Timber.w(
                            "onionmasq NEWNYM rate-limited — wait %ds",
                            ((wait + 999) / 1000),
                        )
                        return START_STICKY
                    }
                } else if (preferences.torEngine == TorEngine.LITTLE_T) {
                    // Soft debounce — SocksPort stays up (C Tor defers NEWNYM).
                    val wait = lastLittleTNewNymMs + LITTLE_T_NEWNYM_SOFT_DEBOUNCE_MS -
                        System.currentTimeMillis()
                    if (wait > 0) {
                        Timber.w(
                            "%s NEWNYM soft-debounced — wait %ds",
                            preferences.torEngine.name,
                            ((wait + 999) / 1000),
                        )
                        return START_STICKY
                    }
                }
                // Set before launch — avoid TOCTOU double-start.
                identityRefreshing = true
                newNymJob = scope.launch {
                    updateSnapshot(TunnelPhase.Connected)
                    validationJob?.cancel()
                    validationJob = null
                    val result = try {
                        if (OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ) {
                            // Single TorClient: refreshCircuits rotates app + DNSCrypt IsolationTokens.
                            if (org.torproject.onionmasq.OnionMasq.isInitialized() &&
                                org.torproject.onionmasq.OnionMasq.isRunning()
                            ) {
                                val refreshed = runCatching {
                                    org.torproject.onionmasq.OnionMasq.refreshCircuits()
                                }
                                if (refreshed.isSuccess) {
                                    lastOnionmasqNewNymMs = System.currentTimeMillis()
                                    Timber.i("New identity via onionmasq refreshCircuits()")
                                    DnsHostnameCache.clear()
                                    OnionAutomapAllocator.clear()
                                    // Sidecar IsolationTokens are sticky per username —
                                    // rotate app + DNSCrypt tokens (KeepAliveIsolateSOCKSAuth).
                                    val epoch = TunnelEndpoints.bumpAppSocksNymEpoch()
                                    onionmasqDnsNymEpoch = epoch
                                    val ports = runtimePorts
                                    val sidecar = ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                                        .OnionmasqSocksSidecar.socksPortOrZero()
                                    val dnsUser = TunnelEndpoints.dnsCryptSocksUser(epoch)
                                    if (ports != null && sidecar > 0) {
                                        ensureSocksDnsBootstrapRelay(
                                            listenPort = ports.torDnsPort,
                                            socksPort = sidecar,
                                            socksUser = dnsUser,
                                        )
                                        dnsCrypt.start(
                                            preferences.dnsCryptServerName,
                                            ports,
                                            preferences,
                                            socksPortOverride = sidecar,
                                            socksUserOverride = dnsUser,
                                        ).onFailure {
                                            Timber.w(it, "DNSCrypt NEWNYM token rotate failed")
                                        }
                                    } else {
                                        dnsCrypt.clearQueryCache()
                                    }
                                    Result.success(Unit)
                                } else {
                                    // Count failed attempts toward rate limit to avoid hammering.
                                    lastOnionmasqNewNymMs = System.currentTimeMillis()
                                    val err = refreshed.exceptionOrNull()
                                        ?: IllegalStateException("refreshCircuits failed")
                                    Timber.w(err, "onionmasq refreshCircuits failed")
                                    Result.failure(err)
                                }
                            } else {
                                Timber.w("onionmasq refreshCircuits skipped — not running")
                                Result.failure(IllegalStateException("onionmasq not running"))
                            }
                        } else {
                            val nym = tor.newNym()
                            if (nym.isSuccess) {
                                // C Tor KeepAliveIsolateSOCKSAuth sticks on u{uid} until
                                // username rotates — bump epoch on every successful NEWNYM.
                                TunnelEndpoints.bumpAppSocksNymEpoch()
                                if (preferences.torEngine == TorEngine.LITTLE_T) {
                                    lastLittleTNewNymMs = System.currentTimeMillis()
                                }
                            }
                            nym
                        }
                    } finally {
                        identityRefreshing = false
                    }
                    result.onSuccess {
                        Timber.i(
                            "New identity via %s",
                            when {
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
                    // onionmasq TorClient has no MaxCircuitDirtiness JNI (Tor VPN same gap).
                    // arti-mobile Ext is not running on this plane — do not call dead JNI.
                    if (isOnionmasqPlane()) {
                        Timber.i(
                            "Circuit timing persisted only on onionmasq " +
                                "(dirt=%d period=%d; no live dirtiness API) — use NEWNYM / exit country",
                            dirt,
                            period,
                        )
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
                // Cancel outside the mutex — a wedged start holding the lock must not
                // block revoke forever (kotlinx Mutex is not reentrant).
                tunnelJob?.cancel()
                newNymJob?.cancel()
                identityRefreshing = false
                scope.launch {
                    lifecycleMutex.withLock {
                        tunnelJob = null
                        newNymJob = null
                        validationJob?.cancel()
                        validationJob = null
                        forwarderWatchJob?.cancel()
                        forwarderWatchJob = null
                        stopThroughputUpdates()
                        teardownModules(
                            resetSnapshot = false,
                            phase = TunnelPhase.Error,
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
                scope.launch {
                    lifecycleMutex.withLock {
                        val vpnMode = OnionVpnService.vpnProfileMode.value
                        val forwarderDead = !OnionVpnService.tunForwarderAlive.value
                        val unhealthyWhileStarting =
                            vpnMode == VpnProfileMode.Blocking || forwarderDead
                        if (tunnelJob?.isActive == true) {
                            if (!unhealthyWhileStarting) {
                                Timber.w("Ignoring ALWAYS_ON — tunnel already starting")
                                return@withLock
                            }
                            Timber.w(
                                "ALWAYS_ON — canceling active job (vpnMode=%s forwarderAlive=%s)",
                                vpnMode,
                                !forwarderDead,
                            )
                            tunnelJob?.cancel()
                            tunnelJob = null
                            newNymJob?.cancel()
                            newNymJob = null
                            identityRefreshing = false
                        }
                        val phase = _snapshot.value.phase
                        // Sticky VPN restart leaves Blocking TUN while FGS may still say Connected.
                        val needsReconcile =
                            (phase == TunnelPhase.Connected || phase == TunnelPhase.Validating) &&
                                (vpnMode == VpnProfileMode.Blocking || forwarderDead)
                        if (needsReconcile || unhealthyWhileStarting) {
                            Timber.w(
                                "ALWAYS_ON reconcile — phase=%s vpnMode=%s forwarderAlive=%s",
                                phase,
                                vpnMode,
                                !forwarderDead,
                            )
                            validationJob?.cancel()
                            validationJob = null
                            stopThroughputUpdates()
                            forwarderWatchJob?.cancel()
                            forwarderWatchJob = null
                            socksDnsBootstrapRelay?.stop()
                            socksDnsBootstrapRelay = null
                            tor.clearExternalRuntimePorts()
                            runtimePorts = null
                            dnsCrypt.stop()
                            artiSocksRoleMux.stop()
                            tor.stop()
                            updateSnapshot(
                                TunnelPhase.Blocking,
                                lastError = "Always-on VPN rebound — restoring Tor path",
                            )
                        } else if (phase == TunnelPhase.Connected || phase == TunnelPhase.Validating ||
                            phase == TunnelPhase.StartingTor || phase == TunnelPhase.StartingDnsCrypt ||
                            phase == TunnelPhase.StartingVpn
                        ) {
                            Timber.w("Ignoring ALWAYS_ON — already up phase=%s", phase)
                            return@withLock
                        }
                        tunnelJob = scope.launch {
                            teardownOnce.set(false)
                            preferences = preferencesStore.preferences.first()
                            runStartSequence()
                        }
                    }
                }
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        OnionVpnService.onUnderlyingNetworkChanged = null
        // Teardown before cancelling scope — otherwise TUN/Tor/DNSCrypt leak on process
        // death paths that skip STOP/REVOKED.
        if (teardownOnce.compareAndSet(false, true)) {
            runCatching {
                runBlocking(Dispatchers.IO) {
                    val phase = _snapshot.value.phase
                    if (phase != TunnelPhase.Idle && phase != TunnelPhase.Stopping) {
                        Timber.w("onDestroy teardown — phase was %s", phase)
                        teardownModules(
                            resetSnapshot = false,
                            phase = TunnelPhase.Idle,
                            lastError = null,
                        )
                    }
                }
            }.onFailure { Timber.w(it, "onDestroy teardown failed") }
        }
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
                // Holding lifecycleMutex — must not re-enter handleFailure's withLock.
                failDuringStart(
                    message = failure.userMessage,
                    fromValidation = false,
                    stopTorProcesses = failure.stopTor,
                )
            }
        }
    }

    /**
     * Start-path failure helper: [runStartSequence] already holds [lifecycleMutex]
     * (non-reentrant). Using plain [handleFailure] here deadlocks the coordinator.
     */
    private suspend fun failDuringStart(
        message: String,
        fromValidation: Boolean = false,
        validations: List<ValidationCheck> = emptyList(),
        stopTorProcesses: Boolean = true,
    ) {
        handleFailure(
            message = message,
            fromValidation = fromValidation,
            validations = validations,
            stopTorProcesses = stopTorProcesses,
            alreadyHoldingLifecycleLock = true,
        )
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
                    failDuringStart("Kill-switch Blocking TUN failed to establish", fromValidation = false)
                    return@stepSuspending
                }
                OpTrace.info("tunnel", "Kill-switch Blocking TUN up before Tor bootstrap")
            }
            // handleFailure → Blocking (not Error) when VPN permission present.
            val afterBlock = _snapshot.value.phase
            if (afterBlock == TunnelPhase.Error || afterBlock == TunnelPhase.Blocking) {
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
                // Defer upstream until plane-specific SOCKS is live (onionmasq: sidecar).
                pacServer.updateUpstream(0, 0)
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

        // ONIONMASQ: single TorClient inside onionmasq — skip arti-mobile entirely.
        // HEV / C Tor: classic tor.start → DNSCrypt → Connected.
        var activePorts = ports
        if (effectivePlane != TunDataPlane.ONIONMASQ) {
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
                failDuringStart(failure.userMessage, fromValidation = false, stopTorProcesses = failure.stopTor)
                return
            }
            domainReputation.onTorReady()
            if (preferences.torEngine == TorEngine.ARTI) {
                OpTrace.step("tunnel", "arti_socks_role_mux") {
                    artiSocksRoleMux.start(ports)
                }
                // C Tor keeps Tor DNSPort bootstrap. Arti: only use DoH relay if DNSPort dead.
                val dnsReady = ltechnologies.onionphone.onionvpn.core.tor.lifecycle.TorReadiness
                    .isDnsPortReady(ports.torDnsPort, timeoutMs = 2_000)
                if (!dnsReady) {
                    Timber.w(
                        "Arti DNSPort :%d not ready — SocksDnsBootstrapRelay DoH fallback",
                        ports.torDnsPort,
                    )
                    OpTrace.step("tunnel", "socks_dns_bootstrap_relay_arti") {
                        ensureSocksDnsBootstrapRelay(
                            listenPort = ports.torDnsPort,
                            socksPort = ports.torDnsCryptSocksPort,
                        )
                    }
                }
            }
            updateSnapshot(TunnelPhase.StartingDnsCrypt, torRunning = true)
            val dnsResult = OpTrace.stepSuspending("tunnel", "dnscrypt_start", ProcessLogLevel.INFO) {
                dnsCrypt.start(preferences.dnsCryptServerName, ports, preferences)
            }
            if (dnsResult.isFailure) {
                val err = dnsResult.exceptionOrNull() ?: Exception("DNSCrypt failed")
                val failure = TunnelFailure.fromThrowable(err, context = "dnscrypt.start")
                failDuringStart(
                    message = failure.userMessage,
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return
            }
            pacServer.updateUpstream(ports.torSocksPort, ports.dnsCryptListenPort)
            updateSnapshot(TunnelPhase.StartingVpn, dnsCryptRunning = true)
        } else {
            bootstrapUiJob.cancel()
            updateSnapshot(TunnelPhase.StartingVpn, torRunning = false)
            Timber.i("ONIONMASQ plane — skipping arti-mobile; DNSCrypt after sidecar ready")
        }

        if (VpnService.prepare(this) != null) {
            failDuringStart(
                TunnelFailure.VpnEstablish("VPN permission not granted — approve OnionVPN in system VPN dialog").userMessage,
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }

        // Seed firewall prefs before Connected TUN packets (ASK/DENY must not flip mid-flow).
        firewallEngine.start()

        val vpnGeneration = OnionVpnService.nextGeneration()
        OpTrace.stepSuspending("tunnel", "connected_tun", ProcessLogLevel.INFO) {
            vpnBridge.startConnected(preferences, activePorts, vpnGeneration)
            val vpnReady = vpnBridge.waitForConnected(vpnGeneration, activePorts)
            if (!vpnReady) {
                failDuringStart(
                    TunnelFailure.VpnEstablish(
                        "VPN interface not established (timeout or establish() null)",
                    ).userMessage,
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return@stepSuspending
            }
        }
        // Blocking is also a terminal path for start (kill-switch engaged).
        val afterTun = _snapshot.value.phase
        if (afterTun == TunnelPhase.Error || afterTun == TunnelPhase.Blocking) return

        if (effectivePlane == TunDataPlane.ONIONMASQ) {
            // UI stays StartingVpn until onionmasq ready — TUN is up but fail-closed until then.
            val ready = OnionVpnService.onionmasqReady.value ||
                withTimeoutOrNull(ONIONMASQ_BOOTSTRAP_TIMEOUT_MS) {
                    OnionVpnService.onionmasqReady.first { it }
                } == true
            if (!ready) {
                failDuringStart(
                    message = "onionmasq not ready for traffic (bootstrap timeout) — fail-closed",
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return
            }
            val sidecar = ltechnologies.onionphone.onionvpn.core.vpn.onionmasq
                .OnionmasqSocksSidecar.awaitPort(30_000L)
            Timber.i(
                "onionmasq bootstrapReady=%s socksSidecar=%d singleTorClient=true",
                ready,
                sidecar,
            )
            if (sidecar <= 0) {
                failDuringStart(
                    message = "onionmasq SOCKS sidecar not listening — fail-closed",
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return
            }
            // DNSCrypt bootstrap_resolvers → local UDP relay → sidecar SOCKS → DoH :443
            OpTrace.step("tunnel", "socks_dns_bootstrap_relay") {
                ensureSocksDnsBootstrapRelay(
                    listenPort = ports.torDnsPort,
                    socksPort = sidecar,
                )
            }
            // Point DNSCrypt + probes at sidecar (same TorClient as TUN).
            activePorts = ports.copy(
                torDnsCryptSocksPort = sidecar,
                torProbeSocksPort = sidecar,
                torSocksPort = sidecar,
            )
            runtimePorts = activePorts
            tor.attachExternalRuntimePorts(activePorts)
            updateSnapshot(TunnelPhase.StartingDnsCrypt, torRunning = true)
            val dnsResult = OpTrace.stepSuspending("tunnel", "dnscrypt_start_sidecar", ProcessLogLevel.INFO) {
                dnsCrypt.start(
                    preferences.dnsCryptServerName,
                    activePorts,
                    preferences,
                    socksPortOverride = sidecar,
                )
            }
            if (dnsResult.isFailure) {
                val err = dnsResult.exceptionOrNull() ?: Exception("DNSCrypt failed")
                val failure = TunnelFailure.fromThrowable(err, context = "dnscrypt.start")
                failDuringStart(
                    message = failure.userMessage,
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return
            }
            pacServer.updateUpstream(sidecar, activePorts.dnsCryptListenPort)
            domainReputation.onTorReady()
            updateSnapshot(TunnelPhase.StartingVpn, dnsCryptRunning = true, torRunning = true)
        }

        val useDnsCrypt = true
        val hevSocks = OnionVpnService.hevSocksPort.value
        val hevDns = OnionVpnService.hevDnsCryptPort.value
        val dnsPortExpected = if (useDnsCrypt) activePorts.dnsCryptListenPort else hevDns
        // ONIONMASQ publishes allocated socks from the Connected intent (pre-sidecar);
        // match on DNSCrypt listen only for that plane.
        val portsOk = if (effectivePlane == TunDataPlane.ONIONMASQ) {
            OnionVpnService.tunForwarderAlive.value && hevDns == activePorts.dnsCryptListenPort
        } else {
            vpnBridge.hevPortsMatch(activePorts, useDnsCrypt)
        }
        if (!portsOk) {
            failDuringStart(
                message = "TUN forwarder port desync (plane=$effectivePlane socks=$hevSocks dns=$hevDns; " +
                    "expected socks=${activePorts.torSocksPort} dns=$dnsPortExpected)",
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }

        updateSnapshot(TunnelPhase.Validating, vpnEstablished = true)
        // Wake Tor if dormant so DNSPort / SOCKS5A probes don't Poll/connect timeout.
        maybeSignalActive()
        val validations = runValidation(activePorts)
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
            val torDead = hardFails.any {
                it.id == "tor.socks" || it.id == "onionmasq.plane.wiring"
            } || when (effectivePlane) {
                TunDataPlane.ONIONMASQ -> !OnionVpnService.onionmasqReady.value
                else -> !tor.isRunning()
            }
            failDuringStart(
                message = "Validation failed — $summary",
                fromValidation = true,
                validations = validations,
                stopTorProcesses = torDead && effectivePlane != TunDataPlane.ONIONMASQ,
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
        // HEV / classic / arti-mobile Ext only — onionmasq has no live dirtiness JNI.
        if (!isOnionmasqPlane() &&
            (
                preferences.torEngine.capabilities.liveCircuitTiming ||
                    preferences.torEngine.capabilities.liveSetConf
                )
        ) {
            tor.applyCircuitTimingLive(
                preferences.torMaxCircuitDirtinessSec,
                preferences.torNewCircuitPeriodSec,
            )
        }
        // Classic ControlPort circuit poll — not used on onionmasq (event repository).
        if (preferences.torEngine.capabilities.circuitInspection && !isOnionmasqPlane()) {
            circuitLifecycle.start()
        } else {
            circuitLifecycle.stop()
        }
        startPeriodicValidation()
        startForwarderWatchdog()
        registerTorNativePackageReceiver()
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
                val base = TunnelValidator.validateAll(
                    context = applicationContext,
                    torConfigFile = tor.runtimeConfigFile,
                    dnsCryptConfigFile = dnsCrypt.configFile,
                    vpnEstablished = OnionVpnService.vpnEstablished.value,
                    killSwitchEnabled = preferences.killSwitchEnabled,
                    runtimePorts = ports,
                    dnsResolverMode = preferences.dnsResolverMode,
                    torEngine = preferences.torEngine,
                )
                // arti-mobile control health is N/A on single-TorClient onionmasq.
                if (isOnionmasqPlane()) {
                    base
                } else {
                    base + TorControlHealth.validate(
                        status = tor.controlStatus.value,
                        engine = preferences.torEngine,
                    )
                }
            }
        }
    } catch (error: CancellationException) {
        throw error
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
            if (gateError is CancellationException) throw gateError
            Timber.e(gateError, "Hard-gate after timeout failed — fail-closed (never SOCKS-only promote)")
            listOf(
                ValidationCheck(
                    id = "validation.hard_gate",
                    label = "Hard kill-switch gate",
                    status = ValidationStatus.Fail,
                    detail = gateError.message ?: "Hard-gate failed after validation timeout",
                    tripsKillSwitch = true,
                ),
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
        validationJob?.cancel()
        validationJob = null
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
        socksDnsBootstrapRelay?.stop()
        socksDnsBootstrapRelay = null
        // Drop stale onionmasq sidecar publish so probes don't hit ghost ports.
        tor.clearExternalRuntimePorts()
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
        teardownOnce.set(true)
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
        unregisterTorNativePackageReceiver()
        circuitLifecycle.stop()
        firewallEngine.stop()
        runCatching { pacServer.stop() }
        vpnBridge.destroy()
        vpnBridge.waitUntilDown()
        dnsCrypt.stop()
        socksDnsBootstrapRelay?.stop()
        socksDnsBootstrapRelay = null
        onionmasqDnsNymEpoch = 0
        TunnelEndpoints.resetAppSocksNymEpoch()
        artiSocksRoleMux.stop()
        tor.clearExternalRuntimePorts()
        tor.stop()
        releaseTunnelWakeLock()
        MemoryHygiene.afterHeavyWork("tunnel_teardown")
        if (resetSnapshot) {
            runtimePorts = null
            throughputTracker.reset()
            _snapshot.value = TunnelSnapshot()
        }
        // Allow a later START after clean STOP / destroy.
        if (phase == TunnelPhase.Idle || phase == TunnelPhase.Stopping || resetSnapshot) {
            teardownOnce.set(false)
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
                        val socksUp = ports != null && isSocksReachable(ports.torSocksPort)
                        val canRebind = ports != null && socksUp &&
                            (isOnionmasqLive() || tor.isRunning())
                        if (canRebind) {
                            Timber.w("TUN forwarder died — data plane still up; rebinding forwarder")
                            val gen = OnionVpnService.nextGeneration()
                            vpnBridge.startConnected(preferences, ports!!, gen)
                            if (vpnBridge.waitForConnected(gen, ports)) {
                                OnionVpnService.markForwarderAlive()
                                Timber.i("TUN forwarder rebound after forwarder death")
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

    /**
     * hev / all planes: [addDisallowedApplication] is apply-once at establish.
     * When a Tor-native package is installed/updated/removed, rebind Connected so
     * BYPASS (and INCLUDE allow-list) stay honest. onionmasq also refreshes
     * [setExcludedUids] in its own receiver.
     */
    private fun registerTorNativePackageReceiver() {
        unregisterTorNativePackageReceiver()
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                val action = intent?.action ?: return
                if (action != Intent.ACTION_PACKAGE_ADDED &&
                    action != Intent.ACTION_PACKAGE_REMOVED &&
                    action != Intent.ACTION_PACKAGE_REPLACED
                ) {
                    return
                }
                val pkg = intent.data?.schemeSpecificPart
                if (!TorNativeAppUids.isBypassPackage(pkg.orEmpty()) &&
                    !TorNativeAppUids.isBypassPackageFromUri(intent.dataString)
                ) {
                    return
                }
                Timber.i("Tor-native package change action=%s pkg=%s — schedule VPN rebind", action, pkg)
                scheduleTorNativePackageRebind()
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                registerReceiver(receiver, filter)
            }
            torNativePackageReceiver = receiver
            Timber.i("Tor-native package rebind receiver registered")
        }.onFailure { Timber.w(it, "Tor-native package receiver register failed") }
    }

    private fun unregisterTorNativePackageReceiver() {
        torNativePackageRebindJob?.cancel()
        torNativePackageRebindJob = null
        val receiver = torNativePackageReceiver ?: return
        torNativePackageReceiver = null
        runCatching { unregisterReceiver(receiver) }
            .onFailure { Timber.w(it, "Tor-native package receiver unregister failed") }
    }

    private fun scheduleTorNativePackageRebind() {
        torNativePackageRebindJob?.cancel()
        torNativePackageRebindJob = scope.launch {
            delay(TOR_NATIVE_PACKAGE_REBIND_DEBOUNCE_MS)
            if (_snapshot.value.phase != TunnelPhase.Connected) return@launch
            if (tor.isInMaintenance || OnionVpnService.vpnRebinding.value) {
                Timber.i("Tor-native package rebind deferred — maintenance/rebind")
                return@launch
            }
            lifecycleMutex.withLock {
                if (_snapshot.value.phase != TunnelPhase.Connected) return@withLock
                if (tor.isInMaintenance || OnionVpnService.vpnRebinding.value) return@withLock
                val ports = runtimePorts ?: return@withLock
                val socksUp = isSocksReachable(ports.torSocksPort) || isOnionmasqLive()
                if (!socksUp && !isOnionmasqLive() && !tor.isRunning()) return@withLock
                Timber.i("Rebinding Connected VPN after Tor-native package change")
                val gen = OnionVpnService.nextGeneration()
                vpnBridge.startConnected(preferences, ports, gen)
                if (vpnBridge.waitForConnected(gen, ports)) {
                    OnionVpnService.markForwarderAlive()
                    Timber.i("Connected VPN rebound for Tor-native BYPASS update")
                } else {
                    Timber.w("Tor-native package rebind failed — keeping previous plane")
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
                    val torDead = hardFails.any {
                        it.id == "tor.socks" || it.id == "onionmasq.plane.wiring"
                    } || !isDataPlaneTorLive()
                    handleFailure(
                        message = "Leak detected — $summary",
                        fromValidation = true,
                        validations = checks,
                        // onionmasq: keep DNSCrypt/relay when TUN plane still live.
                        stopTorProcesses = torDead && !isOnionmasqPlane(),
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
                    if (preferences.torEngine.capabilities.classicControlPlane &&
                        tor.control.isConnected
                    ) {
                        tor.refreshControlTraffic()
                    }
                }
                if (ticks % LITE_CONTROL_REFRESH_TICKS == 0 || phase == TunnelPhase.StartingTor) {
                    if (preferences.torEngine.capabilities.classicControlPlane &&
                        tor.control.isConnected
                    ) {
                        tor.refreshControlHealthLite()
                    }
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
                            val canRebind = ports != null &&
                                isSocksReachable(ports.torSocksPort) &&
                                (isOnionmasqLive() || tor.isRunning())
                            if (canRebind) {
                                val gen = OnionVpnService.nextGeneration()
                                vpnBridge.startConnected(preferences, ports!!, gen)
                                if (vpnBridge.waitForConnected(gen, ports)) {
                                    OnionVpnService.markForwarderAlive()
                                    return@withLock
                                }
                            }
                            handleFailure(
                                message = "TUN forwarder died",
                                fromValidation = true,
                                stopTorProcesses = !isDataPlaneTorLive() && !isOnionmasqPlane(),
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
                onionmasqReady = isOnionmasqLive(),
                newNymCooldownUntilMs = newNymCooldownUntilMs(),
            )
        }
        notifications.updateIfChanged(
            phase,
            throughputText,
            lastNotificationText,
            lastNotificationUpdateMs,
            lastNotificationPhase,
        ).also { (text, at, p) ->
            lastNotificationText = text
            lastNotificationUpdateMs = at
            lastNotificationPhase = p
        }
    }

    private fun maybeSignalActive() {
        if (!preferences.torEngine.capabilities.dormantSignals) return
        val st = tor.controlStatus.value
        val controlLive = preferences.torEngine == TorEngine.LITTLE_T &&
            tor.control.isConnected
        val artiLive = preferences.torEngine == TorEngine.ARTI &&
            (st.connected || tor.isRunning())
        if (!controlLive && !artiLive) return
        // Orbot: SIGNAL ACTIVE whenever control is up before probes — not only when dormant.
        tor.signalActive()
    }

    /** Earliest time New Identity may fire again (UI canNewNym + service debounce). */
    private fun newNymCooldownUntilMs(): Long {
        val onion = if (lastOnionmasqNewNymMs > 0) {
            lastOnionmasqNewNymMs + ONIONMASQ_NEWNYM_MIN_INTERVAL_MS
        } else {
            0L
        }
        val little = if (lastLittleTNewNymMs > 0) {
            lastLittleTNewNymMs + LITTLE_T_NEWNYM_SOFT_DEBOUNCE_MS
        } else {
            0L
        }
        return maxOf(onion, little)
    }

    companion object {
        /** Match C Tor MAX_SIGNEWNYM_RATE (~10s) / Arti restart gate. */
        private const val ONIONMASQ_NEWNYM_MIN_INTERVAL_MS = 10_500L
        /** Soft debounce for little-t — Tor accepts NEWNYM with 250 OK and defers. */
        private const val LITTLE_T_NEWNYM_SOFT_DEBOUNCE_MS = 10_000L

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

        /**
         * onionmasq (separate TorClient) cold microdesc fetch often exceeds 60–90s.
         * Old gate was ~20s → fail/stuck while circuits were still building.
         */
        private const val ONIONMASQ_BOOTSTRAP_TIMEOUT_MS = 240_000L
        /** Soft fail streak / cooldown before Arti hard restart on link flap. */
        private const val HARD_NETWORK_RECOVER_COOLDOWN_MS = 60_000L
        /** Leak checks — catch Private DNS activation sooner without thrashing Tor. */
        private const val VALIDATION_INTERVAL_MS = 45_000L
        private const val TOR_NATIVE_PACKAGE_REBIND_DEBOUNCE_MS = 1_500L
        private const val VALIDATION_TIMEOUT_MS = 90_000L
        /**
         * Bootstrap / validation budget before Connected holds the lock open-ended.
         * Must cover onionmasq bootstrap (240s) + validation + slack.
         */
        private const val BOOTSTRAP_WAKELOCK_TIMEOUT_MS =
            ONIONMASQ_BOOTSTRAP_TIMEOUT_MS + VALIDATION_TIMEOUT_MS + 30_000L
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
