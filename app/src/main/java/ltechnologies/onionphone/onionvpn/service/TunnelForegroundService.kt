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
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelPortAllocator
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlHealth
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.validation.TunnelValidator
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.net.TorBandwidthSampler
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.threat.DomainReputationRepository
import timber.log.Timber
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

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lifecycleMutex = Mutex()
    private var bootstrapWakeLock: PowerManager.WakeLock? = null
    private var tunnelJob: Job? = null
    private var validationJob: Job? = null
    private var throughputJob: Job? = null
    private var forwarderWatchJob: Job? = null
    private var preferences = TunnelPreferences()
    private var runtimePorts: TunnelRuntimePorts? = null
    private var throughputText = ""
    private val bandwidthSampler by lazy { TorBandwidthSampler(applicationInfo.uid) }
    private val notifications by lazy { TunnelNotifications(this) }
    private val vpnBridge by lazy { TunnelVpnBridge(this) }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        notifications.createChannel()
        OnionVpnService.onUnderlyingNetworkChanged = {
            // Never block the main looper with ControlPort I/O.
            scope.launch(Dispatchers.IO) {
                tor.onNetworkChanged().onFailure {
                    Timber.w(it, "Tor network recovery failed")
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (tunnelJob?.isActive == true) {
                    Timber.w("Ignoring duplicate START — tunnel already starting")
                    return START_STICKY
                }
        preferences = preferencesFromIntent(intent)
                notifications.startForeground(TunnelPhase.StartingTor, throughputText)
                tunnelJob = scope.launch { runStartSequence() }
                return START_STICKY
            }
            ACTION_STOP -> {
                scope.launch { runStopSequence(userInitiated = true) }
                return START_NOT_STICKY
            }
            ACTION_NEWNYM -> {
                scope.launch {
                    val result = tor.newNym()
                    result.onSuccess {
                        Timber.i("NEWNYM via control port")
                        updateSnapshot(_snapshot.value.phase)
                    }
                    result.onFailure { err ->
                        Timber.e(err, "NEWNYM failed")
                        updateSnapshot(
                            _snapshot.value.phase,
                            lastError = TunnelFailure.userMessageOf(err, "newnym"),
                        )
                    }
                }
                return START_STICKY
            }
            ACTION_REVOKED -> {
                Timber.w("VPN revoked by system — fail-closed teardown")
                scope.launch {
                    lifecycleMutex.withLock {
                        tunnelJob?.cancel()
                        tunnelJob = null
                        validationJob?.cancel()
                        validationJob = null
                        stopThroughputUpdates()
                        dnsCrypt.stop()
                        tor.stop()
                        releaseBootstrapWakeLock()
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
                if (tunnelJob?.isActive == true) {
                    return START_STICKY
                }
                // Blocking TUN already up from OnionVpnService; bring Tor path online.
                notifications.startForeground(TunnelPhase.StartingTor, throughputText)
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
        releaseBootstrapWakeLock()
        super.onDestroy()
    }

    private suspend fun runStartSequence() {
        lifecycleMutex.withLock {
            try {
                startTunnel()
            } catch (error: CancellationException) {
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
        acquireBootstrapWakeLock()

        // Mullvad/Orbot: if kill-switch is on, own the default route BEFORE Tor bootstrap
        // so no app can clearnet while we wait for circuits.
        if (preferences.killSwitchEnabled && VpnService.prepare(this) == null) {
            updateSnapshot(TunnelPhase.StartingVpn)
            val blockingGen = OnionVpnService.nextGeneration()
            vpnBridge.startBlocking(preferences, blockingGen)
            if (!vpnBridge.waitForBlocking(blockingGen)) {
                handleFailure("Kill-switch Blocking TUN failed to establish", fromValidation = false)
                return
            }
            Timber.i("Kill-switch Blocking TUN up before Tor bootstrap")
        }

        updateSnapshot(TunnelPhase.StartingTor)

        val ports = TunnelPortAllocator.allocate()
        runtimePorts = ports
        Timber.i(
            "Allocated tunnel ports socks=${ports.torSocksPort} " +
                "dnscryptSocks=${ports.torDnsCryptSocksPort} " +
                "probeSocks=${ports.torProbeSocksPort} dns=${ports.torDnsPort} " +
                "dnscrypt=${ports.dnsCryptListenPort} dnsMode=${preferences.dnsResolverMode}",
        )

        val bootstrapUiJob = scope.launch {
            while (isActive) {
                delay(500)
                updateSnapshot(TunnelPhase.StartingTor, torRunning = tor.isRunning())
            }
        }
        val torResult = try {
            tor.start(ports, preferences)
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

        updateSnapshot(TunnelPhase.StartingDnsCrypt, torRunning = true)
        val useDnsCrypt = preferences.dnsResolverMode == DnsResolverMode.DNSCRYPT_MUX
        if (useDnsCrypt) {
            val dnsResult = dnsCrypt.start(preferences.dnsCryptServerName, ports, preferences)
            if (dnsResult.isFailure) {
                val err = dnsResult.exceptionOrNull() ?: Exception("DNSCrypt failed")
                val failure = TunnelFailure.fromThrowable(err, context = "dnscrypt.start")
                // DNSCrypt down ≠ Tor down. Keep Tor; blackhole apps until user retries / FakeDNS.
                handleFailure(
                    message = failure.userMessage,
                    fromValidation = false,
                    stopTorProcesses = false,
                )
                return
            }
            updateSnapshot(TunnelPhase.StartingVpn, dnsCryptRunning = true)
        } else {
            // FakeDNS: apps never need DNSCrypt — skip so a resolver flake cannot block Tor streams.
            runCatching { dnsCrypt.stop() }
            Timber.i("FakeDNS mode — DNSCrypt not required for app DNS")
            updateSnapshot(TunnelPhase.StartingVpn, dnsCryptRunning = false)
        }

        if (VpnService.prepare(this) != null) {
            handleFailure(
                TunnelFailure.VpnEstablish("VPN permission not granted — approve OnionVPN in system VPN dialog").userMessage,
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }

        // Seamless rebind: do NOT tear down Blocking/previous TUN first (clearnet window).
        val vpnGeneration = OnionVpnService.nextGeneration()
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
            return
        }

        val hevSocks = OnionVpnService.hevSocksPort.value
        val hevDns = OnionVpnService.hevDnsCryptPort.value
        val dnsPortExpected = if (useDnsCrypt) ports.dnsCryptListenPort else hevDns
        if (!vpnBridge.hevPortsMatch(ports, useDnsCrypt)) {
            handleFailure(
                message = "hev-socks5 port desync (hev socks=$hevSocks dns=$hevDns; " +
                    "expected socks=${ports.torSocksPort} dns=$dnsPortExpected)",
                fromValidation = false,
                stopTorProcesses = false,
            )
            return
        }

        updateSnapshot(TunnelPhase.Validating, vpnEstablished = true)
        val validations = runValidation(ports)
        val hardFails = validations.filter { TunnelValidator.isHardKillSwitchFailure(it) }
        val softFails = validations.filter {
            it.status == ValidationStatus.Fail && !TunnelValidator.isHardKillSwitchFailure(it)
        }

        releaseBootstrapWakeLock()

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

        updateSnapshot(
            phase = TunnelPhase.Connected,
            validations = validations,
            torRunning = true,
            dnsCryptRunning = useDnsCrypt && dnsCrypt.isRunning(),
            vpnEstablished = true,
        )
        startPeriodicValidation()
        startForwarderWatchdog()
        startThroughputUpdates()
    }

    private suspend fun runValidation(ports: TunnelRuntimePorts) = try {
        withTimeout(VALIDATION_TIMEOUT_MS) {
            tor.refreshControlInfo()
            TunnelValidator.validateAll(
                context = applicationContext,
                torConfigFile = tor.torrcFile,
                dnsCryptConfigFile = dnsCrypt.configFile,
                vpnEstablished = OnionVpnService.vpnEstablished.value,
                killSwitchEnabled = preferences.killSwitchEnabled,
                runtimePorts = ports,
                dnsResolverMode = preferences.dnsResolverMode,
            ) + TorControlHealth.validate(tor.controlStatus.value)
        }
    } catch (error: Exception) {
        Timber.e(error, "Validation timed out or failed")
        listOf(
            ValidationCheck(
                id = "validation.timeout",
                label = "Tunnel validation",
                status = ValidationStatus.Fail,
                detail = error.message ?: "Validation failed",
            ),
        )
    }

    private suspend fun handleFailure(
        message: String,
        fromValidation: Boolean,
        validations: List<ValidationCheck> = emptyList(),
        /** Only stop Tor when SOCKS/process is dead — never nuke a live Tor path for soft faults. */
        stopTorProcesses: Boolean = true,
    ) {
        Timber.e("Tunnel failure: $message (stopTor=$stopTorProcesses)")
        releaseBootstrapWakeLock()
        stopThroughputUpdates()

        val canBlock = preferences.killSwitchEnabled && VpnService.prepare(this) == null
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
        } else {
            tor.signalDormant()
            Timber.i("Kill-switch Blocking TUN only — Tor dormant, kept for recovery")
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
        updateSnapshot(phase, lastError = lastError, validations = validations)
        validationJob?.cancel()
        validationJob = null
        vpnBridge.destroy()
        vpnBridge.waitUntilDown()
        dnsCrypt.stop()
        tor.stop()
        releaseBootstrapWakeLock()
        if (resetSnapshot) {
            runtimePorts = null
            throughputText = ""
            _snapshot.value = TunnelSnapshot()
        }
    }

    private fun startForwarderWatchdog() {
        forwarderWatchJob?.cancel()
        forwarderWatchJob = scope.launch {
            OnionVpnService.tunForwarderAlive.collect { alive ->
                if (!alive && _snapshot.value.phase == TunnelPhase.Connected) {
                    lifecycleMutex.withLock {
                        if (_snapshot.value.phase != TunnelPhase.Connected) return@withLock
                        val ports = runtimePorts
                        if (ports != null && tor.isRunning() && isSocksReachable(ports.torSocksPort)) {
                            Timber.w("TUN forwarder died — Tor SOCKS still up; rebinding hev (keep Tor)")
                            val gen = OnionVpnService.nextGeneration()
                            vpnBridge.startConnected(preferences, ports, gen)
                            if (vpnBridge.waitForConnected(gen, ports)) {
                                OnionVpnService.markForwarderAlive()
                                Timber.i("hev rebound after forwarder death")
                                return@withLock
                            }
                        }
                        Timber.e("TUN forwarder dead and Tor path unusable — kill-switch Blocking TUN")
                        handleFailure(
                            message = "TUN forwarder died",
                            fromValidation = true,
                            stopTorProcesses = !tor.isRunning(),
                        )
                    }
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
                val ports = runtimePorts ?: continue
                ticks++
                // Most ticks: local lite probes. Exit-IP OkHttp only every ~15 min.
                val checks = if (ticks % FULL_VALIDATION_TICKS == 0) {
                    TunnelValidator.validateAll(
                        context = applicationContext,
                        torConfigFile = tor.torrcFile,
                        dnsCryptConfigFile = dnsCrypt.configFile,
                        vpnEstablished = OnionVpnService.vpnEstablished.value,
                        killSwitchEnabled = preferences.killSwitchEnabled,
                        runtimePorts = ports,
                        dnsResolverMode = preferences.dnsResolverMode,
                        includeExitIp = true,
                    )
                } else {
                    TunnelValidator.validateLite(
                        context = applicationContext,
                        torConfigFile = tor.torrcFile,
                        dnsCryptConfigFile = dnsCrypt.configFile,
                        vpnEstablished = OnionVpnService.vpnEstablished.value,
                        killSwitchEnabled = preferences.killSwitchEnabled,
                        runtimePorts = ports,
                        dnsResolverMode = preferences.dnsResolverMode,
                    )
                }
                val hardFails = checks.filter { TunnelValidator.isHardKillSwitchFailure(it) }
                val softFails = checks.filter {
                    it.status == ValidationStatus.Fail && !TunnelValidator.isHardKillSwitchFailure(it)
                }
                _snapshot.update { it.copy(validations = checks) }
                softFails.forEach { check ->
                    Timber.e("Periodic soft FAIL [${check.id}] ${check.label}: ${check.detail}")
                }
                if (hardFails.isNotEmpty()) {
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
        bandwidthSampler.reset()
        throughputText = ""
        var ticks = 0
        throughputJob = scope.launch {
            while (isActive) {
                delay(THROUGHPUT_INTERVAL_MS)
                val phase = _snapshot.value.phase
                if (phase != TunnelPhase.Connected && phase != TunnelPhase.StartingTor) continue
                // Prefer live BW events from ControlPort (zero GETINFO cost).
                // Circuit dumps only every ~2 min; lite health every ~10s.
                ticks++
                if (ticks % FULL_CONTROL_REFRESH_TICKS == 0) {
                    tor.refreshControlCircuits()
                } else if (ticks % LITE_CONTROL_REFRESH_TICKS == 0 || phase == TunnelPhase.StartingTor) {
                    tor.refreshControlHealthLite()
                }
                val st = tor.controlStatus.value
                if (phase == TunnelPhase.Connected && st.connected) {
                    val down = st.lastBwReadPerSec
                    val up = st.lastBwWritePerSec
                    throughputText = if (down > 0L || up > 0L) {
                        "Tor ▼ ${TunnelSnapshotBuilder.formatRate(down)}  ▲ ${TunnelSnapshotBuilder.formatRate(up)}  " +
                            "circ=${st.builtCircuits}"
                    } else {
                        bandwidthSampler.sample().displayText
                    }
                } else if (phase == TunnelPhase.Connected) {
                    throughputText = bandwidthSampler.sample().displayText
                }
                updateSnapshot(phase)
            }
        }
    }

    private fun stopThroughputUpdates() {
        throughputJob?.cancel()
        throughputJob = null
        throughputText = ""
        bandwidthSampler.reset()
    }

    private fun acquireBootstrapWakeLock() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        bootstrapWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OnionVPN:Bootstrap").apply {
            setReferenceCounted(false)
            acquire(BOOTSTRAP_WAKELOCK_TIMEOUT_MS)
        }
    }

    private fun releaseBootstrapWakeLock() {
        bootstrapWakeLock?.let { lock ->
            if (lock.isHeld) lock.release()
        }
        bootstrapWakeLock = null
    }

    private fun updateSnapshot(
        phase: TunnelPhase,
        validations: List<ValidationCheck> = _snapshot.value.validations,
        torRunning: Boolean = _snapshot.value.torRunning,
        dnsCryptRunning: Boolean = _snapshot.value.dnsCryptRunning,
        vpnEstablished: Boolean = _snapshot.value.vpnEstablished,
        lastError: String? = _snapshot.value.lastError,
    ) {
        _snapshot.value = TunnelSnapshotBuilder.build(
            phase = phase,
            preferences = preferences,
            torStatus = tor.controlStatus.value,
            throughputText = throughputText,
            validations = validations,
            torRunning = torRunning,
            dnsCryptRunning = dnsCryptRunning,
            vpnEstablished = vpnEstablished,
            lastError = lastError,
        )
        notifications.update(phase, throughputText)
    }

    companion object {
        const val ACTION_START = "ltechnologies.onionphone.onionvpn.tunnel.START"
        const val ACTION_STOP = "ltechnologies.onionphone.onionvpn.tunnel.STOP"
        const val ACTION_NEWNYM = "ltechnologies.onionphone.onionvpn.tunnel.NEWNYM"
        const val ACTION_REVOKED = "ltechnologies.onionphone.onionvpn.tunnel.REVOKED"
        const val ACTION_ALWAYS_ON = "ltechnologies.onionphone.onionvpn.tunnel.ALWAYS_ON"
        const val EXTRA_ROUTE_ALL = "route_all"
        const val EXTRA_KILL_SWITCH = "kill_switch"
        const val EXTRA_DNSCRYPT_SERVER = "dnscrypt_server"
        const val EXTRA_DNS_MODE = "dns_mode"
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

        private const val BOOTSTRAP_WAKELOCK_TIMEOUT_MS = 3 * 60 * 1000L
        /** Leak checks — less aggressive once Connected to save battery/thermal. */
        private const val VALIDATION_INTERVAL_MS = 90_000L
        private const val VALIDATION_TIMEOUT_MS = 60_000L
        /** Every N lite validations → one full (includes exit-IP). ~15 min at 90s. */
        private const val FULL_VALIDATION_TICKS = 10
        /** UI throughput tick; BW events fill rates without GETINFO each tick. */
        private const val THROUGHPUT_INTERVAL_MS = 2_000L
        /** Every N ticks → lite GETINFO (dormant / liveness). ~10s */
        private const val LITE_CONTROL_REFRESH_TICKS = 5
        /** Every N ticks → circuit/stream dump. ~2 min at 2s ticks. */
        private const val FULL_CONTROL_REFRESH_TICKS = 60

        private val _snapshot = MutableStateFlow(TunnelSnapshot())
        val snapshot: StateFlow<TunnelSnapshot> = _snapshot.asStateFlow()

        fun preferencesFromIntent(intent: Intent): TunnelPreferences = TunnelPreferences(
            routeAllTrafficThroughTor = intent.getBooleanExtra(EXTRA_ROUTE_ALL, true),
            killSwitchEnabled = intent.getBooleanExtra(EXTRA_KILL_SWITCH, true),
            dnsCryptServerName = intent.getStringExtra(EXTRA_DNSCRYPT_SERVER) ?: "cloudflare",
            dnsResolverMode = intent.getStringExtra(EXTRA_DNS_MODE)
                ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
                ?: DnsResolverMode.DNSCRYPT_MUX,
            torBridges = intent.getStringExtra(EXTRA_TOR_BRIDGES).orEmpty(),
            torEntryNodes = intent.getStringExtra(EXTRA_TOR_ENTRY).orEmpty(),
            torExitNodes = intent.getStringExtra(EXTRA_TOR_EXIT).orEmpty(),
            torExcludeNodes = intent.getStringExtra(EXTRA_TOR_EXCLUDE).orEmpty(),
            torNewCircuitPeriodSec = intent.getIntExtra(EXTRA_TOR_NEW_CIRCUIT, 30),
            torMaxCircuitDirtinessSec = intent.getIntExtra(EXTRA_TOR_MAX_DIRTINESS, 180),
            dnsCryptRequireNoLog = intent.getBooleanExtra(EXTRA_DNS_NOLOG, true),
            dnsCryptRequireNoFilter = intent.getBooleanExtra(EXTRA_DNS_NOFILTER, false),
            dnsCryptForceTcp = intent.getBooleanExtra(EXTRA_DNS_FORCE_TCP, true),
            dnsCryptRequireDnssec = intent.getBooleanExtra(EXTRA_DNS_DNSSEC, true),
        )
    }
}
