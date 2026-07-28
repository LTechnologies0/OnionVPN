package ltechnologies.onionphone.onionvpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
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
import ltechnologies.onionphone.onionvpn.MainActivity
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelPortAllocator
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.model.VpnProfileMode
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.validation.TunnelValidator
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.TorBandwidthSampler
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
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

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lifecycleMutex = Mutex()
    private var bootstrapWakeLock: PowerManager.WakeLock? = null
    private var tunnelJob: Job? = null
    private var validationJob: Job? = null
    private var throughputJob: Job? = null
    private var preferences = TunnelPreferences()
    private var runtimePorts: TunnelRuntimePorts? = null
    private var throughputText = ""
    private val bandwidthSampler by lazy { TorBandwidthSampler(applicationInfo.uid) }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (tunnelJob?.isActive == true) {
                    Timber.w("Ignoring duplicate START — tunnel already starting")
                    return START_STICKY
                }
                preferences = preferencesFromIntent(intent)
                startForegroundImmediately(TunnelPhase.StartingTor)
                tunnelJob = scope.launch { runStartSequence() }
                return START_STICKY
            }
            ACTION_STOP -> {
                scope.launch { runStopSequence(userInitiated = true) }
                return START_NOT_STICKY
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
                startForegroundImmediately(TunnelPhase.StartingTor)
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
        throughputJob?.cancel()
        scope.cancel()
        releaseBootstrapWakeLock()
        super.onDestroy()
    }

    private suspend fun runStartSequence() {
        lifecycleMutex.withLock {
            try {
                startTunnel()
            } catch (error: Exception) {
                Timber.e(error, "Tunnel start crashed")
                handleFailure(error.message ?: "Unexpected error", fromValidation = false)
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
            startVpnBlocking(blockingGen)
            if (!waitForBlockingEstablishment(blockingGen)) {
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

        val torResult = tor.start(ports, preferences)
        if (torResult.isFailure) {
            handleFailure(torResult.exceptionOrNull()?.message ?: "Tor failed", fromValidation = false)
            return
        }

        updateSnapshot(TunnelPhase.StartingDnsCrypt, torRunning = true)
        val useDnsCrypt = preferences.dnsResolverMode == DnsResolverMode.DNSCRYPT_MUX
        if (useDnsCrypt) {
            val dnsResult = dnsCrypt.start(preferences.dnsCryptServerName, ports, preferences)
            if (dnsResult.isFailure) {
                // DNSCrypt down ≠ Tor down. Keep Tor; blackhole apps until user retries / FakeDNS.
                handleFailure(
                    message = dnsResult.exceptionOrNull()?.message ?: "DNSCrypt failed",
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
            handleFailure("VPN permission not granted", fromValidation = false, stopTorProcesses = false)
            return
        }

        // Seamless rebind: do NOT tear down Blocking/previous TUN first (clearnet window).
        val vpnGeneration = OnionVpnService.nextGeneration()
        startVpn(VpnProfileMode.Connected, ports, vpnGeneration)

        val vpnReady = waitForVpnEstablishment(vpnGeneration, ports)
        if (!vpnReady) {
            handleFailure("VPN interface not established", fromValidation = false, stopTorProcesses = false)
            return
        }

        val hevSocks = OnionVpnService.hevSocksPort.value
        val hevDns = OnionVpnService.hevDnsCryptPort.value
        val dnsPortExpected = if (useDnsCrypt) ports.dnsCryptListenPort else hevDns
        if (hevSocks != ports.torSocksPort || (useDnsCrypt && hevDns != ports.dnsCryptListenPort)) {
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
            TunnelValidator.validateAll(
                context = applicationContext,
                torConfigFile = tor.torrcFile,
                dnsCryptConfigFile = dnsCrypt.configFile,
                vpnEstablished = OnionVpnService.vpnEstablished.value,
                killSwitchEnabled = preferences.killSwitchEnabled,
                runtimePorts = ports,
                dnsResolverMode = preferences.dnsResolverMode,
            )
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
        startVpnBlocking(gen)
        waitForBlockingEstablishment(gen)
        if (stopTorProcesses) {
            dnsCrypt.stop()
            tor.stop()
        } else {
            Timber.i("Kill-switch Blocking TUN only — Tor/DNSCrypt kept for recovery")
        }
        updateSnapshot(
            phase = TunnelPhase.Blocking,
            torRunning = tor.isRunning(),
            dnsCryptRunning = dnsCrypt.isRunning(),
            vpnEstablished = OnionVpnService.vpnEstablished.value,
            lastError = message,
            validations = validations,
        )
        updateNotification(TunnelPhase.Blocking)
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
        startService(Intent(this, OnionVpnService::class.java).setAction(OnionVpnService.ACTION_DESTROY))
        waitUntilVpnDown()
        dnsCrypt.stop()
        tor.stop()
        releaseBootstrapWakeLock()
        if (resetSnapshot) {
            runtimePorts = null
            throughputText = ""
            _snapshot.value = TunnelSnapshot()
        }
    }

    private fun startVpn(mode: VpnProfileMode, ports: TunnelRuntimePorts, generation: Int) {
        startService(
            Intent(this, OnionVpnService::class.java).apply {
                action = OnionVpnService.ACTION_START
                putExtra(OnionVpnService.EXTRA_ROUTE_ALL, preferences.routeAllTrafficThroughTor)
                putExtra(OnionVpnService.EXTRA_KILL_SWITCH, preferences.killSwitchEnabled)
                putExtra(OnionVpnService.EXTRA_PROFILE_MODE, mode.name)
                putExtra(OnionVpnService.EXTRA_TOR_SOCKS_PORT, ports.torSocksPort)
                putExtra(OnionVpnService.EXTRA_DNSCRYPT_PORT, ports.dnsCryptListenPort)
                putExtra(OnionVpnService.EXTRA_GENERATION, generation)
                putExtra(OnionVpnService.EXTRA_DNS_MODE, preferences.dnsResolverMode.name)
            },
        )
    }

    private fun startVpnBlocking(generation: Int = OnionVpnService.nextGeneration()) {
        startService(
            Intent(this, OnionVpnService::class.java).apply {
                action = OnionVpnService.ACTION_BLOCK
                putExtra(OnionVpnService.EXTRA_ROUTE_ALL, preferences.routeAllTrafficThroughTor)
                putExtra(OnionVpnService.EXTRA_KILL_SWITCH, true)
                putExtra(OnionVpnService.EXTRA_PROFILE_MODE, VpnProfileMode.Blocking.name)
                putExtra(OnionVpnService.EXTRA_GENERATION, generation)
            },
        )
    }

    private suspend fun waitForBlockingEstablishment(generation: Int): Boolean {
        repeat(VPN_READY_POLLS) {
            val established = OnionVpnService.vpnEstablished.value
            val genOk = OnionVpnService.vpnGeneration.value == generation
            val modeOk = OnionVpnService.vpnProfileMode.value == VpnProfileMode.Blocking
            val noForwarder = OnionVpnService.hevSocksPort.value < 0
            if (established && genOk && modeOk && noForwarder) return true
            delay(VPN_READY_POLL_MS)
        }
        Timber.e(
            "Blocking VPN wait timeout gen=$generation established=${OnionVpnService.vpnEstablished.value} " +
                "mode=${OnionVpnService.vpnProfileMode.value}",
        )
        return false
    }

    private var forwarderWatchJob: Job? = null

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
                            startVpn(VpnProfileMode.Connected, ports, gen)
                            if (waitForVpnEstablishment(gen, ports)) {
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

    private suspend fun stopVpnAndWait() {
        startService(Intent(this, OnionVpnService::class.java).setAction(OnionVpnService.ACTION_STOP))
        waitUntilVpnDown()
    }

    private suspend fun waitUntilVpnDown() {
        repeat(VPN_DOWN_POLLS) {
            if (!OnionVpnService.vpnEstablished.value && OnionVpnService.hevSocksPort.value < 0) return
            delay(VPN_READY_POLL_MS)
        }
        Timber.w("VPN still marked established after stop wait")
    }

    private suspend fun waitForVpnEstablishment(generation: Int, ports: TunnelRuntimePorts): Boolean {
        repeat(VPN_READY_POLLS) {
            val established = OnionVpnService.vpnEstablished.value
            val genOk = OnionVpnService.vpnGeneration.value == generation
            val hevOk = OnionVpnService.hevSocksPort.value == ports.torSocksPort &&
                OnionVpnService.hevDnsCryptPort.value == ports.dnsCryptListenPort
            if (established && genOk && hevOk) return true
            delay(VPN_READY_POLL_MS)
        }
        Timber.e(
            "VPN wait timeout gen=$generation established=${OnionVpnService.vpnEstablished.value} " +
                "activeGen=${OnionVpnService.vpnGeneration.value} " +
                "hevSocks=${OnionVpnService.hevSocksPort.value} hevDns=${OnionVpnService.hevDnsCryptPort.value}",
        )
        return false
    }

    private fun startPeriodicValidation() {
        validationJob?.cancel()
        validationJob = scope.launch {
            while (isActive) {
                delay(VALIDATION_INTERVAL_MS)
                if (_snapshot.value.phase != TunnelPhase.Connected) continue
                val ports = runtimePorts ?: continue
                val checks = TunnelValidator.validateAll(
                    context = applicationContext,
                    torConfigFile = tor.torrcFile,
                    dnsCryptConfigFile = dnsCrypt.configFile,
                    vpnEstablished = OnionVpnService.vpnEstablished.value,
                    killSwitchEnabled = preferences.killSwitchEnabled,
                    runtimePorts = ports,
                    dnsResolverMode = preferences.dnsResolverMode,
                )
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
        throughputJob = scope.launch {
            while (isActive) {
                delay(THROUGHPUT_INTERVAL_MS)
                if (_snapshot.value.phase != TunnelPhase.Connected) continue
                val sample = bandwidthSampler.sample()
                throughputText = sample.displayText
                _snapshot.value = _snapshot.value.copy(throughputText = throughputText)
                updateNotification(TunnelPhase.Connected)
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

    private fun startForegroundImmediately(phase: TunnelPhase) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                buildNotification(phase),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, buildNotification(phase))
        }
    }

    private fun updateNotification(phase: TunnelPhase) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(phase))
    }

    private fun buildNotification(phase: TunnelPhase): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, TunnelForegroundService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val phaseText = when (phase) {
            TunnelPhase.Connected -> getString(R.string.notification_connected)
            TunnelPhase.Blocking -> getString(R.string.notification_blocking)
            TunnelPhase.Error -> getString(R.string.notification_error)
            TunnelPhase.Stopping -> getString(R.string.notification_stopping)
            else -> getString(R.string.notification_starting)
        }
        val content = if (phase == TunnelPhase.Connected && throughputText.isNotBlank()) {
            throughputText
        } else {
            phaseText
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(
                when (phase) {
                    TunnelPhase.Connected -> getString(R.string.notification_connected)
                    TunnelPhase.Blocking -> getString(R.string.notification_blocking)
                    else -> getString(R.string.app_name)
                },
            )
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setOngoing(phase.isActiveNotification)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.action_stop), stopIntent)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private val TunnelPhase.isActiveNotification: Boolean
        get() = when (this) {
            TunnelPhase.Idle, TunnelPhase.Error, TunnelPhase.Stopping -> false
            else -> true
        }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_desc)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun updateSnapshot(
        phase: TunnelPhase,
        validations: List<ValidationCheck> = _snapshot.value.validations,
        torRunning: Boolean = _snapshot.value.torRunning,
        dnsCryptRunning: Boolean = _snapshot.value.dnsCryptRunning,
        vpnEstablished: Boolean = _snapshot.value.vpnEstablished,
        lastError: String? = _snapshot.value.lastError,
    ) {
        _snapshot.value = TunnelSnapshot(
            phase = phase,
            killSwitchEnabled = preferences.killSwitchEnabled,
            torRunning = torRunning,
            dnsCryptRunning = dnsCryptRunning,
            vpnEstablished = vpnEstablished,
            validations = validations,
            lastError = lastError,
            throughputText = if (phase == TunnelPhase.Connected) throughputText else "",
        )
        updateNotification(phase)
    }

        companion object {
        const val ACTION_START = "ltechnologies.onionphone.onionvpn.tunnel.START"
        const val ACTION_STOP = "ltechnologies.onionphone.onionvpn.tunnel.STOP"
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

        private const val CHANNEL_ID = "onionvpn_tunnel"
        private const val NOTIFICATION_ID = 42
        private const val BOOTSTRAP_WAKELOCK_TIMEOUT_MS = 3 * 60 * 1000L
        /** Faster than 2 min — catch route hijacks / forwarder death sooner. */
        private const val VALIDATION_INTERVAL_MS = 30_000L
        /** Exit IP check via Tor SOCKS can take ~25s; keep headroom for full suite. */
        private const val VALIDATION_TIMEOUT_MS = 60_000L
        private const val THROUGHPUT_INTERVAL_MS = 3_000L
        private const val VPN_READY_POLL_MS = 250L
        private const val VPN_READY_POLLS = 40
        private const val VPN_DOWN_POLLS = 40

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
        )
    }
}
