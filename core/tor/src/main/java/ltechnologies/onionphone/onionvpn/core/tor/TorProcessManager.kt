package ltechnologies.onionphone.onionvpn.core.tor

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.SocksJavaProxyAuth
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.observability.MemoryHygiene
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.tor.arti.ArtiRuntime
import ltechnologies.onionphone.onionvpn.core.tor.config.TorBridgeConfig
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlCompat
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import ltechnologies.onionphone.onionvpn.core.tor.lifecycle.TorDnsResolve
import ltechnologies.onionphone.onionvpn.core.tor.lifecycle.TorReadiness
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import org.torproject.arti.ArtiControlNative
import timber.log.Timber

/**
 * Owns the Tor client runtime and orchestrates the sequential start/stop pipeline.
 *
 * Supports two engines via [TunnelPreferences.torEngine]:
 * - [TorEngine.LITTLE_T] — `libtor.so` process + torrc + ControlSocket (default)
 * - [TorEngine.ARTI] — in-process Arti (`arti-mobile`) SOCKS+DNS; synthetic control status
 *
 * Lives in the root `core.tor` package (public DI entry) while control/config/lifecycle
 * internals stay in subpackages — keeps Hilt/KSP resolution stable.
 *
 * **Little-t start pipeline (ordered):**
 * 1. [stopInternal] + kill orphans + delete stale ControlSocket/cookie
 * 2. [writeTorrc] via [TorConfigWriter]
 * 3. [spawnTorProcess]
 * 4. [waitForControlPlane] (sock + cookie files)
 * 5. [TorControlClient.connect] (auth / SETEVENTS)
 * 6. [waitForBootstrap] (GETINFO + [TorReadiness] listeners)
 * 7. SIGNAL ACTIVE
 *
 * **Arti start pipeline:** stop → JNI start → wait SOCKS accept → wait
 * `ready_for_traffic` (+ DNSPort) → synthetic status. DNSCrypt must not start until this
 * returns — upstream SOCKS + bootstrap DNSPort need a fully bootstrapped TorClient.
 *
 * Control-plane ops go through Arti-aware wrappers mapped by [TorControlCompat]
 * (doc-backed little-t ↔ Arti 1:1 matrix). Prefer those over raw [control] from app
 * code; [control.isConnected] stays false on Arti.
 *
 * Imported by: DI, TunnelForegroundService, MainViewModel, OnionVpnApplication.
 */
class TorProcessManager(
    private val context: Context,
) {
    private var process: Process? = null
    private var logThread: Thread? = null
    private var runtimePorts: TunnelRuntimePorts? = null
    /**
     * True when [attachExternalRuntimePorts] published onionmasq sidecar ports without
     * starting arti-mobile / little-t ([isRunning] stays false).
     */
    @Volatile
    private var externalDataPlanePorts: Boolean = false
    private var preferences: TunnelPreferences = TunnelPreferences()
    private var activeEngine: TorEngine = TorEngine.LITTLE_T
    private val arti = ArtiRuntime(context)
    /**
     * App-layer dormant flag for Arti when Ext JNI is absent.
     * Prefer [ArtiControlNative.setDormant] (TorClient::set_dormant) when patched .so is loaded.
     */
    @Volatile
    private var artiDormant: Boolean = false

    /**
     * Depth of intentional Tor downtime (NEWNYM / hard restart / DisableNetwork bounce).
     * Periodic kill-switch validation and forwarder watchdog must not treat SOCKS refusal
     * as a leak while this is > 0.
     */
    private val maintenanceDepth = AtomicInteger(0)

    /** Serializes Arti stop/start and C Tor DisableNetwork bounce (no concurrent restarts). */
    private val downtimeMutex = Mutex()

    /** True while Tor is mid intentional downtime (SOCKS briefly down by design). */
    val isInMaintenance: Boolean
        get() = maintenanceDepth.get() > 0

    /**
     * Invoked when Tor enters/leaves intentional downtime that drops SocksPort
     * (DisableNetwork bounce / Arti restart). App layer MUST pause SOCKS bridges
     * before Tor closes listeners so CONNECT does not race `DisableNetwork`
     * (control-spec / Tor warn: "Tried to open a socket with DisableNetwork set").
     *
     * Not fired for little-t SIGNAL NEWNYM (SocksPort stays up; circuits rebuild).
     */
    var onTorDowntimeChanged: ((inDowntime: Boolean) -> Unit)? = null

    /** Nested count of [withTorDowntime] calls that requested bridge pause. */
    private val bridgePauseDepth = AtomicInteger(0)

    /**
     * Run [block] under maintenance + exclusive downtime lock.
     * Nested callers queue on the mutex (safe; avoids overlapping Arti JNI restarts).
     *
     * @param pauseUpstreamSocks when true, notify [onTorDowntimeChanged] so VPN
     *   bridges stop dialing Tor. Use false for little-t NEWNYM (SOCKS stays up).
     */
    private suspend fun <T> withTorDowntime(
        pauseUpstreamSocks: Boolean = true,
        block: suspend () -> T,
    ): T =
        downtimeMutex.withLock {
            maintenanceDepth.incrementAndGet()
            val pausedBridges = if (pauseUpstreamSocks) {
                bridgePauseDepth.incrementAndGet() == 1
            } else {
                false
            }
            if (pausedBridges) {
                runCatching { onTorDowntimeChanged?.invoke(true) }
                    .onFailure { Timber.w(it, "onTorDowntimeChanged(true) failed") }
                // Stop DNSCrypt before Tor listeners die — avoids bootstrap_resolvers /
                // SOCKS spam against a restarting Arti / DisableNetwork bounce.
                runCatching { onDnsDependentPause?.invoke() }
                    .onFailure { Timber.w(it, "onDnsDependentPause failed") }
            }
            var ok = false
            try {
                val result = block()
                ok = true
                result
            } finally {
                if (pauseUpstreamSocks && bridgePauseDepth.decrementAndGet() == 0) {
                    if (ok) {
                        // Resume DNSCrypt only after block waited for traffic-ready (Arti)
                        // or SocksPort settle (C Tor), then unpause hev SOCKS bridges.
                        runCatching { onDnsDependentResume?.invoke() }
                            .onFailure { Timber.w(it, "onDnsDependentResume failed") }
                        runCatching { onTorDowntimeChanged?.invoke(false) }
                            .onFailure { Timber.w(it, "onTorDowntimeChanged(false) failed") }
                    } else {
                        // Do not restart DNSCrypt against a failed Arti/DisableNetwork path.
                        // Unpause bridges so dials fail-closed and validation can react.
                        runCatching { onTorDowntimeChanged?.invoke(false) }
                            .onFailure { Timber.w(it, "onTorDowntimeChanged(false) after fail") }
                        Timber.w(
                            "withTorDowntime failed — bridges unpaused without DNSCrypt resume",
                        )
                    }
                }
                maintenanceDepth.decrementAndGet()
            }
        }

    /**
     * Public control session — prefer this over adding more manager wrappers.
     * On Arti, [control.isConnected] stays false; status is synthetic via
     * [TorControlClient.publishSyntheticStatus].
     */
    val control = TorControlClient()

    val controlStatus: StateFlow<TorControlStatus> = control.status
    val controlEvents = control.events

    /**
     * App-layer CLEARDNSCACHE / NEWNYM hook — clear DnsHostnameCache + OnionAutomap
     * (vpn module) so Arti Automap store matches control-spec client DNS clear.
     *
     * May also soft-restart DNSCrypt when it is still running (little-t NEWNYM /
     * soft CLEARDNSCACHE). Hard Arti/C-Tor downtime uses [onDnsDependentPause] /
     * [onDnsDependentResume] instead so DNSCrypt never races a dead SOCKS.
     */
    var onClientDnsCacheClear: (() -> Unit)? = null

    /**
     * Pause DNSCrypt (and any Tor-SOCKS DNS dependent) while Tor listeners are down.
     * Invoked only when [withTorDowntime] pauses upstream SOCKS bridges.
     */
    var onDnsDependentPause: (suspend () -> Unit)? = null

    /**
     * Resume DNSCrypt after Tor is traffic-ready again (Arti: post-[waitForArtiBootstrap]).
     */
    var onDnsDependentResume: (suspend () -> Unit)? = null

    val configDirectory: File
        get() = File(context.filesDir, "tor").also { it.mkdirs() }

    val torrcFile: File
        get() = File(configDirectory, "torrc")

    val controlSocketFile: File
        get() = File(configDirectory, TorConfigWriter.CONTROL_SOCKET_NAME)

    val cookieFile: File
        get() = File(configDirectory, TorConfigWriter.COOKIE_FILE_NAME)

    val binaryFile: File
        get() = File(context.applicationInfo.nativeLibraryDir, "libtor.so")

    val nativeLibraryDir: File
        get() = File(context.applicationInfo.nativeLibraryDir)

    /** Engine used by the last successful [start] (or preference while starting). */
    val engine: TorEngine
        get() = activeEngine

    /** C Tor child PID when little-t is running; null for Arti / stopped. */
    fun nativeProcessPid(): Int? {
        val proc = process ?: return null
        if (!proc.isAlive) return null
        return runCatching {
            val method = Process::class.java.getMethod("pid")
            (method.invoke(proc) as Long).toInt()
        }.getOrNull()?.takeIf { it > 0 }
    }

    /** Arti runtime status file (null semantics when using C Tor). */
    val artiStatusFile: File
        get() = arti.statusFile

    /** Config file path for validators: torrc (C Tor) or arti.status (Arti). */
    val runtimeConfigFile: File
        get() = when (activeEngine) {
            TorEngine.ARTI -> arti.statusFile
            TorEngine.LITTLE_T -> torrcFile
        }

    /** Optional sink for stderr/stdout / Arti log lines. */
    var onLogLine: ((String) -> Unit)? = null
        set(value) {
            field = value
            arti.onLogLine = value
        }

    /**
     * Runs the full start pipeline on [Dispatchers.IO].
     *
     * @return success when bootstrap + listeners ready; failure rolls back via [stopInternal]
     */
    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        OpTrace.stepSuspending("tor", "start engine=${preferences.torEngine}", ProcessLogLevel.INFO) {
            this@TorProcessManager.preferences = preferences
            activeEngine = preferences.torEngine
            when (activeEngine) {
                TorEngine.ARTI -> {
                    artiDormant = false
                    startArti(ports, preferences)
                }
                TorEngine.LITTLE_T -> startLittleT(ports, preferences)
            }
        }
    }

    private suspend fun startArti(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ): Result<Unit> {
        OpTrace.debug("tor", "arti.stop_prior")
        stopInternal()
        runtimePorts = ports
        return try {
            OpTrace.stepSuspending("tor", "arti.jni_start", ProcessLogLevel.INFO) {
                arti.start(ports, preferences)
            }
            // Listeners alone are not enough: DNSCrypt bootstrap_resolvers + proxy need
            // ready_for_traffic (parity with little-t waitForBootstrap before DNSCrypt).
            OpTrace.stepSuspending("tor", "arti.bootstrap", ProcessLogLevel.INFO) {
                waitForArtiBootstrap(ports)
            }
            publishArtiReadyStatus()
            OpTrace.info(
                "tor",
                "Arti ready socks=${ports.torSocksPort} dns=${ports.torDnsPort} " +
                    "frac=${arti.bootstrapFractionOrNull()} readyTraffic=${arti.readyForTrafficNative()}",
            )
            Result.success(Unit)
        } catch (error: Exception) {
            OpTrace.error("tor", "Arti failed to start", error)
            Timber.e(error, "Arti failed to start")
            stopInternal()
            runtimePorts = null
            Result.failure(TunnelFailure.fromThrowable(error, context = "arti.start"))
        }
    }

    private suspend fun startLittleT(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ): Result<Unit> {
        OpTrace.debug("tor", "little_t.stop_prior")
        stopInternal()
        killOrphanedProcesses()
        runCatching { controlSocketFile.delete() }
        runCatching { cookieFile.delete() }
        runtimePorts = ports
        return try {
            OpTrace.step("tor", "ensure_binaries") {
                ensureExecutable(binaryFile)
                ensurePluggableTransportBinaries(preferences.torBridges)
                ensureGeoIpFiles()
                prepareDataDirectoryForBridges(preferences.torBridges)
            }
            OpTrace.step("tor", "write_torrc") { writeTorrc(ports) }
            OpTrace.step("tor", "spawn") { spawnTorProcess() }
            OpTrace.stepSuspending("tor", "wait_control") { waitForControlPlane() }
            OpTrace.stepSuspending("tor", "control_connect") {
                control.connect(
                    controlSocketPath = controlSocketFile,
                    cookieFile = cookieFile,
                    bridgesConfigured = TorBridgeConfig.isConfigured(preferences.torBridges),
                )
            }
            OpTrace.stepSuspending("tor", "bootstrap", ProcessLogLevel.INFO) {
                waitForBootstrap(ports)
            }
            OpTrace.stepSuspending("tor", "geoip") {
                ensureGeoIpFiles(socksPort = ports.torSocksPort)
                applyGeoIpIfPresent()
            }
            OpTrace.stepSuspending("tor", "set_active") { control.setActive() }
            OpTrace.info(
                "tor",
                "Tor ready socks=${ports.torSocksPort} " +
                    "bootstrap=${control.status.value.bootstrapProgress}% " +
                    "circuits=${control.status.value.builtCircuits}",
            )
            Result.success(Unit)
        } catch (error: Exception) {
            OpTrace.error("tor", "Tor failed to start", error)
            Timber.e(error, "Tor failed to start")
            stopInternal()
            runtimePorts = null
            Result.failure(TunnelFailure.fromThrowable(error, context = "tor.start"))
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        OpTrace.stepSuspending("tor", "stop") { stopInternal() }
    }

    fun isRunning(): Boolean = when (activeEngine) {
        TorEngine.ARTI -> arti.isRunning()
        TorEngine.LITTLE_T -> process?.isAlive == true
    }

    /** Probe SocksPort while Tor / onionmasq sidecar path is published. */
    fun currentProbeSocksPort(): Int? =
        runtimePorts?.torProbeSocksPort?.takeIf { it > 0 && (isRunning() || externalDataPlanePorts) }

    /**
     * Onionmasq plane skips arti-mobile — orchestrator publishes remapped sidecar ports here
     * so GeoIP / reputation / Moat can discover the probe SOCKS without [isRunning].
     */
    fun attachExternalRuntimePorts(ports: TunnelRuntimePorts) {
        runtimePorts = ports
        externalDataPlanePorts = true
        // Onionmasq plane skips tor.start() — keep engine aligned for control/status IO.
        activeEngine = TorEngine.ARTI
        preferences = preferences.copy(torEngine = TorEngine.ARTI)
        Timber.i(
            "TorProcessManager attached external ports socks=%d probe=%d dns=%d engine=ARTI",
            ports.torSocksPort,
            ports.torProbeSocksPort,
            ports.torDnsPort,
        )
    }

    fun clearExternalRuntimePorts() {
        if (!externalDataPlanePorts) return
        externalDataPlanePorts = false
        runtimePorts = null
        Timber.i("TorProcessManager cleared external runtime ports")
    }

    /** True when classic ControlSocket session is open (never true on Arti). */
    fun isClassicControlConnected(): Boolean =
        activeEngine == TorEngine.LITTLE_T && control.isConnected

    private fun requireClassic(op: String): Result<Unit>? {
        if (activeEngine == TorEngine.ARTI) {
            return Result.failure(IOException(TorControlCompat.unsupportedMessage(op)))
        }
        if (!control.isConnected) {
            return Result.failure(IOException("control not connected"))
        }
        return null
    }

    private var lastArtiNewNymMs: Long = 0L

    /**
     * New identity: C Tor SIGNAL NEWNYM; Arti full runtime restart (rate-limited ~10s).
     * @see TorControlCompat Op NEWNYM
     */
    suspend fun newNym(): Result<Unit> = withContext(Dispatchers.IO) {
        when (activeEngine) {
            TorEngine.ARTI -> {
                if (!arti.isRunning()) {
                    return@withContext Result.failure(IOException("Arti not running"))
                }
                val now = System.currentTimeMillis()
                val wait = lastArtiNewNymMs + ARTI_NEWNYM_MIN_INTERVAL_MS - now
                if (wait > 0) {
                    return@withContext Result.failure(
                        IOException("NEWNYM rate-limited — wait ${((wait + 999) / 1000)}s"),
                    )
                }
                runCatching {
                    withTorDowntime {
                        arti.restartForNewIdentity()
                        runtimePorts?.let { waitForArtiBootstrap(it) }
                        clearAppDnsCaches()
                        publishArtiReadyStatus()
                    }
                }.fold(
                    onSuccess = {
                        lastArtiNewNymMs = System.currentTimeMillis()
                        Timber.i("Arti new-identity restart complete")
                        Result.success(Unit)
                    },
                    onFailure = { e ->
                        Timber.w(e, "Arti new-identity failed")
                        Result.failure(e)
                    },
                )
            }
            TorEngine.LITTLE_T -> {
                if (!control.isConnected) {
                    return@withContext Result.failure(IOException("control not connected"))
                }
                // Holdoff so validation/watchdog don't treat circuit rebuild as a leak.
                // SocksPort stays up — do not pause VPN bridges (unlike DisableNetwork).
                runCatching {
                    withTorDowntime(pauseUpstreamSocks = false) {
                        control.newNym().getOrThrow()
                        clearAppDnsCaches()
                        // Brief settle — NEWNYM does not drop SOCKS but streams rebuild.
                        delay(NEWNYM_SETTLE_MS)
                    }
                }.fold(
                    onSuccess = {
                        Timber.i("SIGNAL NEWNYM accepted")
                        Result.success(Unit)
                    },
                    onFailure = { e ->
                        Timber.w(e, "NEWNYM failed")
                        Result.failure(e)
                    },
                )
            }
        }
    }

    /** SIGNAL ACTIVE — Arti: TorClient::set_dormant(Normal) when Ext JNI present. */
    fun signalActive(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            artiDormant = false
            val native = arti.setDormantNative(soft = false)
            publishArtiReadyStatus()
            Timber.i(
                "Arti ACTIVE (native set_dormant=%s; runtime kept)",
                native,
            )
            return Result.success(Unit)
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setActive().also {
            it.onSuccess { Timber.i("SIGNAL ACTIVE") }
            it.onFailure { e -> Timber.w(e, "ACTIVE failed") }
        }
    }

    /**
     * SIGNAL DORMANT — Arti: TorClient::set_dormant(Soft) when Ext JNI present;
     * otherwise synthetic flag. Runtime stays up under Blocking TUN.
     */
    fun signalDormant(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            artiDormant = true
            val native = arti.setDormantNative(soft = true)
            publishArtiReadyStatus()
            Timber.i(
                "Arti DORMANT (native set_dormant Soft=%s; runtime kept under Blocking)",
                native,
            )
            return Result.success(Unit)
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setDormant()
    }

    /**
     * SIGNAL CLEARDNSCACHE — forget client DNS; also flush app Automap + DNSCrypt
     * (via [onClientDnsCacheClear]) so sticky A/AAAA cannot link identity across circuits.
     */
    fun clearDnsCache(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            // Soft path: wake / re-probe first; only flush DNSCrypt when upstream is ready.
            return onNetworkChanged()
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.clearDnsCache().also { result ->
            if (result.isSuccess) clearAppDnsCaches()
        }
    }

    /** DROPTIMEOUTS — Arti: soft recovery. */
    fun dropTimeouts(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) return onNetworkChanged()
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.dropTimeouts()
    }

    /** DROPGUARDS — Arti: hard restart (clears client state). */
    suspend fun dropGuards(): Result<Unit> = withContext(Dispatchers.IO) {
        if (activeEngine == TorEngine.ARTI) {
            return@withContext recoverNetworkHard()
        }
        if (!control.isConnected) {
            return@withContext Result.failure(IOException("control not connected"))
        }
        control.dropGuards()
    }

    /** SETCONF DisableNetwork — Arti: hard restart. */
    suspend fun setDisableNetwork(disabled: Boolean): Result<Unit> = withContext(Dispatchers.IO) {
        if (activeEngine == TorEngine.ARTI) {
            return@withContext if (disabled) {
                // Soft stop listeners by stopping Arti; caller should re-enable via hard recover.
                arti.stop()
                control.resetStatus()
                Result.success(Unit)
            } else {
                recoverNetworkHard()
            }
        }
        if (!control.isConnected) {
            return@withContext Result.failure(IOException("control not connected"))
        }
        control.setDisableNetwork(disabled)
    }

    /**
     * Live SETCONF MaxCircuitDirtiness / NewCircuitPeriod.
     * Arti: CircuitTimingBuilder::max_dirtiness + PreemptiveCircuitConfig::prediction_lifetime
     * via Ext JNI reconfigure when available.
     */
    fun applyCircuitTimingLive(
        maxCircuitDirtinessSec: Int,
        newCircuitPeriodSec: Int,
    ): Result<Unit> {
        preferences = preferences.copy(
            torMaxCircuitDirtinessSec = maxCircuitDirtinessSec,
            torNewCircuitPeriodSec = newCircuitPeriodSec,
        )
        if (activeEngine == TorEngine.ARTI) {
            val applied = arti.applyCircuitTimingLive(maxCircuitDirtinessSec, newCircuitPeriodSec)
            val predApplied = ArtiRuntime.artiPredictionLifetimeSec(newCircuitPeriodSec)
            Timber.i(
                "Arti circuit timing dirt=%ds prediction_lifetime=%ds (ui NewCircuitPeriod=%ds) applied=%s",
                maxCircuitDirtinessSec,
                predApplied,
                newCircuitPeriodSec,
                applied,
            )
            return Result.success(Unit)
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setCircuitTiming(maxCircuitDirtinessSec, newCircuitPeriodSec).also {
            it.onSuccess {
                Timber.i(
                    "SETCONF circuit timing dirtiness=%ds period=%ds",
                    maxCircuitDirtinessSec,
                    newCircuitPeriodSec,
                )
            }
        }
    }

    fun closeCircuit(id: String, ifUnused: Boolean = true): Result<Unit> {
        requireClassic("CLOSECIRCUIT")?.let { return it }
        return control.closeCircuit(id, ifUnused)
    }

    fun closeStream(id: String, reason: String = TorControlCatalog.StreamEndReason.DONE): Result<Unit> {
        requireClassic("CLOSESTREAM")?.let { return it }
        return control.closeStream(id, reason)
    }

    fun listCircuits(): List<ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo> =
        if (isClassicControlConnected()) control.listCircuits() else emptyList()

    fun listStreams(): List<ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo> =
        if (isClassicControlConnected()) control.listStreams() else emptyList()

    fun extendNewCircuit(): Result<String> {
        requireClassic("EXTENDCIRCUIT")?.let { return Result.failure(it.exceptionOrNull()!!) }
        return control.extendNewCircuit()
    }

    /**
     * Close all built circuits. Arti: NEWNYM-equivalent restart (semantic 1:1).
     */
    suspend fun closeBuiltCircuits(): Result<Int> = withContext(Dispatchers.IO) {
        when (activeEngine) {
            TorEngine.ARTI -> {
                newNym().map { 0 }
            }
            TorEngine.LITTLE_T -> {
                if (!control.isConnected) {
                    return@withContext Result.failure(IOException("control not connected"))
                }
                control.closeBuiltCircuits()
            }
        }
    }

    /**
     * Underlying Android network changed (Wi‑Fi ↔ cell, loss, validated flip).
     *
     * C Tor soft: DROPTIMEOUTS → ACTIVE → CLEARDNSCACHE.
     * Arti soft: re-probe SOCKS/DNS (no classic DROPTIMEOUTS).
     */
    fun onNetworkChanged(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            // Orbot #1471: after net flip Tor must wake; Arti has no DROPTIMEOUTS —
            // set_dormant(Normal) + re-probe listeners is the soft equivalent.
            // Do NOT restart DNSCrypt until SOCKS + ready_for_traffic — otherwise
            // bootstrap_resolvers race a waking TorClient.
            arti.setDormantNative(soft = false)
            publishArtiReadyStatus()
            val ok = isReadyForDnsCryptUpstream()
            Timber.i(
                "Arti network change soft recovery ready=%s socks=%s",
                ok,
                runtimePorts?.let { TorReadiness.isPrimarySocksReady(it) },
            )
            if (!ok) return Result.failure(IOException("Arti not ready for DNSCrypt upstream"))
            clearAppDnsCaches()
            return Result.success(Unit)
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        control.dropTimeouts().onFailure { Timber.w(it, "DROPTIMEOUTS failed") }
        val active = control.setActive()
        control.clearDnsCache().onFailure { Timber.w(it, "CLEARDNSCACHE failed") }
        // App + DNSCrypt sticky IPs — same deanonymization class as Tor CLEARDNSCACHE.
        clearAppDnsCaches()
        control.refreshHealthLite()
        return active.also {
            it.onSuccess {
                Timber.i("Tor network recovery: DROPTIMEOUTS+ACTIVE+CLEARDNSCACHE")
            }
        }
    }

    /**
     * Hard recovery: C Tor DisableNetwork bounce; Arti full runtime restart.
     */
    suspend fun recoverNetworkHard(): Result<Unit> = withContext(Dispatchers.IO) {
        when (activeEngine) {
            TorEngine.ARTI -> {
                runCatching {
                    withTorDowntime {
                        arti.restartHard()
                        runtimePorts?.let { waitForArtiBootstrap(it) }
                        clearAppDnsCaches()
                        publishArtiReadyStatus()
                    }
                }.fold(
                    onSuccess = {
                        Timber.w("Arti network recovery HARD: runtime restart")
                        Result.success(Unit)
                    },
                    onFailure = { e ->
                        Timber.w(e, "Arti hard recovery failed")
                        Result.failure(e)
                    },
                )
            }
            TorEngine.LITTLE_T -> {
                if (!control.isConnected) {
                    return@withContext Result.failure(IOException("control not connected"))
                }
                // DisableNetwork bounce drops listeners briefly — same race as Arti NEWNYM.
                // Bridges are paused via onTorDowntimeChanged(true) before DisableNetwork=1.
                withTorDowntime {
                    control.dropTimeouts().onFailure { Timber.w(it, "DROPTIMEOUTS failed") }
                    control.setDisableNetwork(true).onFailure { Timber.w(it, "DisableNetwork=1 failed") }
                    control.setDisableNetwork(false).onFailure { Timber.w(it, "DisableNetwork=0 failed") }
                    // Let SocksPort listeners return before DNSCrypt resume + bridge unpause.
                    delay(SOCKS_AFTER_DISABLE_NETWORK_MS)
                    runtimePorts?.let { ports ->
                        repeat(30) {
                            if (TorReadiness.isPrimarySocksReady(ports)) return@let
                            delay(100)
                        }
                    }
                    val active = control.setActive()
                    control.clearDnsCache().onFailure { Timber.w(it, "CLEARDNSCACHE failed") }
                    // Automap / DNSCrypt sticky IPs (DNSCrypt itself resumed in finally).
                    clearAppDnsCaches()
                    control.refreshHealthLite()
                    active
                }.also {
                    it.onSuccess {
                        Timber.w(
                            "Tor network recovery HARD: DROPTIMEOUTS+DisableNetwork bounce+ACTIVE+CLEARDNSCACHE",
                        )
                    }
                }
            }
        }
    }

    /** GETINFO refresh — Arti: synthetic SOCKS/DNS status. */
    fun refreshControlInfo() {
        if (externalDataPlanePorts) {
            // onionmasq plane — no arti-mobile / classic control; status from BootstrapEvent.
            return
        }
        if (activeEngine == TorEngine.ARTI) {
            publishArtiReadyStatus()
            return
        }
        if (control.isConnected) control.refreshInfo()
    }

    fun refreshControlCircuits() {
        if (!isClassicControlConnected()) return
        control.refreshCircuits()
    }

    fun refreshControlHealthLite() {
        if (externalDataPlanePorts) return
        if (activeEngine == TorEngine.ARTI) {
            publishArtiReadyStatus()
            return
        }
        if (control.isConnected) control.refreshHealthLite()
    }

    fun refreshControlTraffic() {
        // Arti: GETINFO traffic unsupported — TunnelThroughputTracker uses UID TrafficStats.
        if (!isClassicControlConnected()) return
        control.refreshTraffic()
    }

    /**
     * Live SETCONF bridges. Arti: restart with new bridgeLines (semantic 1:1 apply).
     */
    suspend fun setBridgesLive(bridgeText: String): Result<Unit> = withContext(Dispatchers.IO) {
        preferences = preferences.copy(torBridges = bridgeText)
        if (activeEngine == TorEngine.ARTI) {
            if (!arti.isRunning()) {
                return@withContext Result.failure(IOException("Arti not running"))
            }
            return@withContext runCatching {
                withTorDowntime {
                    arti.restartWithPreferences(preferences)
                    runtimePorts?.let { waitForArtiBootstrap(it) }
                    clearAppDnsCaches()
                    publishArtiReadyStatus()
                }
            }.fold(
                onSuccess = {
                    Timber.i("Arti bridges applied via restart")
                    Result.success(Unit)
                },
                onFailure = { e ->
                    Timber.w(e, "Arti bridges restart failed")
                    Result.failure(e)
                },
            )
        }
        if (!control.isConnected) {
            return@withContext Result.failure(IOException("control not connected"))
        }
        val lines = TorBridgeConfig.parseLines(bridgeText)
        control.setBridges(lines).also {
            it.onSuccess { Timber.i("SETCONF bridges live count=%d", lines.size) }
        }
    }

    /**
     * Live SETCONF Entry/Exit/ExcludeNodes.
     * Arti: ExitNodes single-country via StreamPrefs::exit_country (control-api≥2);
     * Entry/Exclude remain ENGINE_LIMITATION.
     */
    fun setNodePrefsLive(entry: String, exit: String, exclude: String): Result<Unit> {
        preferences = preferences.copy(
            torEntryNodes = entry,
            torExitNodes = exit,
            torExcludeNodes = exclude,
        )
        if (activeEngine == TorEngine.ARTI) {
            if (entry.isNotBlank() || exclude.isNotBlank()) {
                Timber.w("Arti ignores EntryNodes/ExcludeNodes (ExitNodes country only)")
            }
            val codes = ArtiRuntime.parseCountryCodes(exit)
            if (codes.size > 1) {
                return Result.failure(
                    IOException(
                        "Arti ExitNodes supports a single country code (got ${codes.size})",
                    ),
                )
            }
            val ok = arti.applyExitCountryLive(exit)
            return if (ok || codes.isEmpty()) {
                Result.success(Unit)
            } else {
                Result.failure(IOException("Arti applyExitCountry failed (need control-api≥2)"))
            }
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setNodePrefs(entry, exit, exclude)
    }

    /** SETCONF GeoIPFile — unsupported on Arti (no circuit country UI). */
    fun setGeoIpFilesLive(geoIpPath: String, geoIp6Path: String): Result<Unit> {
        requireClassic("SETCONF_geoip")?.let { return it }
        return control.setGeoIpFiles(geoIpPath, geoIp6Path)
    }

    /**
     * control-spec RESOLVE — Arti: TorClient::resolve via Ext JNI when available,
     * else DNS A query via DNSPort (app-layer 1:1).
     */
    suspend fun resolveHostname(hostname: String, timeoutMs: Long = 15_000): Result<String> =
        withContext(Dispatchers.IO) {
            when (activeEngine) {
                TorEngine.ARTI -> {
                    arti.resolveHostnameNative(hostname)?.let {
                        return@withContext Result.success(it)
                    }
                    val port = runtimePorts?.torDnsPort
                        ?: return@withContext Result.failure(IOException("Arti DNSPort unknown"))
                    runCatching {
                        TorDnsResolve.resolveA(
                            hostname = hostname,
                            dnsPort = port,
                            timeoutMs = timeoutMs.toInt().coerceIn(500, 60_000),
                        )
                    }
                }
                TorEngine.LITTLE_T -> {
                    if (!control.isConnected) {
                        return@withContext Result.failure(IOException("control not connected"))
                    }
                    control.resolve(hostname, timeoutMs)
                }
            }
        }

    /** SIGNAL RELOAD — Arti: hard restart (semantic 1:1 with HUP/reload). */
    suspend fun signalReload(): Result<Unit> = withContext(Dispatchers.IO) {
        if (activeEngine == TorEngine.ARTI) {
            return@withContext recoverNetworkHard()
        }
        if (!control.isConnected) {
            return@withContext Result.failure(IOException("control not connected"))
        }
        control.reload()
    }

    fun signalHeartbeat(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) return Result.success(Unit)
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.heartbeat()
    }

    private fun clearAppDnsCaches() {
        runCatching { onClientDnsCacheClear?.invoke() }
            .onFailure { Timber.w(it, "onClientDnsCacheClear failed") }
    }

    /**
     * True when DNSCrypt may dial Tor SOCKS / DNSPort without racing bootstrap.
     * Little-t: process alive + primary SOCKS. Arti: [publishArtiReadyStatus] ready gate.
     */
    fun isReadyForDnsCryptUpstream(): Boolean {
        val ports = runtimePorts ?: return false
        return when (activeEngine) {
            TorEngine.LITTLE_T ->
                process?.isAlive == true && TorReadiness.isPrimarySocksReady(ports)
            TorEngine.ARTI -> isArtiTrafficReady(ports)
        }
    }

    private fun isArtiTrafficReady(ports: TunnelRuntimePorts): Boolean {
        if (artiDormant || !arti.isRunning()) return false
        if (!TorReadiness.isPrimarySocksReady(ports)) return false
        val frac = arti.bootstrapFractionOrNull()
        val nativeReady = arti.readyForTrafficNative()
        return when {
            nativeReady -> true
            frac != null && frac >= 0.99f -> true
            // Stock AAR without Ext: SOCKS accept after waitForListeners is best-effort;
            // DNSCrypt start path still waits via [waitForArtiBootstrap] (DNSPort).
            frac == null && !ArtiControlNative.isAvailable() -> true
            else -> false
        }
    }

    private fun publishArtiReadyStatus() {
        // Primary Arti SOCKS only — role-mux DNSCrypt/probe ports are app-layer relays.
        val socksUp = runtimePorts?.let { TorReadiness.isPrimarySocksReady(it) } == true
        val frac = arti.bootstrapFractionOrNull()
        val nativeReady = arti.readyForTrafficNative()
        // Prefer Ext JNI ready_for_traffic / bootstrap frac — never treat SOCKS accept alone
        // as "bootstrapped 100%" (listeners can be up before consensus).
        val ready = runtimePorts?.let { isArtiTrafficReady(it) } == true
        val bootPct = when {
            ready -> 100
            frac != null -> (frac * 100f).toInt().coerceIn(0, 99)
            arti.isRunning() && socksUp -> 50
            arti.isRunning() -> 25
            else -> 0
        }
        // connected=true = runtime healthy (UI bootstrap). Circuits stay 0 — no control plane.
        control.publishSyntheticStatus(
            TorControlStatus(
                connected = arti.isRunning() && socksUp,
                torVersion = buildString {
                    append(ArtiRuntime.VERSION_LABEL)
                    append(" (arti-client ")
                    append(ArtiRuntime.ARTI_CLIENT_VERSION)
                    if (arti.hasControlApi()) {
                        append("; control-api=")
                        append(ArtiControlNative.controlApiVersion())
                    }
                    append(')')
                },
                bootstrapProgress = bootPct,
                bootstrapTag = when {
                    ready -> "done"
                    artiDormant -> "dormant"
                    arti.isRunning() -> "starting"
                    else -> "off"
                },
                bootstrapSummary = when {
                    ready && arti.hasControlApi() -> {
                        val block = arti.bootstrapBlockageOrEmpty()
                        if (block.isNotEmpty()) {
                            "Arti blocked: $block"
                        } else {
                            "Arti ready_for_traffic (bootstrap as_frac=${frac ?: 1f})"
                        }
                    }
                    ready -> "Arti SOCKS/DNS ready (ready_for_traffic)"
                    artiDormant && arti.hasControlApi() ->
                        "Arti dormant (TorClient::set_dormant Soft)"
                    artiDormant -> "Arti dormant (synthetic Soft)"
                    arti.isRunning() -> {
                        val block = arti.bootstrapBlockageOrEmpty()
                        when {
                            block.isNotEmpty() -> "Arti blocked: $block"
                            socksUp -> "Waiting for Arti bootstrap"
                            else -> "Waiting for Arti listeners"
                        }
                    }
                    else -> "Arti stopped"
                },
                circuitEstablished = ready,
                enoughDirInfo = ready,
                networkLive = ready,
                dormant = artiDormant,
                builtCircuits = 0,
                streamCount = 0,
            ),
        )
    }

    // --- private pipeline steps ---

    /** Step 3: spawn libtor.so -f torrc. */
    private fun spawnTorProcess() {
        val command = listOf(binaryFile.absolutePath, "-f", torrcFile.absolutePath)
        process = ProcessBuilder(command)
            .directory(configDirectory)
            .redirectErrorStream(true)
            .start()
        startLogPump(process!!)
    }

    /** Step 2: write torrc from current preferences + ports. */
    private fun writeTorrc(ports: TunnelRuntimePorts) {
        torrcFile.writeText(
            TorConfigWriter.write(
                dataDirectory = configDirectory.absolutePath,
                socksPort = ports.torSocksPort,
                dnsCryptSocksPort = ports.torDnsCryptSocksPort,
                probeSocksPort = ports.torProbeSocksPort,
                httpTunnelPort = ports.torHttpTunnelPort,
                dnsPort = ports.torDnsPort,
                preferences = preferences,
                nativeLibraryDir = nativeLibraryDir.absolutePath,
            ),
        )
        if (TorBridgeConfig.isConfigured(preferences.torBridges)) {
            val transports = TorBridgeConfig.requiredTransports(preferences.torBridges)
            Timber.i(
                "Tor bridges enabled transports=%s lines=%d",
                transports.ifEmpty { setOf("vanilla") },
                TorBridgeConfig.parseLines(preferences.torBridges).size,
            )
        }
    }

    /**
     * Switching default→bridges with a warm DataDirectory reuses enough_dirinfo from clearnet
     * bootstrap, then sticks at ap_handshake against dead ORPorts. Drop entry/guard caches so
     * directory fetches happen through the configured PTs.
     */
    private fun prepareDataDirectoryForBridges(bridgeText: String) {
        if (!TorBridgeConfig.isConfigured(bridgeText)) return
        val doomed = buildList {
            add("state")
            add("unparseable-desc")
            configDirectory.listFiles()?.forEach { file ->
                val n = file.name
                if (n.startsWith("cached-microdesc") ||
                    n.startsWith("cached-descriptor") ||
                    n.startsWith("cached-consensus") ||
                    n.startsWith("cached-certs") ||
                    n == "diff-cache"
                ) {
                    add(n)
                }
            }
        }
        var removed = 0
        doomed.forEach { name ->
            val f = File(configDirectory, name)
            when {
                f.isFile && f.delete() -> removed++
                f.isDirectory && f.deleteRecursively() -> removed++
            }
        }
        Timber.i("Cleared Tor bridge bootstrap caches files=%d", removed)
    }

    /** Make PT .so files executable for transports required by current bridges. */
    private fun ensurePluggableTransportBinaries(bridgeText: String) {
        if (!TorBridgeConfig.isConfigured(bridgeText)) return
        // Resolve + chmod every binary referenced by the CTP block we will write.
        TorBridgeConfig.clientTransportPluginLines(bridgeText, nativeLibraryDir).forEach { line ->
            val path = line.substringAfter(" exec ").substringBefore(" -").trim()
            if (path.isNotEmpty()) {
                ensureExecutable(File(path))
            }
        }
        TorBridgeConfig.requiredTransports(bridgeText).forEach { transport ->
            val bin = TorBridgeConfig.binaryForTransport(transport, nativeLibraryDir)
                ?: throw TunnelFailure.TorBinary(
                    "Pluggable transport binary missing for '$transport' " +
                        "(expected under ${nativeLibraryDir.absolutePath})",
                )
            Timber.i("PT ready transport=%s bin=%s", transport, bin.name)
        }
    }

    /** Step 4: wait until ControlSocket + cookie exist. */
    private suspend fun waitForControlPlane(timeoutMs: Long = 60_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive != true) {
                throw TunnelFailure.TorBinary("Tor process exited before control socket appeared")
            }
            if (controlSocketFile.exists() && cookieFile.exists() && cookieFile.length() > 0) {
                delay(150)
                return
            }
            delay(100)
        }
        val sock = controlSocketFile.exists()
        val cookie = cookieFile.exists() && cookieFile.length() > 0
        throw TunnelFailure.TorControl(
            "Tor control plane not ready (socket=$sock cookie=$cookie) after ${timeoutMs}ms",
        )
    }

    /**
     * Arti equivalent of [waitForBootstrap]: SOCKS accept is not enough for DNSCrypt.
     *
     * With Ext JNI: wait for `ready_for_traffic` (or as_frac ≥ 0.99), then DNSPort.
     * Stock AAR (no Ext): DNSPort answering is the bootstrap proxy (needs dir info).
     */
    private suspend fun waitForArtiBootstrap(
        ports: TunnelRuntimePorts,
        timeoutMs: Long = 240_000,
        pollMs: Long = 500,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastLogMs = 0L
        var dnsReady = false
        val hasExt = ArtiControlNative.isAvailable()
        while (System.currentTimeMillis() < deadline) {
            if (!arti.isRunning()) {
                throw TunnelFailure.TorBinary("Arti stopped before bootstrap completed")
            }
            publishArtiReadyStatus()
            val frac = arti.bootstrapFractionOrNull()
            val nativeReady = arti.readyForTrafficNative()
            val bootDone = when {
                nativeReady -> true
                frac != null && frac >= 0.99f -> true
                // No Ext API: cannot read BootstrapStatus — DNSPort reply ≈ enough dir info.
                !hasExt -> TorReadiness.isDnsPortReady(ports.torDnsPort, timeoutMs = 1_500)
                else -> false
            }
            if (bootDone) {
                // Probe DNSPort only after bootstrap (same rule as little-t waitForBootstrap).
                if (!dnsReady) {
                    dnsReady = TorReadiness.isDnsPortReady(ports.torDnsPort, timeoutMs = 2_000)
                }
                if (dnsReady) {
                    Timber.i(
                        "Arti bootstrap complete readyTraffic=%s frac=%s dnsPort=%d",
                        nativeReady,
                        frac,
                        ports.torDnsPort,
                    )
                    return
                }
            }
            val now = System.currentTimeMillis()
            if (now - lastLogMs >= 15_000L) {
                lastLogMs = now
                val block = arti.bootstrapBlockageOrEmpty()
                Timber.i(
                    "Arti waiting for ready_for_traffic (frac=%s ready=%s dns=%s block=%s elapsed=%ds)",
                    frac,
                    nativeReady,
                    dnsReady,
                    block.ifBlank { "-" },
                    (timeoutMs - (deadline - now)) / 1000,
                )
            }
            delay(pollMs)
        }
        val frac = arti.bootstrapFractionOrNull()
        val pct = when {
            frac != null -> (frac * 100f).toInt().coerceIn(0, 99)
            else -> control.status.value.bootstrapProgress
        }
        throw TunnelFailure.TorBootstrap(
            progress = pct,
            detail = "Arti bootstrap timed out at ~$pct% " +
                "(readyTraffic=${arti.readyForTrafficNative()} frac=$frac dnsReady=$dnsReady " +
                "socks=${ports.torSocksPort} dns=${ports.torDnsPort}" +
                arti.bootstrapBlockageOrEmpty().let { if (it.isNotEmpty()) " block=$it" else "" } +
                ") — DNSCrypt requires ready_for_traffic",
        )
    }

    /** Step 6: control bootstrap + local Socks/DNSPort readiness. */
    private suspend fun waitForBootstrap(
        ports: TunnelRuntimePorts,
        timeoutMs: Long = 180_000,
        pollMs: Long = 1_000,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        var socksReady = false
        var dnsReady = false
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive != true) {
                throw TunnelFailure.TorBinary("Tor process exited before bootstrap completed")
            }
            try {
                // Bootstrap-only GETINFO — avoids dormant/network-liveness 552 noise.
                control.refreshBootstrap()
                val st = control.status.value
                val bootDone = st.bootstrapProgress >= 100 ||
                    (st.circuitEstablished && st.enoughDirInfo)

                // SOCKS accepts early; probe often without treating failures as fatal.
                if (!socksReady) {
                    socksReady = TorReadiness.areSocksPortsReady(ports)
                }

                // DNSPort answers only after enough dir info — never probe before bootDone
                // (that caused 1.5–2s timeouts every few polls during bootstrap).
                if (bootDone && socksReady && !dnsReady) {
                    dnsReady = TorReadiness.isDnsPortReady(ports.torDnsPort)
                }

                if (bootDone && socksReady && dnsReady) {
                    Timber.i(
                        "Tor bootstrap complete progress=%d tag=%s",
                        st.bootstrapProgress,
                        st.bootstrapTag,
                    )
                    return
                }
                if (st.bootstrapSummary.isNotBlank()) {
                    Timber.d(
                        "Tor bootstrap %d%% %s — %s (socks=%s dns=%s)",
                        st.bootstrapProgress,
                        st.bootstrapTag,
                        st.bootstrapSummary,
                        socksReady,
                        dnsReady,
                    )
                }
            } catch (error: Exception) {
                lastError = error
                Timber.d(
                    error,
                    "Tor bootstrap poll: %s",
                    error.message ?: error.javaClass.simpleName,
                )
            }
            delay(pollMs)
        }
        val progress = control.status.value.bootstrapProgress
        val summary = control.status.value.bootstrapSummary.ifBlank { "no summary" }
        throw TunnelFailure.TorBootstrap(
            progress = progress,
            detail = "Tor bootstrap timed out at $progress% ($summary) " +
                "socks=$socksReady dns=$dnsReady",
            cause = lastError,
        )
    }

    private fun startLogPump(proc: Process) {
        logThread = Thread {
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        Timber.tag(LOG_TAG).d(line)
                        onLogLine?.invoke(line)
                    }
                }
            } catch (_: Exception) {
                // Process stopped.
            }
        }.apply {
            name = "tor-log"
            isDaemon = true
            start()
        }
    }

    private fun ensureExecutable(file: File) {
        if (!file.exists()) {
            throw TunnelFailure.TorBinary("Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            if (!file.setExecutable(true, false)) {
                throw TunnelFailure.TorBinary("Cannot set executable bit on ${file.absolutePath}")
            }
        }
    }

    /**
     * Seeds GeoIP so circuit UI can resolve relay countries (`ip-to-country`).
     *
     * Order: APK assets → optional clearnet mirrors (often blocked under kill-switch) →
     * Tor SOCKS when [socksPort] is set (preferred under Blocking TUN).
     */
    private fun ensureGeoIpFiles(socksPort: Int? = null) {
        seedGeoIpAsset(TorConfigWriter.GEOIP_FILE_NAME, GEOIP_URLS, minBytes = 100_000L, socksPort)
        seedGeoIpAsset(TorConfigWriter.GEOIP6_FILE_NAME, GEOIP6_URLS, minBytes = 50_000L, socksPort)
    }

    private fun geoIpFile(): File = File(configDirectory, TorConfigWriter.GEOIP_FILE_NAME)
    private fun geoIp6File(): File = File(configDirectory, TorConfigWriter.GEOIP6_FILE_NAME)

    private fun geoIpReady(): Boolean {
        val v4 = geoIpFile()
        val v6 = geoIp6File()
        return v4.isFile && v4.length() >= 100_000L && v6.isFile && v6.length() >= 50_000L
    }

    private fun applyGeoIpIfPresent() {
        if (!geoIpReady() || !control.isConnected) return
        control.setGeoIpFiles(geoIpFile().absolutePath, geoIp6File().absolutePath)
            .onSuccess {
                Timber.i(
                    "GeoIP applied live (ip-to-country/ipv4-available=%s)",
                    runCatching { control.getInfo("ip-to-country/ipv4-available") }.getOrNull()?.trim(),
                )
            }
            .onFailure { Timber.w(it, "SETCONF GeoIPFile failed") }
    }

    private fun seedGeoIpAsset(
        name: String,
        urls: List<String>,
        minBytes: Long,
        socksPort: Int?,
    ) {
        val dest = File(configDirectory, name)
        if (dest.isFile && dest.length() >= minBytes) return
        val fromAsset = runCatching {
            context.assets.open("tor/$name").use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            }
            dest.isFile && dest.length() >= minBytes
        }.getOrDefault(false)
        if (fromAsset) {
            Timber.i("GeoIP seeded from assets: %s (%d bytes)", name, dest.length())
            return
        }
        // Prefer Tor SOCKS under kill-switch. Skip clearnet: Blocking TUN blackholes it
        // and the old gitlab `main` URLs 404/403 anyway.
        if (socksPort == null) {
            Timber.d("GeoIP %s: waiting for Tor SOCKS (no assets / no clearnet)", name)
            return
        }
        for (url in urls) {
            val ok = downloadGeoIp(dest, url, minBytes, socksPort)
            if (ok) {
                Timber.i(
                    "GeoIP downloaded: %s (%d bytes) via socks:%d",
                    name,
                    dest.length(),
                    socksPort,
                )
                return
            }
        }
        Timber.w("GeoIP seed failed for %s — circuit flags may be empty", name)
    }

    private fun downloadGeoIp(
        dest: File,
        url: String,
        minBytes: Long,
        socksPort: Int?,
    ): Boolean {
        // Never clearnet DNS — VPN-excluded UID + Java SOCKS would resolve locally.
        // OkHttp + SOCKS5h + Authenticator (onionmasq/Arti reject empty SOCKS tokens).
        val port = socksPort ?: run {
            Timber.d("GeoIP download refused without Tor SOCKS")
            return false
        }
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(TunnelEndpoints.LOOPBACK, port))
        return SocksJavaProxyAuth.withProbe {
            runCatching {
                val client = OkHttpClient.Builder()
                    .proxy(proxy)
                    .dns(GeoIpTorSocksDns)
                    .connectTimeout(20, TimeUnit.SECONDS)
                    .readTimeout(180, TimeUnit.SECONDS)
                    .followRedirects(true)
                    .build()
                val request = Request.Builder()
                    .url(url)
                    .header("User-Agent", "OnionVPN/geoip")
                    .header("Accept", "text/plain,*/*")
                    .build()
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        error("HTTP ${response.code} for $url")
                    }
                    val body = response.body ?: error("empty body")
                    val tmp = File(configDirectory, "${dest.name}.part")
                    tmp.outputStream().use { output -> body.byteStream().copyTo(output) }
                    if (tmp.length() < minBytes) {
                        tmp.delete()
                        error("GeoIP download too small: ${tmp.length()}")
                    }
                    if (!tmp.renameTo(dest)) {
                        tmp.copyTo(dest, overwrite = true)
                        tmp.delete()
                    }
                }
                true
            }.onFailure {
                Timber.d(it, "GeoIP mirror failed %s", url)
            }.getOrDefault(false)
        }
    }

    private suspend fun stopInternal() {
        if (activeEngine == TorEngine.ARTI || arti.isRunning()) {
            // Await Stopped so a following Little-T/Arti start does not race AMEx state.
            arti.stopAndAwait()
            control.resetStatus()
        } else {
            runCatching { control.disconnect(sendShutdown = true) }
        }
        process?.destroyForcibly()
        runCatching { process?.waitFor() }
        process = null
        logThread?.interrupt()
        logThread = null
        if (!externalDataPlanePorts) {
            runtimePorts = null
        }
        runCatching { controlSocketFile.delete() }
        MemoryHygiene.afterHeavyWork("tor_stop")
    }

    private fun killOrphanedProcesses() {
        runCatching {
            val proc = Runtime.getRuntime()
                .exec(arrayOf("sh", "-c", "pkill -f ${binaryFile.name} 2>/dev/null || true"))
            try {
                // Drain pipes so the helper cannot fill buffers and hang; close FDs.
                proc.inputStream.use { it.readBytes() }
                proc.errorStream.use { it.readBytes() }
                proc.waitFor()
            } finally {
                proc.destroyForcibly()
            }
        }
    }

    companion object {
        const val LOG_TAG = "tor"

        /** Match C Tor [TorControlOperations.NEWNYM_MIN_INTERVAL_MS] (~10.5s). */
        private const val ARTI_NEWNYM_MIN_INTERVAL_MS = 10_500L
        /** Brief maintenance hold after SIGNAL NEWNYM while circuits rebuild. */
        private const val NEWNYM_SETTLE_MS = 2_500L
        /** After DisableNetwork=0, wait for SocksPort to accept before unpausing bridges. */
        private const val SOCKS_AFTER_DISABLE_NETWORK_MS = 300L

        /**
         * SOCKS5h: unresolved host so Tor resolves the name (no local clearnet DNS).
         * Same pattern as TorSocksDns / ExitIpValidator.
         */
        private object GeoIpTorSocksDns : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByAddress(hostname, byteArrayOf(0, 0, 0, 0)))
        }

        /**
         * Official metrics geoip-data (kept current) + Tor release-branch fallback.
         * `main/src/config/geoip` was removed / blocked on GitLab — do not use it.
         */
        private val GEOIP_URLS = listOf(
            "https://tpo.pages.torproject.net/network-health/metrics/geoip-data/geoip",
            "https://gitlab.torproject.org/tpo/core/tor/-/raw/release-0.4.8/src/config/geoip",
        )
        private val GEOIP6_URLS = listOf(
            "https://tpo.pages.torproject.net/network-health/metrics/geoip-data/geoip6",
            "https://gitlab.torproject.org/tpo/core/tor/-/raw/release-0.4.8/src/config/geoip6",
        )
    }
}
