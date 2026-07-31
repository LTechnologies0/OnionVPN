package ltechnologies.onionphone.onionvpn.core.tor

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
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
 * **Arti start pipeline:** stop → JNI start → wait SOCKS/DNS listeners → synthetic status.
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
    private var preferences: TunnelPreferences = TunnelPreferences()
    private var activeEngine: TorEngine = TorEngine.LITTLE_T
    private val arti = ArtiRuntime(context)

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
     */
    var onClientDnsCacheClear: (() -> Unit)? = null

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
        this@TorProcessManager.preferences = preferences
        activeEngine = preferences.torEngine
        when (activeEngine) {
            TorEngine.ARTI -> startArti(ports, preferences)
            TorEngine.LITTLE_T -> startLittleT(ports, preferences)
        }
    }

    private suspend fun startArti(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ): Result<Unit> {
        stopInternal()
        runtimePorts = ports
        return try {
            arti.start(ports, preferences)
            publishArtiReadyStatus()
            Timber.i(
                "Arti ready socks=%d dns=%d (shared SOCKS for apps/dnscrypt/probe)",
                ports.torSocksPort,
                ports.torDnsPort,
            )
            Result.success(Unit)
        } catch (error: Exception) {
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
        // Step 1 — stopInternal clears runtimePorts; re-bind after teardown.
        stopInternal()
        killOrphanedProcesses()
        runCatching { controlSocketFile.delete() }
        runCatching { cookieFile.delete() }
        runtimePorts = ports
        return try {
            ensureExecutable(binaryFile)
            ensurePluggableTransportBinaries(preferences.torBridges)
            ensureGeoIpFiles()
            prepareDataDirectoryForBridges(preferences.torBridges)
            // Step 2
            writeTorrc(ports)
            // Step 3
            spawnTorProcess()
            // Step 4
            waitForControlPlane()
            // Step 5
            control.connect(
                controlSocketPath = controlSocketFile,
                cookieFile = cookieFile,
                bridgesConfigured = TorBridgeConfig.isConfigured(preferences.torBridges),
            )
            // Step 6
            waitForBootstrap(ports)
            // Step 7 — GeoIP over Tor SOCKS (clearnet is blackholed under kill-switch Blocking).
            ensureGeoIpFiles(socksPort = ports.torSocksPort)
            applyGeoIpIfPresent()
            // Step 8
            control.setActive()
            Timber.i(
                "Tor ready socks=${ports.torSocksPort} " +
                    "control=ok bootstrap=${control.status.value.bootstrapProgress}% " +
                    "circuits=${control.status.value.builtCircuits}",
            )
            Result.success(Unit)
        } catch (error: Exception) {
            Timber.e(error, "Tor failed to start")
            stopInternal()
            runtimePorts = null
            Result.failure(TunnelFailure.fromThrowable(error, context = "tor.start"))
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        stopInternal()
    }

    fun isRunning(): Boolean = when (activeEngine) {
        TorEngine.ARTI -> arti.isRunning()
        TorEngine.LITTLE_T -> process?.isAlive == true
    }

    /** Probe SocksPort while Tor is up; used for reputation list downloads. */
    fun currentProbeSocksPort(): Int? =
        runtimePorts?.torProbeSocksPort?.takeIf { isRunning() }

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
                    arti.restartForNewIdentity()
                    clearAppDnsCaches()
                    publishArtiReadyStatus()
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
                control.newNym().also {
                    it.onSuccess { Timber.i("SIGNAL NEWNYM accepted") }
                    it.onFailure { e -> Timber.w(e, "NEWNYM failed") }
                }
            }
        }
    }

    /** SIGNAL ACTIVE — Arti: no-op OK (listeners stay up). */
    fun signalActive(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            publishArtiReadyStatus()
            return Result.success(Unit)
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setActive().also {
            it.onSuccess { Timber.i("SIGNAL ACTIVE") }
            it.onFailure { e -> Timber.w(e, "ACTIVE failed") }
        }
    }

    /** SIGNAL DORMANT — Arti: no-op OK (keep runtime under Blocking TUN). */
    fun signalDormant(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            Timber.i("Arti DORMANT no-op (runtime kept under Blocking)")
            return Result.success(Unit)
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setDormant()
    }

    /** SIGNAL CLEARDNSCACHE — Arti: clear app Automap/DNS caches + soft re-probe. */
    fun clearDnsCache(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) {
            clearAppDnsCaches()
            return onNetworkChanged()
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.clearDnsCache()
    }

    /** DROPTIMEOUTS — Arti: soft recovery. */
    fun dropTimeouts(): Result<Unit> {
        if (activeEngine == TorEngine.ARTI) return onNetworkChanged()
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.dropTimeouts()
    }

    /** DROPGUARDS — Arti: hard restart (clears client state). */
    suspend fun dropGuards(): Result<Unit> = withContext(Dispatchers.IO) {
        if (activeEngine == TorEngine.ARTI) return@withContext recoverNetworkHard()
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
     * Arti: prefs updated for next C Tor switch; arti-mobile JNI cannot set
     * circuit_timing.max_dirtiness — documented ENGINE_LIMITATION / NOOP_OK.
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
            Timber.i(
                "Arti circuit timing stored only (dirt=%ds period=%ds) — " +
                    "arti-mobile JNI has no circuit_timing knob",
                maxCircuitDirtinessSec,
                newCircuitPeriodSec,
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
            publishArtiReadyStatus()
            val ok = runtimePorts?.let { TorReadiness.areSocksPortsReady(it) } == true
            Timber.i("Arti network change soft recovery socksReady=%s", ok)
            return if (ok) Result.success(Unit) else Result.failure(IOException("Arti SOCKS not ready"))
        }
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        control.dropTimeouts().onFailure { Timber.w(it, "DROPTIMEOUTS failed") }
        val active = control.setActive()
        control.clearDnsCache().onFailure { Timber.w(it, "CLEARDNSCACHE failed") }
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
                    arti.restartHard()
                    clearAppDnsCaches()
                    publishArtiReadyStatus()
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
                control.dropTimeouts().onFailure { Timber.w(it, "DROPTIMEOUTS failed") }
                control.setDisableNetwork(true).onFailure { Timber.w(it, "DisableNetwork=1 failed") }
                control.setDisableNetwork(false).onFailure { Timber.w(it, "DisableNetwork=0 failed") }
                val active = control.setActive()
                control.clearDnsCache().onFailure { Timber.w(it, "CLEARDNSCACHE failed") }
                control.refreshHealthLite()
                active.also {
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
                arti.restartWithPreferences(preferences)
                clearAppDnsCaches()
                publishArtiReadyStatus()
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
     * Arti: ENGINE_LIMITATION — not in arti-mobile JNI (fail closed).
     */
    fun setNodePrefsLive(entry: String, exit: String, exclude: String): Result<Unit> {
        preferences = preferences.copy(
            torEntryNodes = entry,
            torExitNodes = exit,
            torExcludeNodes = exclude,
        )
        if (activeEngine == TorEngine.ARTI) {
            return Result.failure(
                IOException(TorControlCompat.unsupportedMessage("SETCONF_nodes")),
            )
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
     * control-spec RESOLVE — Arti: DNS A query via DNSPort (app-layer 1:1).
     */
    suspend fun resolveHostname(hostname: String, timeoutMs: Long = 15_000): Result<String> =
        withContext(Dispatchers.IO) {
            when (activeEngine) {
                TorEngine.ARTI -> {
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
        if (activeEngine == TorEngine.ARTI) return@withContext recoverNetworkHard()
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

    private fun publishArtiReadyStatus() {
        val socksUp = runtimePorts?.let { TorReadiness.areSocksPortsReady(it) } == true
        val ready = socksUp && arti.isRunning()
        // connected=true = runtime healthy (UI bootstrap). Circuits stay 0 — no control plane.
        control.publishSyntheticStatus(
            TorControlStatus(
                connected = ready,
                torVersion = ArtiRuntime.VERSION_LABEL,
                bootstrapProgress = if (ready) 100 else 0,
                bootstrapTag = if (ready) "done" else "starting",
                bootstrapSummary = if (ready) {
                    "Arti SOCKS/DNS listeners ready"
                } else {
                    "Waiting for Arti listeners"
                },
                circuitEstablished = ready,
                enoughDirInfo = ready,
                networkLive = ready,
                dormant = false,
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
    ): Boolean = runCatching {
        // Never clearnet DNS — VPN-excluded UID + Java SOCKS would resolve locally.
        // OkHttp + SOCKS5h placeholder Dns (same as ExitIpValidator / TorSocksDns).
        val port = socksPort ?: error("GeoIP download refused without Tor SOCKS")
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(TunnelEndpoints.LOOPBACK, port))
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

    private fun stopInternal() {
        if (activeEngine == TorEngine.ARTI || arti.isRunning()) {
            arti.stop()
            control.resetStatus()
        } else {
            runCatching { control.disconnect(sendShutdown = true) }
        }
        process?.destroyForcibly()
        runCatching { process?.waitFor() }
        process = null
        logThread?.interrupt()
        logThread = null
        runtimePorts = null
        runCatching { controlSocketFile.delete() }
    }

    private fun killOrphanedProcesses() {
        runCatching {
            Runtime.getRuntime()
                .exec(arrayOf("sh", "-c", "pkill -f ${binaryFile.name} 2>/dev/null || true"))
                .waitFor()
        }
    }

    companion object {
        const val LOG_TAG = "tor"

        /** Match C Tor [TorControlOperations.NEWNYM_MIN_INTERVAL_MS] (~10.5s). */
        private const val ARTI_NEWNYM_MIN_INTERVAL_MS = 10_500L

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
