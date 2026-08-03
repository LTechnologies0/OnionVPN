package ltechnologies.onionphone.onionvpn.core.tor.arti

import android.content.Context
import java.io.File
import java.io.IOException
import kotlinx.coroutines.delay
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.tor.config.TorBridgeConfig
import ltechnologies.onionphone.onionvpn.core.tor.lifecycle.TorReadiness
import org.torproject.arti.ArtiControlNative
import org.torproject.arti.ArtiMobileNative
import timber.log.Timber

/**
 * In-process Arti (Rust) proxy via Guardian Project `arti-mobile`.
 *
 * Unlike little-t Tor, Arti is not a separate `Process` — JNI starts a runtime thread
 * that binds one SOCKS + one DNS listener. There is no classic ControlSocket.
 *
 * Writes [statusFile] for runtime validation (parity with C Tor torrc checks).
 */
internal class ArtiRuntime(
    private val context: Context,
) {
    @Volatile
    private var running: Boolean = false

    private var lastPorts: TunnelRuntimePorts? = null
    private var lastPreferences: TunnelPreferences? = null

    val cacheDirectory: File
        get() = File(context.cacheDir, "arti_cache").also { it.mkdirs() }

    val stateDirectory: File
        get() = File(context.filesDir, "arti_state").also { it.mkdirs() }

    /** Runtime status file — validated instead of torrc when engine is Arti. */
    val statusFile: File
        get() = File(stateDirectory, STATUS_FILE_NAME)

    val nativeLibraryDir: File
        get() = File(context.applicationInfo.nativeLibraryDir)

    var onLogLine: ((String) -> Unit)? = null

    private val logBuffer = ArtiLogLineBuffer { line ->
        // TOR tab only — avoid duplicating ANSI/chunks into APP via Timber.tag("arti").
        onLogLine?.invoke(line)
    }

    fun isRunning(): Boolean = running

    /**
     * Starts Arti SOCKS+DNS on [ports], waits until the primary SOCKS listener accepts.
     *
     * Does **not** wait for `ready_for_traffic` / directory bootstrap — callers that
     * start DNSCrypt (TorProcessManager.startArti) must wait for that separately.
     * SOCKS binds before consensus; DNSPort answers only after enough dir info.
     *
     * Bridge lines (when set) are passed to Arti with managed Lyrebird and/or Conjure
     * PT paths written under state_dir for native TransportConfig.
     */
    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ) {
        OpTrace.stepSuspending("arti", "stop_and_await") { stopAndAwait() }
        lastPorts = ports
        lastPreferences = preferences
        writeCircuitTimingPref(
            preferences.torMaxCircuitDirtinessSec,
            preferences.torNewCircuitPeriodSec,
        )
        writePathPrefs(preferences.torExitNodes)
        writePtPlugins(preferences.torBridges)
        writeStatus(
            ports,
            preferences,
            ready = false,
            dirtinessApplied = false,
            predictionLifetimeApplied = artiPredictionLifetimeSec(preferences.torNewCircuitPeriodSec),
        )

        val bridges = TorBridgeConfig.parseLines(preferences.torBridges)
        val bridgeText = bridges.joinToString("\n").ifBlank { null }
        val ptPath = resolveManagedPtPath(preferences.torBridges)

        if (bridges.isNotEmpty() && ptPath == null && !hasConjureOnly(preferences.torBridges)) {
            val transports = TorBridgeConfig.requiredTransports(preferences.torBridges)
            throw TunnelFailure.TorBinary(
                "Arti bridges need a managed PT binary (Lyrebird/obfs4proxy/Conjure) for $transports",
            )
        }

        OpTrace.info(
            "arti",
            "Starting socks=${ports.torSocksPort} dns=${ports.torDnsPort} " +
                "bridges=${bridges.size} pt=${ptPath?.name ?: "none"}",
        )
        Timber.i(
            "Starting Arti socks=%d dns=%d bridges=%d pt=%s",
            ports.torSocksPort,
            ports.torDnsPort,
            bridges.size,
            ptPath?.name ?: "none",
        )

        var result = try {
            OpTrace.step("arti", "jni_start", ProcessLogLevel.INFO) {
                invokeNativeStart(ports, bridgeText, ptPath)
            }
        } catch (error: Exception) {
            running = false
            writeStatus(ports, preferences, ready = false, error = error.message)
            throw error
        }
        if (isWrongStateError(result)) {
            OpTrace.warn("arti", "still stopping — waiting then retrying start")
            awaitNativeIdle(previousSocksPort = null)
            result = try {
                OpTrace.step("arti", "jni_start_retry", ProcessLogLevel.INFO) {
                    invokeNativeStart(ports, bridgeText, ptPath)
                }
            } catch (error: Exception) {
                running = false
                writeStatus(ports, preferences, ready = false, error = error.message)
                throw error
            }
        }

        if (result.startsWith("Error:", ignoreCase = true)) {
            running = false
            writeStatus(ports, preferences, ready = false, error = result)
            throw TunnelFailure.TorBinary("Arti start error: $result")
        }

        running = true
        OpTrace.stepSuspending("arti", "wait_listeners", ProcessLogLevel.INFO) {
            waitForListeners(ports)
        }
        // Patched libarti_mobile_ex.so: timing/path prefs applied at TorClientConfig build +
        // live reconfigure after client handle is published. Stock AAR: record-only.
        val controlApi = ArtiControlNative.isAvailable()
        val pred = artiPredictionLifetimeSec(preferences.torNewCircuitPeriodSec)
        val liveApplied = controlApi &&
            ArtiControlNative.applyCircuitTiming(
                preferences.torMaxCircuitDirtinessSec.coerceIn(60, 7_200),
                pred,
            )
        if (controlApi) {
            applyExitCountryLive(preferences.torExitNodes)
        }
        writeStatus(
            ports,
            preferences,
            ready = true,
            dirtinessApplied = controlApi,
            predictionLifetimeApplied = pred,
        )
        OpTrace.info(
            "arti",
            "listeners ready socks=${ports.torSocksPort} dns=${ports.torDnsPort} " +
                "controlApi=$controlApi liveDirt=$liveApplied",
        )
        Timber.i(
            "Arti listeners ready socks=%d dns=%d controlApi=%s liveDirt=%s",
            ports.torSocksPort,
            ports.torDnsPort,
            controlApi,
            liveApplied,
        )
    }

    /**
     * Persist MaxCircuitDirtiness + Arti preemptive prediction_lifetime for native start.
     * [predictionLifetimeSec] is the UI/C-Tor NewCircuitPeriod; Arti gets a floored value.
     */
    fun writeCircuitTimingPref(maxDirtinessSec: Int, predictionLifetimeSec: Int = maxDirtinessSec) {
        val dirt = maxDirtinessSec.coerceIn(60, 7_200)
        val pred = artiPredictionLifetimeSec(predictionLifetimeSec)
        val f = File(stateDirectory, TIMING_FILE_NAME)
        runCatching {
            f.writeText("max_dirtiness_sec=$dirt\nprediction_lifetime_sec=$pred\n")
        }.onFailure { Timber.w(it, "Failed to write Arti circuit timing pref") }
    }

    /** Persist ExitNodes country for SOCKS StreamPrefs::exit_country. */
    fun writePathPrefs(exitNodesRaw: String) {
        val cc = singleExitCountryOrNull(exitNodesRaw).orEmpty()
        val f = File(stateDirectory, PATH_PREFS_FILE_NAME)
        runCatching { f.writeText("exit_country=$cc\n") }
            .onFailure { Timber.w(it, "Failed to write Arti path prefs") }
    }

    /** Persist Conjure PT path + register URL for native TransportConfig. */
    fun writePtPlugins(bridgeText: String) {
        val f = File(stateDirectory, PT_PLUGINS_FILE_NAME)
        val needed = TorBridgeConfig.requiredTransports(bridgeText)
        if ("conjure" !in needed) {
            runCatching { f.delete() }
            return
        }
        val conjure = TorBridgeConfig.binaryForTransport("conjure", nativeLibraryDir)
            ?: return
        if (!conjure.canExecute()) {
            conjure.setExecutable(true, false)
        }
        runCatching {
            f.writeText(
                buildString {
                    appendLine("conjure_path=${conjure.absolutePath}")
                    appendLine("conjure_register_url=${TorBridgeConfig.CONJURE_REGISTER_URL}")
                },
            )
        }.onFailure { Timber.w(it, "Failed to write Arti PT plugins pref") }
    }

    /**
     * Live max_dirtiness + prediction_lifetime via Ext JNI reconfigure.
     * Returns false when Ext API absent (stock AAR) — caller should treat as record-only.
     */
    fun applyCircuitTimingLive(maxDirtinessSec: Int, predictionLifetimeSec: Int): Boolean {
        val dirt = maxDirtinessSec.coerceIn(60, 7_200)
        // Do NOT map C Tor NewCircuitPeriod → Arti prediction_lifetime 1:1.
        // Arti's default is ~1h (how long to keep preemptive circuits for a port).
        // Feeding 30–180s thrashs preemptive builds and feels like a bandwidth cap.
        // Floor at Arti default; still honor larger UI values.
        val pred = artiPredictionLifetimeSec(predictionLifetimeSec)
        writeCircuitTimingPref(dirt, predictionLifetimeSec)
        lastPreferences = (lastPreferences ?: TunnelPreferences()).copy(
            torMaxCircuitDirtinessSec = dirt,
            // Persist the C Tor NewCircuitPeriod the UI asked for; Arti uses [pred] separately.
            torNewCircuitPeriodSec = predictionLifetimeSec.coerceIn(10, 86_400),
        )
        if (!ArtiControlNative.isAvailable()) return false
        val ok = ArtiControlNative.applyCircuitTiming(dirt, pred)
        lastPorts?.let { ports ->
            writeStatus(
                ports,
                lastPreferences ?: TunnelPreferences(),
                ready = running,
                dirtinessApplied = ok,
                predictionLifetimeApplied = pred,
            )
        }
        return ok
    }

    /** @deprecated Prefer [applyCircuitTimingLive]. */
    fun applyMaxDirtinessLive(maxDirtinessSec: Int): Boolean {
        val period = lastPreferences?.torNewCircuitPeriodSec ?: maxDirtinessSec
        return applyCircuitTimingLive(maxDirtinessSec, period)
    }

    /**
     * Apply ExitNodes as a single ISO country for SOCKS streams.
     * Multi-country lists are rejected (arti-client StreamPrefs supports one country).
     */
    fun applyExitCountryLive(exitNodesRaw: String): Boolean {
        writePathPrefs(exitNodesRaw)
        lastPreferences = (lastPreferences ?: TunnelPreferences()).copy(torExitNodes = exitNodesRaw)
        if (ArtiControlNative.controlApiVersion() < 2) return false
        val codes = parseCountryCodes(exitNodesRaw)
        return when {
            codes.isEmpty() -> ArtiControlNative.applyExitCountry("")
            codes.size == 1 -> ArtiControlNative.applyExitCountry(codes.first())
            else -> {
                Timber.w("Arti ExitNodes supports a single country; got %s", codes)
                false
            }
        }
    }

    fun setDormantNative(soft: Boolean): Boolean =
        ArtiControlNative.isAvailable() && ArtiControlNative.setDormant(soft)

    fun bootstrapFractionOrNull(): Float? = ArtiControlNative.bootstrapFraction()

    fun readyForTrafficNative(): Boolean =
        ArtiControlNative.isAvailable() && ArtiControlNative.readyForTraffic()

    fun bootstrapBlockageOrEmpty(): String = ArtiControlNative.bootstrapBlockage()

    fun resolveHostnameNative(hostname: String): String? =
        ArtiControlNative.resolveHostname(hostname)

    fun hasControlApi(): Boolean = ArtiControlNative.isAvailable()

    fun controlApiVersion(): Int = ArtiControlNative.controlApiVersion()

    /**
     * New-identity equivalent: stop + start Arti on the same ports (drops all circuits).
     * Parity with C Tor SIGNAL NEWNYM for a full-device VPN client.
     */
    suspend fun restartForNewIdentity() {
        val ports = lastPorts ?: throw IOException("Arti has no runtime ports for NEWNYM")
        val prefs = lastPreferences ?: TunnelPreferences()
        Timber.i("Arti new-identity: restarting runtime socks=%d", ports.torSocksPort)
        start(ports, prefs)
    }

    /** Hard network recovery: full Arti restart (no DisableNetwork equivalent). */
    suspend fun restartHard() {
        val ports = lastPorts ?: throw IOException("Arti has no runtime ports for hard recovery")
        val prefs = lastPreferences ?: TunnelPreferences()
        Timber.w("Arti hard recovery: restarting runtime")
        start(ports, prefs)
    }

    /**
     * Apply new preferences (bridges / timing stored for status) and restart.
     * Bridges are re-passed to JNI — the arti-mobile equivalent of live SETCONF Bridge.
     */
    suspend fun restartWithPreferences(preferences: TunnelPreferences) {
        val ports = lastPorts ?: throw IOException("Arti has no runtime ports for reconfigure")
        Timber.i("Arti reconfigure+restart bridges=%d", TorBridgeConfig.parseLines(preferences.torBridges).size)
        start(ports, preferences)
    }

    fun currentPreferences(): TunnelPreferences? = lastPreferences

    fun currentPorts(): TunnelRuntimePorts? = lastPorts

    fun stop() {
        signalNativeStop()
    }

    /**
     * Signal Arti to stop and wait until the previous SOCKS listener is gone (or timeout).
     * Required before [start] — native AMEx rejects start while state is `Stopping`.
     */
    suspend fun stopAndAwait(timeoutMs: Long = STOP_AWAIT_TIMEOUT_MS) {
        val previousSocks = lastPorts?.torSocksPort
        signalNativeStop()
        awaitNativeIdle(previousSocksPort = previousSocks, timeoutMs = timeoutMs)
        logBuffer.flush()
    }

    private fun signalNativeStop() {
        runCatching { ArtiMobileNative.stop() }
            .onFailure { Timber.w(it, "Arti stop failed") }
        running = false
        runCatching { statusFile.delete() }
    }

    private suspend fun awaitNativeIdle(
        previousSocksPort: Int?,
        timeoutMs: Long = STOP_AWAIT_TIMEOUT_MS,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        if (previousSocksPort != null && previousSocksPort > 0) {
            while (System.currentTimeMillis() < deadline) {
                if (!TorReadiness.isSocksReady(previousSocksPort, timeoutMs = 150)) {
                    // Native poll loop is 200ms; brief grace for Stopping → Stopped.
                    delay(250)
                    return
                }
                delay(100)
            }
            Timber.w("Arti SOCKS :%d still accepting after stop wait", previousSocksPort)
            return
        }
        delay(400)
    }

    private fun invokeNativeStart(
        ports: TunnelRuntimePorts,
        bridgeText: String?,
        ptPath: File?,
    ): String = try {
        ArtiMobileNative.start(
            cacheDir = cacheDirectory.absolutePath,
            stateDir = stateDirectory.absolutePath,
            obfs4Port = 0,
            snowflakePort = 0,
            obfs4proxyPath = ptPath?.absolutePath,
            bridgeLines = bridgeText,
            socksPort = ports.torSocksPort,
            dnsPort = ports.torDnsPort,
            logListener = { chunk -> logBuffer.accept(chunk) },
        )
    } catch (error: Throwable) {
        running = false
        throw TunnelFailure.TorBinary(
            "Arti JNI start failed: ${error.message ?: error.javaClass.simpleName}",
            error,
        )
    }

    private fun isWrongStateError(result: String): Boolean =
        result.startsWith("Error:", ignoreCase = true) &&
            result.contains("wrong state", ignoreCase = true)

    private fun writeStatus(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
        ready: Boolean,
        error: String? = null,
        dirtinessApplied: Boolean = false,
        predictionLifetimeApplied: Int = artiPredictionLifetimeSec(preferences.torNewCircuitPeriodSec),
    ) {
        val bridges = TorBridgeConfig.parseLines(preferences.torBridges).size
        val pt = runCatching {
            resolveManagedPtPath(preferences.torBridges)?.name
        }.getOrNull().orEmpty()
        val dirt = preferences.torMaxCircuitDirtinessSec.coerceIn(60, 7_200)
        val newCirc = preferences.torNewCircuitPeriodSec.coerceIn(10, 86_400)
        val controlApi = ArtiControlNative.controlApiVersion()
        val exitCc = singleExitCountryOrNull(preferences.torExitNodes).orEmpty()
        val text = buildString {
            appendLine("engine=arti")
            appendLine("version=$VERSION_LABEL")
            // Embedded crate (libarti_mobile_ex.so) — docs: docs.rs/arti-client/0.36.0
            appendLine("arti_client=$ARTI_CLIENT_VERSION")
            appendLine("control_api=$controlApi")
            appendLine("ready=${if (ready) 1 else 0}")
            appendLine("socks=${ports.torSocksPort}")
            appendLine("dns=${ports.torDnsPort}")
            appendLine("shared_socks=1")
            appendLine("socks_auth_isolation=1")
            appendLine("bridges=$bridges")
            appendLine("pt=$pt")
            appendLine("synthesize_onion_automap=1")
            appendLine("max_dirtiness_sec=$dirt")
            appendLine("prediction_lifetime_sec=$predictionLifetimeApplied")
            appendLine("new_circuit_period_sec=$newCirc")
            appendLine("max_dirtiness_applied=${if (dirtinessApplied) 1 else 0}")
            appendLine("exit_country=$exitCc")
            if (error != null) appendLine("error=${error.replace('\n', ' ')}")
        }
        runCatching { statusFile.writeText(text) }
            .onFailure { Timber.w(it, "Failed to write Arti status file") }
    }

    private fun resolveManagedPtPath(bridgeText: String): File? {
        if (!TorBridgeConfig.isConfigured(bridgeText)) return null
        val needed = TorBridgeConfig.requiredTransports(bridgeText)
        if (needed.isEmpty()) return null
        // Conjure is registered via onionvpn_pt_plugins; Lyrebird path still passed to JNI.
        val lyrebirdNeeded = needed - setOf("conjure")
        if (lyrebirdNeeded.isEmpty()) return null
        val path = lyrebirdNeeded
            .asSequence()
            .mapNotNull { TorBridgeConfig.binaryForTransport(it, nativeLibraryDir) }
            .firstOrNull()
            ?: return null
        if (!path.canExecute()) {
            path.setExecutable(true, false)
        }
        return path
    }

    private fun hasConjureOnly(bridgeText: String): Boolean {
        val needed = TorBridgeConfig.requiredTransports(bridgeText)
        return needed.isNotEmpty() && needed.all { it == "conjure" } &&
            TorBridgeConfig.binaryForTransport("conjure", nativeLibraryDir) != null
    }

    /**
     * Wait until Arti SOCKS accepts TCP.
     *
     * DNSPort must NOT be required here: Arti resolves via Tor (needs bootstrap), so a
     * full DNS query probe would hang for minutes under OnDemand bootstrap — same failure
     * mode as TorReadiness docs ("never require a successful DNS reply before bootstrap").
     * SOCKS binds as soon as the proxy task starts (create_unbootstrapped + run_proxy).
     */
    private suspend fun waitForListeners(
        ports: TunnelRuntimePorts,
        timeoutMs: Long = 180_000,
        pollMs: Long = 500,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        var lastLogMs = 0L
        while (System.currentTimeMillis() < deadline) {
            if (!running) {
                throw TunnelFailure.TorBinary("Arti stopped before listeners became ready")
            }
            try {
                // Only the native Arti SOCKS port exists here. DNSCrypt/probe ports are
                // opened later by ArtiSocksRoleMux (after tor.start returns) — requiring
                // areSocksPortsReady() deadlocks forever (seen as 180s timeout while Arti
                // already logs "Listening on 127.0.0.1:<socks>").
                if (TorReadiness.isPrimarySocksReady(ports)) {
                    Timber.i(
                        "Arti SOCKS ready :%d (DNSPort :%d answers after bootstrap; " +
                            "role mux ports after start)",
                        ports.torSocksPort,
                        ports.torDnsPort,
                    )
                    return
                }
            } catch (error: Exception) {
                lastError = error
            }
            val now = System.currentTimeMillis()
            if (now - lastLogMs >= 15_000L) {
                lastLogMs = now
                Timber.i(
                    "Arti waiting for SOCKS :%d (elapsed %ds)",
                    ports.torSocksPort,
                    (timeoutMs - (deadline - now)) / 1000,
                )
            }
            delay(pollMs)
        }
        throw TunnelFailure.TorBootstrap(
            progress = 0,
            detail = "Arti SOCKS listener not ready after ${timeoutMs}ms " +
                "(socks=${ports.torSocksPort} dns=${ports.torDnsPort})",
            cause = lastError ?: IOException("timeout"),
        )
    }

    companion object {
        const val LOG_TAG = "arti"
        const val VERSION_LABEL = "arti-mobile"
        /** Matches arti-client crate embedded in arti-mobile 1.7.0.1. */
        const val ARTI_CLIENT_VERSION = "0.36.0"
        /**
         * arti-client default [preemptive_circuits.prediction_lifetime] ≈ 1 hour.
         * Must not track C Tor NewCircuitPeriod (often 30–180s).
         */
        const val ARTI_PREDICTION_LIFETIME_DEFAULT_SEC = 3_600
        const val STATUS_FILE_NAME = "arti.status"
        const val TIMING_FILE_NAME = "onionvpn_circuit_timing"
        const val PATH_PREFS_FILE_NAME = "onionvpn_path_prefs"
        const val PT_PLUGINS_FILE_NAME = "onionvpn_pt_plugins"
        private const val STOP_AWAIT_TIMEOUT_MS = 45_000L

        /** Map UI/C-Tor NewCircuitPeriod → Arti prediction_lifetime (floored). */
        fun artiPredictionLifetimeSec(uiNewCircuitPeriodSec: Int): Int =
            maxOf(uiNewCircuitPeriodSec, ARTI_PREDICTION_LIFETIME_DEFAULT_SEC)
                .coerceIn(ARTI_PREDICTION_LIFETIME_DEFAULT_SEC, 86_400)

        /** Parse Tor `{cc},{cc}` (also tolerates bare `cc`). */
        fun parseCountryCodes(raw: String): Set<String> =
            raw.split(',')
                .map { it.trim().removePrefix("{").removeSuffix("}").lowercase() }
                .filter { it.length == 2 && it.all(Char::isLetter) }
                .toSet()

        /** Single-country ExitNodes for Arti StreamPrefs::exit_country, or null. */
        fun singleExitCountryOrNull(raw: String): String? {
            val codes = parseCountryCodes(raw)
            return codes.singleOrNull()
        }
    }
}
