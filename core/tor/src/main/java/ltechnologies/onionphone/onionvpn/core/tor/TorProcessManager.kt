package ltechnologies.onionphone.onionvpn.core.tor

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import ltechnologies.onionphone.onionvpn.core.tor.lifecycle.TorReadiness
import timber.log.Timber

/**
 * Owns the Tor native process and orchestrates the sequential start/stop pipeline.
 *
 * Lives in the root `core.tor` package (public DI entry) while control/config/lifecycle
 * internals stay in subpackages — keeps Hilt/KSP resolution stable.
 *
 * **Start pipeline (ordered):**
 * 1. [stopInternal] + kill orphans + delete stale ControlSocket/cookie
 * 2. [writeTorrc] via [TorConfigWriter]
 * 3. [spawnTorProcess]
 * 4. [waitForControlPlane] (sock + cookie files)
 * 5. [TorControlClient.connect] (auth / SETEVENTS)
 * 6. [waitForBootstrap] (GETINFO + [TorReadiness] listeners)
 * 7. SIGNAL ACTIVE
 *
 * **Network recovery sub-pipeline:** DROPTIMEOUTS → ACTIVE → CLEARDNSCACHE → refresh.
 *
 * Control ops are exposed via [control] (single surface — no duplicated SIGNAL wrappers).
 * App conveniences kept: [newNym], [onNetworkChanged], [signalDormant].
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

    /**
     * Public control session — prefer this over adding more manager wrappers.
     */
    val control = TorControlClient()

    val controlStatus: StateFlow<TorControlStatus> = control.status
    val controlEvents = control.events

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

    /** Optional sink for stderr/stdout lines from the Tor process. */
    var onLogLine: ((String) -> Unit)? = null

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
        // Step 1 — stopInternal clears runtimePorts; re-bind after teardown.
        stopInternal()
        killOrphanedProcesses()
        runCatching { controlSocketFile.delete() }
        runCatching { cookieFile.delete() }
        runtimePorts = ports
        try {
            ensureExecutable(binaryFile)
            ensureGeoIpFiles()
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
                bridgesConfigured = preferences.torBridges.lineSequence()
                    .map { it.trim() }
                    .any { it.isNotEmpty() && !it.startsWith("#") },
            )
            // Step 6
            waitForBootstrap(ports)
            // Step 7
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

    fun isRunning(): Boolean = process?.isAlive == true

    /** Probe SocksPort while Tor is up; used for reputation list downloads. */
    fun currentProbeSocksPort(): Int? =
        runtimePorts?.torProbeSocksPort?.takeIf { isRunning() }

    /** SIGNAL NEWNYM + CLEARDNSCACHE (user “new identity”), rate-limited ~10s. */
    fun newNym(): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.newNym().also {
            it.onSuccess { Timber.i("SIGNAL NEWNYM accepted") }
            it.onFailure { e -> Timber.w(e, "NEWNYM failed") }
        }
    }

    /** SIGNAL ACTIVE — wake from DORMANT after Blocking / network recovery. */
    fun signalActive(): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.setActive().also {
            it.onSuccess { Timber.i("SIGNAL ACTIVE") }
            it.onFailure { e -> Timber.w(e, "ACTIVE failed") }
        }
    }

    /** Live SETCONF MaxCircuitDirtiness / NewCircuitPeriod (no restart). */
    fun applyCircuitTimingLive(
        maxCircuitDirtinessSec: Int,
        newCircuitPeriodSec: Int,
    ): Result<Unit> {
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
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.closeCircuit(id, ifUnused)
    }

    fun closeStream(id: String, reason: String = TorControlCatalog.StreamEndReason.DONE): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.closeStream(id, reason)
    }

    fun listCircuits(): List<ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo> =
        if (control.isConnected) control.listCircuits() else emptyList()

    fun listStreams(): List<ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo> =
        if (control.isConnected) control.listStreams() else emptyList()

    fun extendNewCircuit(): Result<String> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.extendNewCircuit()
    }

    /** SIGNAL DORMANT (kill-switch Blocking while keeping Tor process). */
    fun signalDormant(): Result<Unit> = control.setDormant()

    /**
     * Underlying Android network changed (Wi‑Fi ↔ cell, loss, validated flip).
     *
     * Soft recovery only: DROPTIMEOUTS → ACTIVE → CLEARDNSCACHE.
     * A DisableNetwork bounce closes every Socks/DNS listener and DESTROYs all circuits
     * (see connection_connect_sockaddr Bug warn + STREAM FAILED storm) — that caused
     * app streams to sit at NEW without SENTCONNECT while Tor rebuilt isolation circuits.
     * Hard bounce is reserved for [recoverNetworkHard] (captive / prolonged stall).
     */
    fun onNetworkChanged(): Result<Unit> {
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
     * Hard recovery: DisableNetwork bounce to rebind OR sockets on a new path.
     * Tears down listeners/circuits — use only when soft recovery is insufficient.
     */
    fun recoverNetworkHard(): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        control.dropTimeouts().onFailure { Timber.w(it, "DROPTIMEOUTS failed") }
        control.setDisableNetwork(true).onFailure { Timber.w(it, "DisableNetwork=1 failed") }
        control.setDisableNetwork(false).onFailure { Timber.w(it, "DisableNetwork=0 failed") }
        val active = control.setActive()
        control.clearDnsCache().onFailure { Timber.w(it, "CLEARDNSCACHE failed") }
        control.refreshHealthLite()
        return active.also {
            it.onSuccess {
                Timber.w("Tor network recovery HARD: DROPTIMEOUTS+DisableNetwork bounce+ACTIVE+CLEARDNSCACHE")
            }
        }
    }

    /** Convenience: refresh GETINFO into [controlStatus]. */
    fun refreshControlInfo() = control.refreshInfo()

    /** Circuit/stream dumps — rare UI ticks only. */
    fun refreshControlCircuits() = control.refreshCircuits()

    /** Lightweight health poll (no circuit-status dump). */
    fun refreshControlHealthLite() = control.refreshHealthLite()

    /**
     * Process-wide `traffic/read|written` only — for aggregate bandwidth across all circuits.
     */
    fun refreshControlTraffic() = control.refreshTraffic()

    /** Live SETCONF bridges from multiline preference text. */
    fun setBridgesLive(bridgeText: String): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        val lines = bridgeText.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        return control.setBridges(lines).also {
            it.onSuccess { Timber.i("SETCONF bridges live count=%d", lines.size) }
        }
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
            ),
        )
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

    /** Seeds GeoIP so circuit UI can resolve relay countries (`ip-to-country`). */
    private fun ensureGeoIpFiles() {
        seedGeoIpAsset(TorConfigWriter.GEOIP_FILE_NAME, GEOIP_URL, minBytes = 100_000L)
        seedGeoIpAsset(TorConfigWriter.GEOIP6_FILE_NAME, GEOIP6_URL, minBytes = 50_000L)
    }

    private fun seedGeoIpAsset(name: String, url: String, minBytes: Long) {
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
        runCatching {
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 20_000
                readTimeout = 120_000
                instanceFollowRedirects = true
            }
            try {
                conn.inputStream.use { input ->
                    val tmp = File(configDirectory, "$name.part")
                    tmp.outputStream().use { output -> input.copyTo(output) }
                    if (tmp.length() < minBytes) {
                        tmp.delete()
                        error("GeoIP download too small: ${tmp.length()}")
                    }
                    if (!tmp.renameTo(dest)) {
                        tmp.copyTo(dest, overwrite = true)
                        tmp.delete()
                    }
                }
            } finally {
                conn.disconnect()
            }
            Timber.i("GeoIP downloaded: %s (%d bytes)", name, dest.length())
        }.onFailure {
            Timber.w(it, "GeoIP seed failed for %s — circuit flags may be empty", name)
        }
    }

    private fun stopInternal() {
        runCatching { control.disconnect(sendShutdown = true) }
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
        private const val GEOIP_URL =
            "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/config/geoip"
        private const val GEOIP6_URL =
            "https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/config/geoip6"
    }
}
