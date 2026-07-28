package ltechnologies.onionphone.onionvpn.core.tor

import android.content.Context
import java.io.File
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
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
        runtimePorts = ports
        // Step 1
        stopInternal()
        killOrphanedProcesses()
        runCatching { controlSocketFile.delete() }
        runCatching { cookieFile.delete() }
        try {
            ensureExecutable(binaryFile)
            // Step 2
            writeTorrc(ports)
            // Step 3
            spawnTorProcess()
            // Step 4
            waitForControlPlane()
            // Step 5
            control.connect(controlSocketFile, cookieFile)
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
            Result.failure(error)
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        stopInternal()
    }

    fun isRunning(): Boolean = process?.isAlive == true

    /** SIGNAL NEWNYM + CLEARDNSCACHE (user “new identity”). */
    fun newNym(): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.newNym().also {
            it.onSuccess { Timber.i("SIGNAL NEWNYM accepted") }
            it.onFailure { e -> Timber.w(e, "NEWNYM failed") }
        }
    }

    /** SIGNAL DORMANT (kill-switch Blocking while keeping Tor process). */
    fun signalDormant(): Result<Unit> = control.setDormant()

    /**
     * Underlying Android network changed — Orbot-style recovery:
     * DROPTIMEOUTS → ACTIVE → CLEARDNSCACHE → refreshInfo.
     */
    fun onNetworkChanged(): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        control.dropTimeouts().onFailure { Timber.w(it, "DROPTIMEOUTS failed") }
        val active = control.setActive()
        control.clearDnsCache().onFailure { Timber.w(it, "CLEARDNSCACHE failed") }
        control.refreshInfo()
        return active.also {
            it.onSuccess { Timber.i("Tor network recovery: DROPTIMEOUTS+ACTIVE+CLEARDNSCACHE") }
        }
    }

    /** Convenience: refresh GETINFO into [controlStatus]. */
    fun refreshControlInfo() = control.refreshInfo()

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
                throw IOException("Tor process exited before control socket")
            }
            if (controlSocketFile.exists() && cookieFile.exists() && cookieFile.length() > 0) {
                delay(150)
                return
            }
            delay(100)
        }
        throw IOException(
            "Tor control socket/cookie not ready " +
                "(sock=${controlSocketFile.exists()} cookie=${cookieFile.exists()})",
        )
    }

    /** Step 6: control bootstrap + local Socks/DNSPort readiness. */
    private suspend fun waitForBootstrap(
        ports: TunnelRuntimePorts,
        timeoutMs: Long = 120_000,
        pollMs: Long = 400,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive != true) {
                throw IOException("Tor process exited before bootstrap")
            }
            try {
                control.refreshInfo()
                val st = control.status.value
                val bootDone = st.bootstrapProgress >= 100 ||
                    (st.circuitEstablished && st.enoughDirInfo)
                TorReadiness.assertAllListenersReady(ports)
                if (bootDone) {
                    Timber.i(
                        "Tor bootstrap complete progress=%d tag=%s circuits=%d",
                        st.bootstrapProgress,
                        st.bootstrapTag,
                        st.builtCircuits,
                    )
                    return
                }
                if (st.bootstrapSummary.isNotBlank()) {
                    Timber.d(
                        "Tor bootstrap %d%% %s — %s",
                        st.bootstrapProgress,
                        st.bootstrapTag,
                        st.bootstrapSummary,
                    )
                }
            } catch (error: Exception) {
                lastError = error
            }
            delay(pollMs)
        }
        throw IOException("Tor bootstrap timed out", lastError)
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
            throw IOException("Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            file.setExecutable(true, false)
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
    }
}
