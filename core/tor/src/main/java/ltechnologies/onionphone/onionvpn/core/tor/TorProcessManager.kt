package ltechnologies.onionphone.onionvpn.core.tor

import android.content.Context
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import timber.log.Timber

class TorProcessManager(
    private val context: Context,
) {
    private var process: Process? = null
    private var logThread: Thread? = null
    private var runtimePorts: TunnelRuntimePorts? = null
    private var preferences: TunnelPreferences = TunnelPreferences()
    private val control = TorControlClient()

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

    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        this@TorProcessManager.preferences = preferences
        runtimePorts = ports
        stopInternal()
        killOrphanedProcesses()
        // Stale control socket blocks bind.
        runCatching { controlSocketFile.delete() }
        runCatching { cookieFile.delete() }
        try {
            ensureExecutable(binaryFile)
            writeTorrc(ports)
            val command = listOf(binaryFile.absolutePath, "-f", torrcFile.absolutePath)
            process = ProcessBuilder(command)
                .directory(configDirectory)
                .redirectErrorStream(true)
                .start()
            startLogPump(process!!)
            waitForControlPlane()
            control.connect(controlSocketFile, cookieFile)
            waitForBootstrap(ports)
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

    fun newNym(): Result<Unit> {
        if (!control.isConnected) return Result.failure(IOException("control not connected"))
        return control.newNym().also {
            it.onSuccess { Timber.i("SIGNAL NEWNYM accepted") }
            it.onFailure { e -> Timber.w(e, "NEWNYM failed") }
        }
    }

    fun clearDnsCache(): Result<Unit> = control.clearDnsCache()

    fun signalActive(): Result<Unit> = control.setActive().also {
        it.onSuccess { Timber.i("SIGNAL ACTIVE (underlying network change)") }
    }

    fun signalDormant(): Result<Unit> = control.setDormant()

    fun refreshControlInfo() = control.refreshInfo()

    fun closeBuiltCircuits(): Result<Int> = control.closeBuiltCircuits()

    /** Optional sink for UI log buffers (set by app layer). */
    var onLogLine: ((String) -> Unit)? = null

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
                // Process stopped — ignore read interruption.
            }
        }.apply {
            name = "tor-log"
            isDaemon = true
            start()
        }
    }

    private suspend fun waitForControlPlane(timeoutMs: Long = 60_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive != true) {
                throw IOException("Tor process exited before control socket")
            }
            if (controlSocketFile.exists() && cookieFile.exists() && cookieFile.length() > 0) {
                // Brief settle — Tor finishes listen bind.
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
                val socksReady =
                    isSocksReady(ports.torSocksPort) &&
                        isSocksReady(ports.torDnsCryptSocksPort) &&
                        isSocksReady(ports.torProbeSocksPort) &&
                        isDnsPortReady(ports.torDnsPort)
                if (bootDone && socksReady) {
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

    private fun isSocksReady(port: Int): Boolean {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(TunnelEndpoints.LOOPBACK, port),
                1_000,
            )
        }
        return true
    }

    private fun isDnsPortReady(port: Int): Boolean {
        val query = byteArrayOf(
            0x00, 0x01,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        )
        java.net.DatagramSocket().use { socket ->
            socket.soTimeout = 2_000
            socket.send(
                java.net.DatagramPacket(
                    query,
                    query.size,
                    java.net.InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                    port,
                ),
            )
            val response = java.net.DatagramPacket(ByteArray(512), 512)
            socket.receive(response)
        }
        return true
    }

    private fun ensureExecutable(file: File) {
        if (!file.exists()) {
            throw IOException("Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            file.setExecutable(true, false)
        }
    }

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

    companion object {
        const val LOG_TAG = "tor"
    }

    private fun stopInternal() {
        // TAKEOWNERSHIP: closing control asks Tor to exit cleanly.
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
}
