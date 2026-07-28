package ltechnologies.onionphone.onionvpn.core.dnscrypt

import android.content.Context
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.dnscrypt.lifecycle.DnsCryptReadiness
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import timber.log.Timber

/**
 * Owns the dnscrypt-proxy native process (public DI façade at module root).
 *
 * **Start pipeline (ordered):**
 * 1. [stopInternal] + kill orphans
 * 2. [writeConfig] via [DnsCryptConfigWriter]
 * 3. [spawnProcess]
 * 4. [waitForListener] ([DnsCryptReadiness] + log hints)
 * 5. [waitForLiveServer] (upstream via Tor SOCKS)
 *
 * Imported by: TunnelModule, TunnelForegroundService, OnionVpnApplication.
 */
class DnsCryptProcessManager(
    private val context: Context,
) {
    private var process: Process? = null
    private var logThread: Thread? = null
    private val listenerReady = AtomicBoolean(false)
    private val serverReady = AtomicBoolean(false)
    private var listenPort: Int? = null
    private var preferences: TunnelPreferences = TunnelPreferences()

    val configDirectory: File
        get() = File(context.filesDir, "dnscrypt").also { it.mkdirs() }

    val configFile: File
        get() = File(configDirectory, "dnscrypt-proxy.toml")

    val binaryFile: File
        get() = File(context.applicationInfo.nativeLibraryDir, "libdnscrypt-proxy.so")

    /** Optional sink for UI log buffers (set by app layer). */
    var onLogLine: ((String) -> Unit)? = null

    suspend fun start(
        serverName: String = "cloudflare",
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences = TunnelPreferences(),
    ): Result<Unit> = withContext(Dispatchers.IO) {
        this@DnsCryptProcessManager.preferences = preferences
        listenPort = ports.dnsCryptListenPort
        // Step 1
        stopInternal()
        killOrphanedProcesses()
        listenerReady.set(false)
        serverReady.set(false)
        try {
            ensureExecutable(binaryFile)
            // Step 2
            writeConfig(serverName.ifBlank { preferences.dnsCryptServerName }, ports)
            // Step 3
            spawnProcess()
            // Step 4
            waitForListener(ports.dnsCryptListenPort)
            // Step 5
            waitForLiveServer()
            Timber.i("DNSCrypt listening on ${ports.dnsCryptListenPort}")
            Result.success(Unit)
        } catch (error: Exception) {
            Timber.e(error, "DNSCrypt failed to start")
            stopInternal()
            Result.failure(error)
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        stopInternal()
    }

    fun isRunning(): Boolean = process?.isAlive == true

    private fun spawnProcess() {
        val command = listOf(
            binaryFile.absolutePath,
            "-config",
            configFile.absolutePath,
        )
        process = ProcessBuilder(command)
            .directory(configDirectory)
            .redirectErrorStream(true)
            .start()
        startLogPump(process!!)
    }

    private fun startLogPump(proc: Process) {
        logThread = Thread {
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { line ->
                        Timber.tag(LOG_TAG).d(line)
                        onLogLine?.invoke(line)
                        val (listener, server) = DnsCryptReadiness.hintsFromLogLine(line)
                        if (listener) listenerReady.set(true)
                        if (server) serverReady.set(true)
                    }
                }
            } catch (_: Exception) {
                // Process stopped.
            }
        }.apply {
            name = "dnscrypt-log"
            isDaemon = true
            start()
        }
    }

    private suspend fun waitForLiveServer(
        timeoutMs: Long = 90_000,
        pollMs: Long = 500,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!kotlin.coroutines.coroutineContext.isActive) {
                throw IOException("DNSCrypt server wait cancelled")
            }
            if (process?.isAlive != true) {
                throw IOException("DNSCrypt process exited before upstream was ready")
            }
            if (serverReady.get()) {
                Timber.i("DNSCrypt upstream server ready")
                return
            }
            val port = listenPort ?: return
            if (DnsCryptReadiness.probeResolvesExample(port)) {
                serverReady.set(true)
                Timber.i("DNSCrypt upstream ready (DNS probe)")
                return
            }
            delay(pollMs)
        }
        throw IOException("DNSCrypt upstream server timed out (SafeSocks/proxy?)")
    }

    private suspend fun waitForListener(
        port: Int,
        timeoutMs: Long = 60_000,
        pollMs: Long = 250,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!kotlin.coroutines.coroutineContext.isActive) {
                throw IOException("DNSCrypt listener wait cancelled")
            }
            if (process?.isAlive != true) {
                throw IOException("DNSCrypt process exited before listener was ready")
            }
            if (listenerReady.get() ||
                DnsCryptReadiness.probeLocalDns(port) ||
                DnsCryptReadiness.probeLocalTcp(port)
            ) {
                return
            }
            delay(pollMs)
        }
        throw IOException("DNSCrypt listener timed out on port $port")
    }

    private fun ensureExecutable(file: File) {
        if (!file.exists()) {
            throw IOException("Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            file.setExecutable(true, false)
        }
    }

    private fun writeConfig(serverName: String, ports: TunnelRuntimePorts) {
        configFile.writeText(
            DnsCryptConfigWriter.write(
                configDirectory = configDirectory.absolutePath,
                serverName = serverName,
                listenPort = ports.dnsCryptListenPort,
                torSocksPort = ports.torDnsCryptSocksPort,
                torDnsPort = ports.torDnsPort,
                preferences = preferences,
            ),
        )
        File(configDirectory, DnsCryptConfigWriter.BLOCKED_NAMES_FILE).writeText(
            DnsCryptConfigWriter.blockedNamesFileContent(),
        )
    }

    companion object {
        const val LOG_TAG = "dnscrypt"
    }

    private fun stopInternal() {
        process?.destroyForcibly()
        runCatching { process?.waitFor() }
        process = null
        logThread?.interrupt()
        logThread = null
        listenPort = null
    }

    private fun killOrphanedProcesses() {
        runCatching {
            Runtime.getRuntime()
                .exec(arrayOf("sh", "-c", "pkill -f ${binaryFile.name} 2>/dev/null || true"))
                .waitFor()
        }
    }
}
