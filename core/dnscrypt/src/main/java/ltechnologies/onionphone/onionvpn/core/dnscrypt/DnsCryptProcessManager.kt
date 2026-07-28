package ltechnologies.onionphone.onionvpn.core.dnscrypt

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptPublicResolvers
import ltechnologies.onionphone.onionvpn.core.dnscrypt.lifecycle.DnsCryptReadiness
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
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
        } catch (error: CancellationException) {
            stopInternal()
            throw error
        } catch (error: Exception) {
            Timber.e(error, "DNSCrypt failed to start")
            stopInternal()
            Result.failure(TunnelFailure.fromThrowable(error, context = "dnscrypt.start"))
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
            } catch (error: Exception) {
                if (process?.isAlive == true) {
                    Timber.w(error, "DNSCrypt log reader stopped unexpectedly")
                }
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
                throw CancellationException("DNSCrypt server wait cancelled")
            }
            if (process?.isAlive != true) {
                throw TunnelFailure.DnsCrypt(
                    "upstream",
                    "DNSCrypt process exited before upstream was ready",
                )
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
        throw TunnelFailure.DnsCrypt(
            "upstream",
            "DNSCrypt upstream timed out after ${timeoutMs}ms (SafeSocks/Tor proxy?)",
        )
    }

    private suspend fun waitForListener(
        port: Int,
        timeoutMs: Long = 60_000,
        pollMs: Long = 250,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!kotlin.coroutines.coroutineContext.isActive) {
                throw CancellationException("DNSCrypt listener wait cancelled")
            }
            if (process?.isAlive != true) {
                throw TunnelFailure.DnsCrypt(
                    "listen",
                    "DNSCrypt process exited before listener was ready on port $port",
                )
            }
            if (listenerReady.get() ||
                DnsCryptReadiness.probeLocalDns(port) ||
                DnsCryptReadiness.probeLocalTcp(port)
            ) {
                return
            }
            delay(pollMs)
        }
        throw TunnelFailure.DnsCrypt(
            "listen",
            "DNSCrypt listener timed out on port $port after ${timeoutMs}ms",
        )
    }

    private fun ensureExecutable(file: File) {
        if (!file.exists()) {
            throw TunnelFailure.DnsCrypt("start", "Binary missing at ${file.absolutePath}")
        }
        if (!file.canExecute()) {
            if (!file.setExecutable(true, false)) {
                throw TunnelFailure.DnsCrypt(
                    "start",
                    "Cannot set executable bit on ${file.absolutePath}",
                )
            }
        }
    }

    private fun writeConfig(serverName: String, ports: TunnelRuntimePorts) {
        seedPublicResolversCache()
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

    /** Seed offline public-resolvers cache (+ minisig) so sources work before Tor refresh. */
    private fun seedPublicResolversCache() {
        val names = listOf(
            DnsCryptPublicResolvers.SOURCE_CACHE_FILE,
            "${DnsCryptPublicResolvers.SOURCE_CACHE_FILE}.minisig",
        )
        for (name in names) {
            val dest = File(configDirectory, name)
            runCatching {
                context.assets.open(name).use { input ->
                    dest.outputStream().use { output -> input.copyTo(output) }
                }
            }.onFailure { err ->
                Timber.w(err, "Failed to seed DNSCrypt asset %s", name)
            }
        }
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
