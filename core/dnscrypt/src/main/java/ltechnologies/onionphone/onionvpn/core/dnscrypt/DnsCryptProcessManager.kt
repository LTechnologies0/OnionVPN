package ltechnologies.onionphone.onionvpn.core.dnscrypt

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptPublicResolvers
import ltechnologies.onionphone.onionvpn.core.dnscrypt.lifecycle.DnsCryptReadiness
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.observability.MemoryHygiene
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
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
    private var lastPorts: TunnelRuntimePorts? = null
    private var lastSocksOverride: Int? = null
    private var lastSocksUser: String? = null
    private var lastServerName: String = "cloudflare"
    private val lifecycleMutex = Mutex()
    private val lastClearCacheMs = AtomicLong(0L)

    val configDirectory: File
        get() = File(context.filesDir, "dnscrypt").also { it.mkdirs() }

    val configFile: File
        get() = File(configDirectory, "dnscrypt-proxy.toml")

    val binaryFile: File
        get() = File(context.applicationInfo.nativeLibraryDir, "libdnscrypt-proxy.so")

    /** Optional sink for UI log buffers (set by app layer). */
    var onLogLine: ((String) -> Unit)? = null

    /**
     * @param socksPortOverride when set (onionmasq SOCKS sidecar), proxy line uses this
     *   instead of [TunnelRuntimePorts.torDnsCryptSocksPort].
     * @param socksUserOverride IsolationToken username (NEWNYM rotates `dnscrypt-nN`).
     */
    suspend fun start(
        serverName: String = "cloudflare",
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences = TunnelPreferences(),
        socksPortOverride: Int? = null,
        socksUserOverride: String? = null,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        lifecycleMutex.withLock {
            OpTrace.stepSuspending("dnscrypt", "start", ProcessLogLevel.INFO) {
                this@DnsCryptProcessManager.preferences = preferences
                lastPorts = ports
                lastSocksOverride = socksPortOverride
                lastSocksUser = socksUserOverride
                lastServerName = serverName.ifBlank { preferences.dnsCryptServerName }
                listenPort = ports.dnsCryptListenPort
                OpTrace.debug("dnscrypt", "stop_prior")
                stopInternal()
                killOrphanedProcesses()
                listenerReady.set(false)
                serverReady.set(false)
                try {
                    OpTrace.step("dnscrypt", "ensure_binary") { ensureExecutable(binaryFile) }
                    OpTrace.step("dnscrypt", "write_config") {
                        writeConfig(lastServerName, ports, socksPortOverride, socksUserOverride)
                    }
                    OpTrace.step("dnscrypt", "spawn") { spawnProcess() }
                    OpTrace.stepSuspending("dnscrypt", "wait_listener") {
                        waitForListener(ports.dnsCryptListenPort)
                    }
                    OpTrace.stepSuspending("dnscrypt", "wait_server") { waitForLiveServer() }
                    OpTrace.info("dnscrypt", "listening on ${ports.dnsCryptListenPort}")
                    Timber.i("DNSCrypt listening on ${ports.dnsCryptListenPort}")
                    Result.success(Unit)
                } catch (error: CancellationException) {
                    stopInternal()
                    throw error
                } catch (error: Exception) {
                    OpTrace.error("dnscrypt", "failed to start", error)
                    Timber.e(error, "DNSCrypt failed to start")
                    stopInternal()
                    Result.failure(TunnelFailure.fromThrowable(error, context = "dnscrypt.start"))
                }
            }
        }
    }

    suspend fun stop() = withContext(Dispatchers.IO) {
        lifecycleMutex.withLock {
            OpTrace.stepSuspending("dnscrypt", "stop") {
                stopInternal()
                lastPorts = null
                lastSocksOverride = null
                lastSocksUser = null
            }
        }
    }

    fun isRunning(): Boolean = process?.isAlive == true

    /** Soft reconfigure while Connected — rewrite toml + restart with last SOCKS override. */
    suspend fun applyPreferences(
        serverName: String,
        preferences: TunnelPreferences,
    ): Result<Unit> {
        val ports = lastPorts ?: return Result.failure(
            TunnelFailure.DnsCrypt("reconfigure", "DNSCrypt has no runtime ports"),
        )
        return start(
            serverName,
            ports,
            preferences,
            socksPortOverride = lastSocksOverride,
            socksUserOverride = lastSocksUser,
        )
    }

    /**
     * Tor CLEARDNSCACHE / NEWNYM parity for dnscrypt-proxy.
     *
     * Upstream keeps the query cache in memory only and has no flush RPC — a soft
     * restart is the supported way to drop cached A/AAAA that could otherwise stick
     * across circuit identity changes (deanonymization via sticky DNS).
     */
    suspend fun clearQueryCache(): Result<Unit> = withContext(Dispatchers.IO) {
        val ports = lastPorts
        if (ports == null || !isRunning()) {
            return@withContext Result.success(Unit)
        }
        val now = System.currentTimeMillis()
        val prev = lastClearCacheMs.get()
        if (now - prev < CLEAR_CACHE_COOLDOWN_MS) {
            Timber.d("DNSCrypt clearQueryCache skipped — cooldown")
            return@withContext Result.success(Unit)
        }
        if (!lastClearCacheMs.compareAndSet(prev, now)) {
            return@withContext Result.success(Unit)
        }
        Timber.i("DNSCrypt clearQueryCache — soft restart (flush in-memory DNS cache)")
        start(
            lastServerName,
            ports,
            preferences,
            socksPortOverride = lastSocksOverride,
            socksUserOverride = lastSocksUser,
        )
    }

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
                // destroyForcibly() closes the pipe while the process may still look alive.
                val intentional =
                    error is java.io.InterruptedIOException ||
                        error.message?.contains("interrupted by close", ignoreCase = true) == true ||
                        process?.isAlive != true
                if (!intentional) {
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
                DnsCryptReadiness.probeLocalTcp(port) ||
                DnsCryptReadiness.probeLocalDns(port)
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

    private fun writeConfig(
        serverName: String,
        ports: TunnelRuntimePorts,
        socksPortOverride: Int? = null,
        socksUserOverride: String? = null,
    ) {
        seedPublicResolversCache()
        val socks = socksPortOverride?.takeIf { it > 0 } ?: ports.torDnsCryptSocksPort
        configFile.writeText(
            DnsCryptConfigWriter.write(
                configDirectory = configDirectory.absolutePath,
                serverName = serverName,
                listenPort = ports.dnsCryptListenPort,
                torSocksPort = socks,
                torDnsPort = ports.torDnsPort,
                preferences = preferences,
                socksUser = socksUserOverride ?: TunnelEndpoints.SOCKS_DNSCRYPT_USER,
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
        /** Avoid thrashing on Wi‑Fi blips that chain CLEARDNSCACHE + soft recovery. */
        private const val CLEAR_CACHE_COOLDOWN_MS = 5_000L
    }

    private fun stopInternal() {
        process?.destroyForcibly()
        runCatching { process?.waitFor() }
        process = null
        logThread?.interrupt()
        logThread = null
        listenPort = null
        MemoryHygiene.afterHeavyWork("dnscrypt_stop")
    }

    private fun killOrphanedProcesses() {
        runCatching {
            val proc = Runtime.getRuntime()
                .exec(arrayOf("sh", "-c", "pkill -f ${binaryFile.name} 2>/dev/null || true"))
            try {
                proc.inputStream.use { it.readBytes() }
                proc.errorStream.use { it.readBytes() }
                proc.waitFor()
            } finally {
                proc.destroyForcibly()
            }
        }
    }
}
