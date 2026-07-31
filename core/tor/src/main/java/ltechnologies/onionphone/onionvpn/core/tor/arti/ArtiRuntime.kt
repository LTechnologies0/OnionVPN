package ltechnologies.onionphone.onionvpn.core.tor.arti

import android.content.Context
import java.io.File
import java.io.IOException
import kotlinx.coroutines.delay
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.tor.config.TorBridgeConfig
import ltechnologies.onionphone.onionvpn.core.tor.lifecycle.TorReadiness
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

    fun isRunning(): Boolean = running

    /**
     * Starts Arti SOCKS+DNS on [ports], waits until listeners accept, then returns.
     *
     * Bridge lines (when set) are passed to Arti with a managed Lyrebird path when the
     * required transports are Lyrebird-backed. Conjure is rejected (C Tor only).
     */
    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ) {
        stop()
        lastPorts = ports
        lastPreferences = preferences
        writeStatus(ports, preferences, ready = false)

        val bridges = TorBridgeConfig.parseLines(preferences.torBridges)
        val bridgeText = bridges.joinToString("\n").ifBlank { null }
        val ptPath = resolveManagedPtPath(preferences.torBridges)

        if (bridges.isNotEmpty() && ptPath == null) {
            val transports = TorBridgeConfig.requiredTransports(preferences.torBridges)
            throw TunnelFailure.TorBinary(
                "Arti bridges need a managed PT binary (Lyrebird/obfs4proxy) for $transports",
            )
        }

        Timber.i(
            "Starting Arti socks=%d dns=%d bridges=%d pt=%s",
            ports.torSocksPort,
            ports.torDnsPort,
            bridges.size,
            ptPath?.name ?: "none",
        )

        val result = try {
            ArtiMobileNative.start(
                cacheDir = cacheDirectory.absolutePath,
                stateDir = stateDirectory.absolutePath,
                obfs4Port = 0,
                snowflakePort = 0,
                obfs4proxyPath = ptPath?.absolutePath,
                bridgeLines = bridgeText,
                socksPort = ports.torSocksPort,
                dnsPort = ports.torDnsPort,
                logListener = { line ->
                    Timber.tag(LOG_TAG).d(line)
                    onLogLine?.invoke(line)
                },
            )
        } catch (error: Throwable) {
            running = false
            writeStatus(ports, preferences, ready = false, error = error.message)
            throw TunnelFailure.TorBinary(
                "Arti JNI start failed: ${error.message ?: error.javaClass.simpleName}",
                error,
            )
        }

        if (result.startsWith("Error:", ignoreCase = true)) {
            running = false
            writeStatus(ports, preferences, ready = false, error = result)
            throw TunnelFailure.TorBinary("Arti start error: $result")
        }

        running = true
        waitForListeners(ports)
        writeStatus(ports, preferences, ready = true)
        Timber.i("Arti listeners ready socks=%d dns=%d", ports.torSocksPort, ports.torDnsPort)
    }

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

    fun stop() {
        if (!running) {
            runCatching { ArtiMobileNative.stop() }
            runCatching { statusFile.delete() }
            return
        }
        runCatching { ArtiMobileNative.stop() }
            .onFailure { Timber.w(it, "Arti stop failed") }
        running = false
        runCatching { statusFile.delete() }
    }

    private fun writeStatus(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
        ready: Boolean,
        error: String? = null,
    ) {
        val bridges = TorBridgeConfig.parseLines(preferences.torBridges).size
        val pt = runCatching {
            resolveManagedPtPath(preferences.torBridges)?.name
        }.getOrNull().orEmpty()
        val text = buildString {
            appendLine("engine=arti")
            appendLine("version=$VERSION_LABEL")
            appendLine("ready=${if (ready) 1 else 0}")
            appendLine("socks=${ports.torSocksPort}")
            appendLine("dns=${ports.torDnsPort}")
            appendLine("shared_socks=1")
            appendLine("bridges=$bridges")
            appendLine("pt=$pt")
            appendLine("synthesize_onion_automap=1")
            if (error != null) appendLine("error=${error.replace('\n', ' ')}")
        }
        runCatching { statusFile.writeText(text) }
            .onFailure { Timber.w(it, "Failed to write Arti status file") }
    }

    private fun resolveManagedPtPath(bridgeText: String): File? {
        if (!TorBridgeConfig.isConfigured(bridgeText)) return null
        val needed = TorBridgeConfig.requiredTransports(bridgeText)
        if (needed.isEmpty()) return null
        if ("conjure" in needed) {
            throw TunnelFailure.TorBinary(
                "Arti engine does not support conjure bridges — switch Tor engine to C Tor",
            )
        }
        val path = needed
            .asSequence()
            .mapNotNull { TorBridgeConfig.binaryForTransport(it, nativeLibraryDir) }
            .firstOrNull()
            ?: return null
        if (!path.canExecute()) {
            path.setExecutable(true, false)
        }
        return path
    }

    private suspend fun waitForListeners(
        ports: TunnelRuntimePorts,
        timeoutMs: Long = 180_000,
        pollMs: Long = 500,
    ) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        while (System.currentTimeMillis() < deadline) {
            if (!running) {
                throw TunnelFailure.TorBinary("Arti stopped before listeners became ready")
            }
            try {
                if (TorReadiness.areSocksPortsReady(ports) &&
                    TorReadiness.isDnsPortReady(ports.torDnsPort)
                ) {
                    return
                }
            } catch (error: Exception) {
                lastError = error
            }
            delay(pollMs)
        }
        throw TunnelFailure.TorBootstrap(
            progress = 0,
            detail = "Arti SOCKS/DNS listeners not ready after ${timeoutMs}ms " +
                "(socks=${ports.torSocksPort} dns=${ports.torDnsPort})",
            cause = lastError ?: IOException("timeout"),
        )
    }

    companion object {
        const val LOG_TAG = "arti"
        const val VERSION_LABEL = "arti-mobile"
        const val STATUS_FILE_NAME = "arti.status"
    }
}
