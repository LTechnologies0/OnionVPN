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
 */
internal class ArtiRuntime(
    private val context: Context,
) {
    @Volatile
    private var running: Boolean = false

    val cacheDirectory: File
        get() = File(context.cacheDir, "arti_cache").also { it.mkdirs() }

    val stateDirectory: File
        get() = File(context.filesDir, "arti_state").also { it.mkdirs() }

    val nativeLibraryDir: File
        get() = File(context.applicationInfo.nativeLibraryDir)

    var onLogLine: ((String) -> Unit)? = null

    fun isRunning(): Boolean = running

    /**
     * Starts Arti SOCKS+DNS on [ports], waits until listeners accept, then returns.
     *
     * Bridge lines (when set) are passed to Arti with a managed Lyrebird path when the
     * required transports are Lyrebird-backed. Conjure / unmanaged PT ports are not
     * wired yet — prefer little-t Tor for those.
     */
    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ) {
        stop()
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
            throw TunnelFailure.TorBinary(
                "Arti JNI start failed: ${error.message ?: error.javaClass.simpleName}",
                error,
            )
        }

        if (result.startsWith("Error:", ignoreCase = true)) {
            running = false
            throw TunnelFailure.TorBinary("Arti start error: $result")
        }

        running = true
        waitForListeners(ports)
        Timber.i("Arti listeners ready socks=%d dns=%d", ports.torSocksPort, ports.torDnsPort)
    }

    fun stop() {
        if (!running) {
            runCatching { ArtiMobileNative.stop() }
            return
        }
        runCatching { ArtiMobileNative.stop() }
            .onFailure { Timber.w(it, "Arti stop failed") }
        running = false
    }

    private fun resolveManagedPtPath(bridgeText: String): File? {
        if (!TorBridgeConfig.isConfigured(bridgeText)) return null
        val needed = TorBridgeConfig.requiredTransports(bridgeText)
        if (needed.isEmpty()) return null
        // Managed path only covers Lyrebird / obfs4proxy transports. Conjure needs a
        // separate CTP binary Arti-mobile does not accept via the single path slot.
        if ("conjure" in needed) {
            throw TunnelFailure.TorBinary(
                "Arti engine does not support conjure bridges yet — use C Tor (libtor)",
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
    }
}
