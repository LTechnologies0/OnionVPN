package ltechnologies.onionphone.onionvpn.core.tor.kotlintor

import android.content.Context
import java.io.File
import java.net.Socket
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter
import org.kotlintor.android.KotlinTorEngine
import org.kotlintor.config.ListenSpec
import timber.log.Timber

internal class KotlinTorRuntime(
    private val context: Context,
) {
    private var engine: KotlinTorEngine? = null

    /** Shared with C Tor [ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager.configDirectory]. */
    val dataDirectory: File
        get() = File(context.filesDir, "tor").also { it.mkdirs() }

    val torrcFile: File
        get() = File(dataDirectory, KotlinTorTorrc.TORRC_NAME)

    val cookieFile: File
        get() = File(dataDirectory, TorConfigWriter.COOKIE_FILE_NAME)

    var socketProtector: ((Int) -> Boolean)? = null
    var socketProtectorSocket: ((Socket) -> Boolean)? = null

    var onLogLine: ((String) -> Unit)? = null

    fun isRunning(): Boolean = engine?.isRunning == true

    fun controlPort(): Int = engine?.controlPort?.takeIf { it > 0 } ?: -1

    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ) = suspendCancellableCoroutine { cont ->
        stopQuietly()
        val config = KotlinTorTorrc.writeAndParse(
            dataDirectory = dataDirectory,
            ports = ports,
            preferences = preferences,
            nativeLibraryDir = context.applicationInfo.nativeLibraryDir,
        )
        val tor = KotlinTorEngine(context, config)
        socketProtector?.let { tor.socketProtector = it }
        if (socketProtectorSocket != null) {
            org.kotlintor.os.PlatformNatives.socketProtectorSocket = socketProtectorSocket
        }
        engine = tor
        tor.startWithPorts(
            socks = ListenSpec(TunnelLoopback.HOST, ports.torSocksPort),
            dnsCryptSocks = ListenSpec(TunnelLoopback.HOST, ports.torDnsCryptSocksPort),
            probeSocks = ListenSpec(TunnelLoopback.HOST, ports.torProbeSocksPort),
            dns = ListenSpec(TunnelLoopback.HOST, ports.torDnsPort),
            httpTunnel = ListenSpec(TunnelLoopback.HOST, 0),
            controlListen = ListenSpec(TunnelLoopback.HOST, 0),
            onReady = {
                if (cont.isActive) cont.resume(Unit)
            },
            onError = { err ->
                if (cont.isActive) cont.resumeWithException(err)
            },
        )
        cont.invokeOnCancellation { tor.stop() }
    }

    fun stop() {
        stopQuietly()
        org.kotlintor.os.PlatformNatives.socketProtector = null
        org.kotlintor.os.PlatformNatives.socketProtectorSocket = null
    }

    fun newNym() {
        engine?.newnym()
    }

    private fun stopQuietly() {
        runCatching { engine?.stop() }
        engine = null
    }

    private object TunnelLoopback {
        const val HOST = "127.0.0.1"
    }
}
