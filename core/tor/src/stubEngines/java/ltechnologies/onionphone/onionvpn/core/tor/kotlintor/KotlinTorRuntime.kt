package ltechnologies.onionphone.onionvpn.core.tor.kotlintor

import android.content.Context
import java.io.File
import java.net.Socket
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter

/**
 * Stub when the kotlin-tor composite build is absent (CI / release without sibling checkout).
 * Selecting [ltechnologies.onionphone.onionvpn.core.model.TorEngine.KOTLIN_TOR] fails at start.
 */
internal class KotlinTorRuntime(
    private val context: Context,
) {
    val dataDirectory: File
        get() = File(context.filesDir, "tor").also { it.mkdirs() }

    val torrcFile: File
        get() = File(dataDirectory, "torrc.kotlin-tor")

    val cookieFile: File
        get() = File(dataDirectory, TorConfigWriter.COOKIE_FILE_NAME)

    var socketProtector: ((Int) -> Boolean)? = null
    var socketProtectorSocket: ((Socket) -> Boolean)? = null
    var onLogLine: ((String) -> Unit)? = null

    fun isRunning(): Boolean = false

    fun controlPort(): Int = -1

    suspend fun start(
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
    ) {
        throw UnsupportedOperationException(
            "kotlin-tor composite build missing — clone LTechnologies0/kotlin-tor next to OnionVPN",
        )
    }

    fun stop() = Unit

    fun newNym() = Unit
}
