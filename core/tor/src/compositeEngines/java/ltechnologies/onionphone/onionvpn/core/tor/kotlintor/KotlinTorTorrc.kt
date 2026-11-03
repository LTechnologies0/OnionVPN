package ltechnologies.onionphone.onionvpn.core.tor.kotlintor

import java.io.File
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.tor.config.TorConfigWriter
import org.kotlintor.config.TorConfig
import org.kotlintor.config.TorrcParser

/**
 * OnionVPN torrc → [TorConfig] for kotlin-tor. Control listens on loopback TCP (engine
 * binds via [org.kotlintor.android.KotlinTorEngine.startWithPorts]); torrc keeps
 * ControlPort 0 / no ControlSocket so parsed config does not fight the listener.
 */
internal object KotlinTorTorrc {
    const val TORRC_NAME = "torrc.kotlin-tor"

    fun writeAndParse(
        dataDirectory: File,
        ports: TunnelRuntimePorts,
        preferences: TunnelPreferences,
        nativeLibraryDir: String?,
    ): TorConfig {
        dataDirectory.mkdirs()
        val raw = TorConfigWriter.write(
            dataDirectory = dataDirectory.absolutePath,
            socksPort = ports.torSocksPort,
            dnsCryptSocksPort = ports.torDnsCryptSocksPort,
            probeSocksPort = ports.torProbeSocksPort,
            openVpnSocksPort = ports.torOpenVpnSocksPort,
            httpTunnelPort = ports.torHttpTunnelPort,
            dnsPort = ports.torDnsPort,
            preferences = preferences,
            nativeLibraryDir = nativeLibraryDir,
        )
        val torrc = raw.lines()
            .filterNot { line ->
                val t = line.trimStart()
                t.startsWith("ControlSocket", ignoreCase = true)
            }
            .joinToString("\n")
        val file = File(dataDirectory, TORRC_NAME)
        file.writeText(torrc)
        return TorrcParser.parse(torrc, dataDirectory.toPath())
    }
}
