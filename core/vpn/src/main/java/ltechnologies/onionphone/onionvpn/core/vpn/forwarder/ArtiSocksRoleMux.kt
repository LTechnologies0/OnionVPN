package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.Process
import java.net.Socket
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import timber.log.Timber

/**
 * Gives Arti the product equivalent of C Tor SessionGroups: distinct loopback
 * SocksPorts for DNSCrypt, probes, and OpenVPN that forward to the single Arti SOCKS
 * listener. IsolationTokens remain the SOCKS username/password from each client.
 *
 * Peer-UID gate: only our process may dial these ports (DNSCrypt / validators / OVPN).
 * Foreign apps forging role auth would otherwise skip the TUN firewall.
 *
 * Do **not** construct with a Service/`ContextWrapper` from a field initializer —
 * [Context.getApplicationContext] NPEs before [android.app.Service.onCreate].
 */
class ArtiSocksRoleMux {
    private var ownerResolver: ConnectionOwnerResolver? = null
    private val ownUid = Process.myUid()
    private var dnsCryptRelay: SocksTcpRelay? = null
    private var probeRelay: SocksTcpRelay? = null
    private var openVpnRelay: SocksTcpRelay? = null

    /**
     * @param appContext application context (never a half-constructed Service).
     */
    fun start(ports: TunnelRuntimePorts, appContext: Context? = null) {
        stop()
        ownerResolver = appContext?.applicationContext?.let { ConnectionOwnerResolver(it) }
        if (ports.torDnsCryptSocksPort == ports.torSocksPort &&
            ports.torProbeSocksPort == ports.torSocksPort &&
            ports.torOpenVpnSocksPort == ports.torSocksPort
        ) {
            Timber.i("ArtiSocksRoleMux: ports collapsed — nothing to relay")
            return
        }
        if (ports.torDnsCryptSocksPort != ports.torSocksPort) {
            dnsCryptRelay = SocksTcpRelay(
                listenPort = ports.torDnsCryptSocksPort,
                upstreamHost = TunnelEndpoints.LOOPBACK,
                upstreamPort = ports.torSocksPort,
                label = "dnscrypt",
                acceptPeer = ::isTrustedPeer,
            ).also { it.start() }
        }
        if (ports.torProbeSocksPort != ports.torSocksPort &&
            ports.torProbeSocksPort != ports.torDnsCryptSocksPort
        ) {
            probeRelay = SocksTcpRelay(
                listenPort = ports.torProbeSocksPort,
                upstreamHost = TunnelEndpoints.LOOPBACK,
                upstreamPort = ports.torSocksPort,
                label = "probe",
                acceptPeer = ::isTrustedPeer,
            ).also { it.start() }
        }
        if (ports.torOpenVpnSocksPort != ports.torSocksPort &&
            ports.torOpenVpnSocksPort != ports.torDnsCryptSocksPort &&
            ports.torOpenVpnSocksPort != ports.torProbeSocksPort
        ) {
            openVpnRelay = SocksTcpRelay(
                listenPort = ports.torOpenVpnSocksPort,
                upstreamHost = TunnelEndpoints.LOOPBACK,
                upstreamPort = ports.torSocksPort,
                label = "openvpn",
                acceptPeer = ::isTrustedPeer,
            ).also { it.start() }
        }
        Timber.i(
            "ArtiSocksRoleMux up arti=%d dnscrypt=%d probe=%d openvpn=%d peerGate=%s",
            ports.torSocksPort,
            ports.torDnsCryptSocksPort,
            ports.torProbeSocksPort,
            ports.torOpenVpnSocksPort,
            ownerResolver != null,
        )
    }

    fun stop() {
        dnsCryptRelay?.stop()
        probeRelay?.stop()
        openVpnRelay?.stop()
        dnsCryptRelay = null
        probeRelay = null
        openVpnRelay = null
        ownerResolver = null
    }

    private fun isTrustedPeer(client: Socket): Boolean {
        val resolver = ownerResolver ?: return true
        val peer = resolver.resolveAcceptedClientUid(client)
        if (!ConnectionOwnerResolver.isValidUid(peer)) {
            // Pre-Q: getConnectionOwnerUid unavailable. API ≥ Q: fail-closed on miss.
            return android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.Q
        }
        return peer == ownUid
    }
}
