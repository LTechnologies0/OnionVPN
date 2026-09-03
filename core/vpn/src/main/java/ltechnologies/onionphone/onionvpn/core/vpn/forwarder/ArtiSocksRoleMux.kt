package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.Process
import java.net.InetSocketAddress
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
 *
 * [start] hot-swaps upstream when listen ports are unchanged (onionmasq sidecar rebind)
 * so the OpenVPN auth shim keeps its accept FD and does not force soft-reconnect.
 */
class ArtiSocksRoleMux {
    private var ownerResolver: ConnectionOwnerResolver? = null
    private val ownUid = Process.myUid()
    private var dnsCryptRelay: SocksTcpRelay? = null
    private var probeRelay: SocksTcpRelay? = null
    /** Auth-injecting shim: OpenVPN NO-AUTH → Arti IsolateSOCKSAuth. */
    private var openVpnRelay: SocksAuthInjectingRelay? = null

    /**
     * @param appContext application context (never a half-constructed Service).
     */
    fun start(ports: TunnelRuntimePorts, appContext: Context? = null) {
        ownerResolver = appContext?.applicationContext?.let { ConnectionOwnerResolver(it) }
        if (ports.torDnsCryptSocksPort == ports.torSocksPort &&
            ports.torProbeSocksPort == ports.torSocksPort &&
            ports.torOpenVpnSocksPort == ports.torSocksPort
        ) {
            stop()
            Timber.i("ArtiSocksRoleMux: ports collapsed — nothing to relay")
            return
        }

        val wantDns = ports.torDnsCryptSocksPort != ports.torSocksPort
        val wantProbe = ports.torProbeSocksPort != ports.torSocksPort &&
            ports.torProbeSocksPort != ports.torDnsCryptSocksPort
        val wantOvpn = ports.torOpenVpnSocksPort != ports.torSocksPort &&
            ports.torOpenVpnSocksPort != ports.torDnsCryptSocksPort &&
            ports.torOpenVpnSocksPort != ports.torProbeSocksPort

        dnsCryptRelay = syncTcpRelay(
            current = dnsCryptRelay,
            want = wantDns,
            listen = ports.torDnsCryptSocksPort,
            upstream = ports.torSocksPort,
            label = "dnscrypt",
        )
        probeRelay = syncTcpRelay(
            current = probeRelay,
            want = wantProbe,
            listen = ports.torProbeSocksPort,
            upstream = ports.torSocksPort,
            label = "probe",
        )
        openVpnRelay = syncAuthRelay(
            current = openVpnRelay,
            want = wantOvpn,
            listen = ports.torOpenVpnSocksPort,
            upstream = ports.torSocksPort,
        )

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

    private fun syncTcpRelay(
        current: SocksTcpRelay?,
        want: Boolean,
        listen: Int,
        upstream: Int,
        label: String,
    ): SocksTcpRelay? {
        if (!want) {
            current?.stop()
            return null
        }
        if (current != null && current.listenPort == listen) {
            current.updateUpstream(upstream)
            return current
        }
        current?.stop()
        return SocksTcpRelay(
            listenPort = listen,
            upstreamHost = TunnelEndpoints.LOOPBACK,
            upstreamPort = upstream,
            label = label,
            acceptPeer = ::isTrustedPeer,
        ).also { it.start() }
    }

    private fun syncAuthRelay(
        current: SocksAuthInjectingRelay?,
        want: Boolean,
        listen: Int,
        upstream: Int,
    ): SocksAuthInjectingRelay? {
        if (!want) {
            current?.stop()
            return null
        }
        if (current != null && current.listenPort == listen) {
            current.updateUpstream(upstream)
            Timber.i("ArtiSocksRoleMux openvpn hot-swap upstream=%d (listen kept)", upstream)
            return current
        }
        current?.stop()
        return SocksAuthInjectingRelay(
            listenPort = listen,
            upstreamHost = TunnelEndpoints.LOOPBACK,
            upstreamPort = upstream,
            label = "openvpn",
            acceptPeer = ::isTrustedPeer,
        ).also { it.start() }
    }

    private fun isTrustedPeer(client: Socket): Boolean {
        val peerAddr = (client.remoteSocketAddress as? InetSocketAddress)?.address
        // Role mux binds loopback only — other UIDs cannot dial our 127.0.0.1 listeners.
        // When getConnectionOwnerUid/proc miss (Waydroid), fail-open for loopback peers.
        if (peerAddr?.isLoopbackAddress == true) {
            val resolver = ownerResolver ?: return true
            val peer = resolver.resolveAcceptedClientUid(client)
            if (ConnectionOwnerResolver.isValidUid(peer)) {
                return peer == ownUid
            }
            return true
        }
        val resolver = ownerResolver ?: return true
        val peer = resolver.resolveAcceptedClientUid(client)
        if (!ConnectionOwnerResolver.isValidUid(peer)) {
            // Pre-Q: getConnectionOwnerUid unavailable. API ≥ Q: fail-closed on miss.
            return android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.Q
        }
        return peer == ownUid
    }
}
