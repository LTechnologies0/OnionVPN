package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import timber.log.Timber

/**
 * Gives Arti the product equivalent of C Tor SessionGroups: distinct loopback
 * SocksPorts for DNSCrypt and probes that forward to the single Arti SOCKS
 * listener. IsolationTokens remain the SOCKS username/password from each client.
 */
class ArtiSocksRoleMux {
    private var dnsCryptRelay: SocksTcpRelay? = null
    private var probeRelay: SocksTcpRelay? = null

    fun start(ports: TunnelRuntimePorts) {
        stop()
        if (ports.torDnsCryptSocksPort == ports.torSocksPort &&
            ports.torProbeSocksPort == ports.torSocksPort
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
            ).also { it.start() }
        }
        Timber.i(
            "ArtiSocksRoleMux up arti=%d dnscrypt=%d probe=%d",
            ports.torSocksPort,
            ports.torDnsCryptSocksPort,
            ports.torProbeSocksPort,
        )
    }

    fun stop() {
        dnsCryptRelay?.stop()
        probeRelay?.stop()
        dnsCryptRelay = null
        probeRelay = null
    }
}
