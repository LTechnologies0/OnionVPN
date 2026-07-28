package ltechnologies.onionphone.onionvpn.core.tor.lifecycle

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts

/**
 * Package `lifecycle` — SOCKS/DNSPort readiness probes for the Tor start pipeline.
 *
 * Separated from control so listener checks stay testable without ControlSocket.
 * Used by [ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager] step 6.
 */

/**
 * Local listener probes used after control bootstrap (pipeline step 6).
 *
 * Verifies the three SocksPorts + DNSPort from [TunnelRuntimePorts] accept connections
 * before the VPN declares Tor ready.
 */
internal object TorReadiness {
    /** TCP connect to loopback SOCKS. Throws on failure. */
    fun assertSocksReady(port: Int) {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(TunnelEndpoints.LOOPBACK, port),
                1_000,
            )
        }
    }

    /** Minimal DNS query to Tor DNSPort. Throws on failure. */
    fun assertDnsPortReady(port: Int) {
        val query = byteArrayOf(
            0x00, 0x01,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,
            0x00, 0x01,
            0x00, 0x01,
        )
        DatagramSocket().use { socket ->
            socket.soTimeout = 2_000
            socket.send(
                DatagramPacket(
                    query,
                    query.size,
                    InetAddress.getByName(TunnelEndpoints.LOOPBACK),
                    port,
                ),
            )
            val response = DatagramPacket(ByteArray(512), 512)
            socket.receive(response)
        }
    }

    /**
     * True when apps + DNSCrypt + probe SocksPorts and DNSPort all respond.
     *
     * @throws Exception from the first failing probe
     */
    fun assertAllListenersReady(ports: TunnelRuntimePorts) {
        assertSocksReady(ports.torSocksPort)
        assertSocksReady(ports.torDnsCryptSocksPort)
        assertSocksReady(ports.torProbeSocksPort)
        assertDnsPortReady(ports.torDnsPort)
    }
}
