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
 * SOCKS TCP accepts early; DNSPort may listen but not answer queries until bootstrap
 * finishes — never require a successful DNS reply before bootstrap is done.
 */
internal object TorReadiness {
    /** TCP connect to loopback SOCKS. Throws on failure. */
    fun assertSocksReady(port: Int, timeoutMs: Int = 800) {
        Socket().use { socket ->
            socket.connect(
                InetSocketAddress(TunnelEndpoints.LOOPBACK, port),
                timeoutMs,
            )
        }
    }

    /** True when a SOCKS TCP connect succeeds. */
    fun isSocksReady(port: Int, timeoutMs: Int = 800): Boolean =
        runCatching { assertSocksReady(port, timeoutMs) }.isSuccess

    /**
     * Minimal DNS query to Tor DNSPort.
     * @throws Exception on send/receive failure or timeout
     */
    fun assertDnsPortReady(port: Int, timeoutMs: Int = 8_000) {
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
        DatagramSocket(0, InetAddress.getByName(TunnelEndpoints.LOOPBACK)).use { socket ->
            socket.soTimeout = timeoutMs
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

    fun isDnsPortReady(port: Int, timeoutMs: Int = 1_500): Boolean =
        runCatching { assertDnsPortReady(port, timeoutMs) }.isSuccess

    /** All three SocksPorts accept TCP. */
    fun assertSocksPortsReady(ports: TunnelRuntimePorts) {
        assertSocksReady(ports.torSocksPort)
        assertSocksReady(ports.torDnsCryptSocksPort)
        assertSocksReady(ports.torProbeSocksPort)
    }

    fun areSocksPortsReady(ports: TunnelRuntimePorts): Boolean =
        isSocksReady(ports.torSocksPort) &&
            isSocksReady(ports.torDnsCryptSocksPort) &&
            isSocksReady(ports.torProbeSocksPort)

    /**
     * Native Tor/Arti SOCKS only (not DNSCrypt/probe role-mux listen ports).
     * Use for Arti start/readiness — [ArtiSocksRoleMux] opens the other ports later.
     */
    fun isPrimarySocksReady(ports: TunnelRuntimePorts): Boolean =
        isSocksReady(ports.torSocksPort)

    /**
     * True when apps + DNSCrypt + probe SocksPorts and DNSPort all respond.
     *
     * @throws Exception from the first failing probe
     */
    fun assertAllListenersReady(ports: TunnelRuntimePorts) {
        assertSocksPortsReady(ports)
        assertDnsPortReady(ports.torDnsPort)
    }
}
