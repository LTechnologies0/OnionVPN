package ltechnologies.onionphone.onionvpn.core.tor.lifecycle

import java.io.DataInputStream
import java.io.DataOutputStream
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
 *
 * DNSCrypt uses `force_tcp = true`, so [isDnsPortTcpReady] matters for Arti bootstrap
 * (Arti stock dns-proxy is UDP-only; OnionVPN binds a TCP DNS adapter on the same port).
 */
object TorReadiness {
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
     * Minimal DNS query to Tor DNSPort (UDP).
     * @throws Exception on send/receive failure or timeout
     */
    fun assertDnsPortReady(port: Int, timeoutMs: Int = 8_000) {
        DatagramSocket(0, InetAddress.getByName(TunnelEndpoints.LOOPBACK)).use { socket ->
            socket.soTimeout = timeoutMs
            socket.send(
                DatagramPacket(
                    MINIMAL_DNS_QUERY,
                    MINIMAL_DNS_QUERY.size,
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

    /**
     * DNS-over-TCP (RFC 1035 length-prefixed) — what DNSCrypt hits with `force_tcp`.
     * @throws Exception on connect / framing / timeout
     */
    fun assertDnsPortTcpReady(port: Int, timeoutMs: Int = 8_000) {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(TunnelEndpoints.LOOPBACK, port), timeoutMs.coerceAtLeast(500))
            socket.soTimeout = timeoutMs
            // Do not close stream wrappers — that closes the Socket before the answer.
            val out = DataOutputStream(socket.getOutputStream())
            out.writeShort(MINIMAL_DNS_QUERY.size)
            out.write(MINIMAL_DNS_QUERY)
            out.flush()
            val inp = DataInputStream(socket.getInputStream())
            val len = inp.readUnsignedShort()
            if (len < 12 || len > 4_096) {
                throw IllegalStateException("DNS TCP answer length=$len")
            }
            val resp = ByteArray(len)
            inp.readFully(resp)
            if (resp[0] != MINIMAL_DNS_QUERY[0] || resp[1] != MINIMAL_DNS_QUERY[1]) {
                throw IllegalStateException("DNS TCP answer TXID mismatch")
            }
        }
    }

    fun isDnsPortTcpReady(port: Int, timeoutMs: Int = 1_500): Boolean =
        runCatching { assertDnsPortTcpReady(port, timeoutMs) }.isSuccess

    /** UDP or TCP DNS answer — true when either path works. */
    fun isDnsPortAnyReady(port: Int, timeoutMs: Int = 1_500): Boolean =
        isDnsPortTcpReady(port, timeoutMs) || isDnsPortReady(port, timeoutMs)

    /**
     * All three SocksPorts accept TCP.
     *
     * **C Tor only** — torrc opens apps + DNSCrypt + probe SocksPorts before bootstrap
     * completes. Do **not** use for Arti start: DNSCrypt/probe ports are opened later by
     * [ltechnologies.onionphone.onionvpn.core.vpn.forwarder.ArtiSocksRoleMux] (chicken-egg
     * deadlock / 180s timeout). Use [isPrimarySocksReady] for Arti.
     */
    fun assertSocksPortsReady(ports: TunnelRuntimePorts) {
        assertSocksReady(ports.torSocksPort)
        assertSocksReady(ports.torDnsCryptSocksPort)
        assertSocksReady(ports.torProbeSocksPort)
    }

    /** @see assertSocksPortsReady */
    fun areSocksPortsReady(ports: TunnelRuntimePorts): Boolean =
        isSocksReady(ports.torSocksPort) &&
            isSocksReady(ports.torDnsCryptSocksPort) &&
            isSocksReady(ports.torProbeSocksPort)

    /**
     * Native Tor/Arti SOCKS only (not DNSCrypt/probe role-mux listen ports).
     * Use for Arti start/readiness/network soft recovery — [ArtiSocksRoleMux] opens the
     * other ports after [ltechnologies.onionphone.onionvpn.core.tor.arti.ArtiRuntime] returns.
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

    private val MINIMAL_DNS_QUERY = byteArrayOf(
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
}
