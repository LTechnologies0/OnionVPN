package ltechnologies.onionphone.onionvpn.core.model

import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * Picks ephemeral loopback ports at tunnel start to avoid clashes with Tor Browser,
 * InviZible, Orbot, or stale processes still bound to well-known defaults.
 *
 * Whonix / path-spec stream isolation:
 * - [torSocksPort] hev/apps (SessionGroup APPS)
 * - [torDnsCryptSocksPort] DNSCrypt upstream (SessionGroup DNSCRYPT)
 * - [torProbeSocksPort] exit-IP / SOCKS5A probes (SessionGroup PROBE)
 * Distinct SocksPorts ⇒ incompatible proxy-address isolation profiles.
 */
object TunnelPortAllocator {
    private const val MIN_PORT = 10240
    private const val MAX_PORT = 65535
    private const val MAX_ATTEMPTS = 64

    fun allocate(engine: TorEngine = TorEngine.LITTLE_T): TunnelRuntimePorts {
        val used = mutableSetOf(
            TunnelEndpoints.PAC_LISTEN_PORT,
            TunnelEndpoints.PAC_BRIDGE_SOCKS_PORT,
            TunnelEndpoints.SOCKS_UID_BRIDGE_PORT,
            TunnelEndpoints.DNSCRYPT_LISTEN_PORT,
        )
        val socks = allocateTcpPort(used)
        // Always distinct role ports (SessionGroup parity). On Arti, [torSocksPort] is the
        // real Arti listener; DNSCrypt/probe ports are local TCP relays that forward to it
        // so IsolationToken usernames stay role-separated even without multi SocksPort.
        val dnsCryptSocks = allocateTcpPort(used)
        val probeSocks = allocateTcpPort(used)
        return TunnelRuntimePorts(
            torSocksPort = socks,
            torDnsCryptSocksPort = dnsCryptSocks,
            torProbeSocksPort = probeSocks,
            torHttpTunnelPort = allocateTcpPort(used),
            torDnsPort = allocateUdpPort(used),
            dnsCryptListenPort = allocateTcpUdpPort(used),
        )
    }

    private fun allocateTcpPort(exclude: MutableSet<Int>): Int {
        repeat(MAX_ATTEMPTS) {
            val port = ServerSocket(0).use { socket -> socket.localPort }
            if (port in exclude || port !in MIN_PORT..MAX_PORT) return@repeat
            exclude.add(port)
            return port
        }
        throw IOException("Failed to allocate a free TCP port after $MAX_ATTEMPTS attempts")
    }

    private fun allocateUdpPort(exclude: MutableSet<Int>): Int {
        repeat(MAX_ATTEMPTS) {
            val port = DatagramSocket(0).use { socket -> socket.localPort }
            if (port in exclude || port !in MIN_PORT..MAX_PORT) return@repeat
            exclude.add(port)
            return port
        }
        throw IOException("Failed to allocate a free UDP port after $MAX_ATTEMPTS attempts")
    }

    /** DNSCrypt listens on TCP and UDP on the same loopback port. */
    private fun allocateTcpUdpPort(exclude: MutableSet<Int>): Int {
        repeat(MAX_ATTEMPTS) {
            val port = ServerSocket(0).use { socket -> socket.localPort }
            if (port in exclude || port !in MIN_PORT..MAX_PORT) return@repeat
            if (!canBindUdp(port)) return@repeat
            exclude.add(port)
            return port
        }
        throw IOException("Failed to allocate a free TCP/UDP port after $MAX_ATTEMPTS attempts")
    }

    private fun canBindUdp(port: Int): Boolean {
        return try {
            DatagramSocket(null).use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port))
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}

data class TunnelRuntimePorts(
    /** Tor SocksPort for UID forwarder / application traffic. */
    val torSocksPort: Int,
    /** Tor SocksPort for DNSCrypt upstream only (Whonix: separate circuit family). */
    val torDnsCryptSocksPort: Int,
    /** Tor SocksPort for OnionVPN validation probes only (no app circuit sharing). */
    val torProbeSocksPort: Int,
    /** Tor HTTPTunnelPort slot (allocated but unused — HTTPTunnelPort 0; PAC bridge only). */
    val torHttpTunnelPort: Int,
    val torDnsPort: Int,
    val dnsCryptListenPort: Int,
)
