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
 * Uses OS-assigned ephemeral ports (port 0) instead of probing random ports — the
 * manual bind probe fails on Android even when the port is actually free.
 */
object TunnelPortAllocator {
    private const val MIN_PORT = 10240
    private const val MAX_PORT = 65535
    private const val MAX_ATTEMPTS = 64

    fun allocate(): TunnelRuntimePorts {
        val used = mutableSetOf<Int>()
        return TunnelRuntimePorts(
            torSocksPort = allocateTcpPort(used),
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
    val torSocksPort: Int,
    val torDnsPort: Int,
    val dnsCryptListenPort: Int,
)
