package ltechnologies.onionphone.onionvpn.core.dnscrypt.lifecycle

import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.PortUnreachableException
import java.net.Socket
import java.net.SocketTimeoutException
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import timber.log.Timber

/**
 * Package `lifecycle` — local DNSCrypt listener / upstream readiness probes (no process spawn).
 *
 * Used by [ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager] steps 4–5.
 *
 * Probe failures are classified in logs (timeout vs refused vs unreachable) so start
 * timeouts can explain *why* the stub was not ready.
 */
internal object DnsCryptReadiness {
    /** TCP connect to loopback stub. */
    fun probeLocalTcp(port: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(TunnelEndpoints.LOOPBACK, port), 1_000)
        }
        true
    } catch (error: Exception) {
        logProbe("tcp", port, error)
        false
    }

    /** Any UDP DNS response from the stub (listener up). */
    fun probeLocalDns(port: Int): Boolean = try {
        DatagramSocket().use { socket ->
            socket.soTimeout = 1_000
            val query = wwwExampleQuery(id = 1)
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
            response.length > 0
        }
    } catch (error: Exception) {
        logProbe("udp-listen", port, error)
        false
    }

    /**
     * Successful A query (RCODE 0 + answers) — proves upstream via Tor SOCKS is usable.
     */
    fun probeResolvesExample(port: Int): Boolean = try {
        DatagramSocket().use { socket ->
            socket.soTimeout = 3_000
            val query = exampleComQuery(id = 2)
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
            response.length > 12 &&
                (response.data[3].toInt() and 0x0f) == 0 &&
                (((response.data[6].toInt() and 0xff) shl 8) or (response.data[7].toInt() and 0xff)) > 0
        }
    } catch (error: Exception) {
        logProbe("udp-upstream", port, error)
        false
    }

    /**
     * Parses dnscrypt-proxy log lines into readiness flags.
     *
     * @return Pair(listenerHint, serverHint)
     */
    fun hintsFromLogLine(line: String): Pair<Boolean, Boolean> {
        val listener = line.contains("Now listening to") || line.contains("live servers:")
        val server = line.contains("live servers:") ||
            (line.contains("[NOTICE]") && line.contains("OK") && line.contains("ms"))
        return listener to server
    }

    private fun logProbe(kind: String, port: Int, error: Exception) {
        val label = when (error) {
            is SocketTimeoutException -> "timeout"
            is ConnectException -> "refused"
            is PortUnreachableException -> "port-unreachable"
            else -> error.javaClass.simpleName
        }
        Timber.d("DNSCrypt probe %s:%d → %s (%s)", kind, port, label, error.message)
    }

    private fun exampleComQuery(id: Int): ByteArray = byteArrayOf(
        (id shr 8).toByte(), (id and 0xff).toByte(),
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

    private fun wwwExampleQuery(id: Int): ByteArray = byteArrayOf(
        (id shr 8).toByte(), (id and 0xff).toByte(),
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x03, 'w'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte(),
        0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
        'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
        0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
        0x00,
        0x00, 0x01,
        0x00, 0x01,
    )
}
