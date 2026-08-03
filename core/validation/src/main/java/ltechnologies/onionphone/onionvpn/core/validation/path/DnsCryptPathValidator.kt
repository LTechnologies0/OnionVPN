package ltechnologies.onionphone.onionvpn.core.validation.path

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import timber.log.Timber

object DnsCryptPathValidator {
    suspend fun validate(
        listenPort: Int = TunnelEndpoints.DNSCRYPT_LISTEN_PORT,
    ): List<ValidationCheck> = withContext(Dispatchers.IO) {
        listOf(probeListener(listenPort)).also { checks ->
            checks.filter { it.status == ValidationStatus.Fail }.forEach { check ->
                Timber.e("Request FAIL [%s] %s: %s", check.id, check.label, check.detail)
            }
        }
    }

    fun validateConfigContent(
        config: String,
        source: String,
        listenPort: Int? = null,
        torSocksPort: Int? = null,
        torDnsPort: Int? = null,
    ): ValidationCheck {
        val loopback = TunnelEndpoints.LOOPBACK
        val usesBootstrap = if (torDnsPort != null) {
            config.contains("bootstrap_resolvers = ['$loopback:$torDnsPort']")
        } else {
            config.contains("bootstrap_resolvers = ['$loopback:")
        }
        val usesNetprobe = if (torDnsPort != null) {
            config.contains("netprobe_address = '$loopback:$torDnsPort'")
        } else {
            config.contains("netprobe_address = '$loopback:")
        }
        val ignoresSystemDns = config.contains("ignore_system_dns = true")
        val usesProxy = if (torSocksPort != null) {
            config.contains("proxy = 'socks5://") && config.contains("@$loopback:$torSocksPort'")
        } else {
            config.contains("proxy = 'socks5://")
        }
        val hasListen = if (listenPort != null) {
            config.contains("listen_addresses = ['$loopback:$listenPort']")
        } else {
            config.contains("listen_addresses = ['$loopback:")
        }
        val ephemeralKeys = config.contains("dnscrypt_ephemeral_keys = true")
        val noTlsTickets = config.contains("tls_disable_session_tickets = true")
        val blockIpv6On = config.contains("block_ipv6 = true")
        val forceTcp = config.contains("force_tcp = true")
        val ok = usesBootstrap && usesNetprobe && ignoresSystemDns && usesProxy && hasListen &&
            ephemeralKeys && noTlsTickets && blockIpv6On && forceTcp
        return ValidationCheck(
            id = "dnscrypt.config.runtime",
            label = "DNSCrypt config (runtime)",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "$source: listen=$hasListen bootstrap=$usesBootstrap proxy=$usesProxy " +
                "ignore_system_dns=$ignoresSystemDns ephemeral=$ephemeralKeys " +
                "noTlsTickets=$noTlsTickets block_ipv6=true=$blockIpv6On force_tcp=$forceTcp",
            tripsKillSwitch = !ok,
        )
    }

    private fun probeListener(port: Int): ValidationCheck {
        // Prefer a real DNS answer (TCP first — force_tcp=true). Mere TCP accept is not enough.
        if (probeTcpDns(port)) {
            return ValidationCheck(
                id = "dnscrypt.listener",
                label = "DNSCrypt listener responds",
                status = ValidationStatus.Pass,
                detail = "${TunnelEndpoints.LOOPBACK}:$port (TCP DNS answer)",
                tripsKillSwitch = false,
            )
        }
        return try {
            DatagramSocket(0, InetAddress.getByName(TunnelEndpoints.LOOPBACK)).use { socket ->
                socket.soTimeout = 10_000
                val query = dnsQueryExampleA()
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
                if (!dnsIdMatches(response.data, response.length, query)) {
                    throw IllegalStateException("DNS response ID mismatch")
                }
            }
            ValidationCheck(
                id = "dnscrypt.listener",
                label = "DNSCrypt listener responds",
                status = ValidationStatus.Pass,
                detail = "${TunnelEndpoints.LOOPBACK}:$port (UDP DNS answer)",
                tripsKillSwitch = false,
            )
        } catch (error: Exception) {
            ValidationCheck(
                id = "dnscrypt.listener",
                label = "DNSCrypt listener responds",
                status = ValidationStatus.Fail,
                detail = error.message ?: "no DNS answer",
                tripsKillSwitch = false,
            )
        }
    }

    /** DNS-over-TCP: length-prefixed query; require matching transaction ID + answers. */
    private fun probeTcpDns(port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(TunnelEndpoints.LOOPBACK, port), 3_000)
                socket.soTimeout = 15_000
                val query = dnsQueryExampleA()
                // Do not close stream wrappers — that closes the Socket before the answer.
                val out = DataOutputStream(socket.getOutputStream())
                out.writeShort(query.size)
                out.write(query)
                out.flush()
                val inp = DataInputStream(socket.getInputStream())
                val len = inp.readUnsignedShort()
                if (len < 12 || len > 4_096) return false
                val resp = ByteArray(len)
                inp.readFully(resp)
                dnsIdMatches(resp, resp.size, query) &&
                    (resp[3].toInt() and 0x0f) == 0 &&
                    (((resp[6].toInt() and 0xff) shl 8) or (resp[7].toInt() and 0xff)) > 0
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun dnsQueryExampleA(): ByteArray = byteArrayOf(
        0x12, 0x34,
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

    private fun dnsIdMatches(response: ByteArray, length: Int, query: ByteArray): Boolean {
        if (length < 2 || query.size < 2) return false
        return response[0] == query[0] && response[1] == query[1]
    }
}
