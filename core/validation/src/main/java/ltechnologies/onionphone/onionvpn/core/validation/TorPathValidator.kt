package ltechnologies.onionphone.onionvpn.core.validation

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

object TorPathValidator {
    suspend fun validate(
        socksHost: String = TunnelEndpoints.LOOPBACK,
        socksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
        dnsPort: Int = TunnelEndpoints.TOR_DNS_PORT,
    ): List<ValidationCheck> = withContext(Dispatchers.IO) {
        listOf(
            checkTcp("tor.socks", "Tor SOCKS reachable", socksHost, socksPort),
            checkDnsPort("tor.dnsport", "Tor DNSPort reachable (UDP)", socksHost, dnsPort),
            checkRemoteDns(socksHost, socksPort),
        ).also { checks ->
            checks.filter { it.status == ValidationStatus.Fail }.forEach { check ->
                Timber.e("Request FAIL [%s] %s: %s", check.id, check.label, check.detail)
            }
        }
    }

    fun validateTorrcContent(
        config: String,
        source: String,
        socksPort: Int? = null,
        dnsPort: Int? = null,
    ): ValidationCheck {
        val loopback = TunnelEndpoints.LOOPBACK
        val hasSocks = if (socksPort != null) {
            config.contains("SOCKSPort $loopback:$socksPort")
        } else {
            config.contains("SOCKSPort $loopback:")
        }
        val hasDns = if (dnsPort != null) {
            config.contains("DNSPort $loopback:$dnsPort")
        } else {
            config.contains("DNSPort $loopback:")
        }
        val safeSocksSet = config.contains("SafeSocks 0") || config.contains("SafeSocks 1")
        val clientOnly = config.contains("ClientOnly 1")
        val entryGuards = config.contains("UseEntryGuards 1")
        val socksIsolation = config.contains("IsolateDestAddr") &&
            config.contains("IsolateDestPort") &&
            config.contains("IsolateSOCKSAuth")
        val socksPolicy = config.contains("SocksPolicy accept 127.0.0.1") &&
            config.contains("SocksPolicy reject *")
        // Whonix: two SOCKSPort lines (app + DNSCrypt).
        val dualSocks = config.lineSequence().count { it.startsWith("SOCKSPort ") } >= 2
        val ok = hasSocks && hasDns && safeSocksSet && clientOnly &&
            entryGuards && socksIsolation && socksPolicy && dualSocks
        return ValidationCheck(
            id = "tor.config.content",
            label = "Tor torrc (runtime)",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "$source: socks=$hasSocks dns=$hasDns dualSocks=$dualSocks " +
                "SocksPolicy=$socksPolicy EntryGuards=$entryGuards Isolation=$socksIsolation" +
                (if (socksPort != null) " ports=$socksPort/$dnsPort" else ""),
        )
    }

    private fun checkDnsPort(id: String, label: String, host: String, port: Int): ValidationCheck {
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 5_000
                val query = minimalDnsQuery()
                socket.send(DatagramPacket(query, query.size, InetAddress.getByName(host), port))
                val response = DatagramPacket(ByteArray(512), 512)
                socket.receive(response)
            }
            ValidationCheck(id, label, ValidationStatus.Pass, "$host:$port (UDP)")
        } catch (error: Exception) {
            ValidationCheck(id, label, ValidationStatus.Fail, error.message ?: "unreachable")
        }
    }

    private fun checkTcp(id: String, label: String, host: String, port: Int): ValidationCheck {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 3_000)
            }
            ValidationCheck(id, label, ValidationStatus.Pass, "$host:$port")
        } catch (error: Exception) {
            ValidationCheck(id, label, ValidationStatus.Fail, error.message ?: "unreachable")
        }
    }

    private fun checkRemoteDns(host: String, port: Int): ValidationCheck {
        return try {
            val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, InetSocketAddress(host, port))
            val target = InetSocketAddress.createUnresolved("example.com", 80)
            Socket(proxy).use { socket ->
                socket.connect(target, 8_000)
            }
            ValidationCheck(
                id = "tor.remote.dns",
                label = "SOCKS5A remote DNS via Tor",
                status = ValidationStatus.Pass,
                detail = "Resolved example.com through SOCKS",
            )
        } catch (error: Exception) {
            ValidationCheck(
                id = "tor.remote.dns",
                label = "SOCKS5A remote DNS via Tor",
                status = ValidationStatus.Fail,
                detail = error.message ?: "remote DNS failed",
            )
        }
    }

    private fun minimalDnsQuery(): ByteArray = byteArrayOf(
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
