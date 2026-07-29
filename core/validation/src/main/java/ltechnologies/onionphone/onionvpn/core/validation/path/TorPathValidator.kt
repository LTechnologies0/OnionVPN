package ltechnologies.onionphone.onionvpn.core.validation.path

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
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.Socks5Client
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
        val safeSocksOff = config.contains("SafeSocks 0")
        val clientOnly = config.contains("ClientOnly 1")
        val entryGuards = config.contains("UseEntryGuards 1")
        val rejectInternal = config.contains("ClientRejectInternalAddresses 1")
        val safeLogging = config.contains("SafeLogging 1")
        val refuseUnknownExits = config.contains("RefuseUnknownExits 1")
        val controlSocket = config.contains("ControlSocket ") && config.contains("CookieAuthentication 1")
        val socksIsolation = config.contains("IsolateDestAddr") &&
            config.contains("IsolateSOCKSAuth") &&
            config.contains("IsolateClientAddr") &&
            config.contains("IsolateClientProtocol")
        val appsNoDestPortStorm = config.lineSequence()
            .filter { it.startsWith("SOCKSPort ") && it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}") }
            .any { it.contains("KeepAliveIsolateSOCKSAuth") && !it.contains("IsolateDestPort") }
        val socksPolicy = config.contains("SocksPolicy accept 127.0.0.1") &&
            config.contains("SocksPolicy reject *")
        // Apps + DNSCrypt + probe SocksPorts (path-spec proxy-address isolation).
        val multiSocks = config.lineSequence().count { it.startsWith("SOCKSPort ") } >= 3
        val hasProbeGroup = config.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_PROBE}")
        val keepAliveOnApps = config.lineSequence()
            .filter { it.startsWith("SOCKSPort ") && it.contains("SessionGroup=${TunnelEndpoints.SESSION_GROUP_APPS}") }
            .any { it.contains("KeepAliveIsolateSOCKSAuth") }
        val guardsOk = config.contains("NumEntryGuards 2") && config.contains("NumPrimaryGuards 2")
        val pendingOk = config.contains("MaxClientCircuitsPending 32")
        val ok = hasSocks && hasDns && safeSocksOff && clientOnly &&
            entryGuards && socksIsolation && socksPolicy && multiSocks &&
            hasProbeGroup && keepAliveOnApps && appsNoDestPortStorm &&
            guardsOk && pendingOk &&
            rejectInternal && safeLogging &&
            refuseUnknownExits && controlSocket
        return ValidationCheck(
            id = "tor.config.content",
            label = "Tor torrc (runtime)",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "$source: socks=$hasSocks dns=$hasDns multiSocks=$multiSocks " +
                "probeGroup=$hasProbeGroup keepAliveApps=$keepAliveOnApps " +
                "appsNoDestPort=$appsNoDestPortStorm guards2=$guardsOk pending32=$pendingOk " +
                "SafeSocks0=$safeSocksOff ControlSocket=$controlSocket RejectInternal=$rejectInternal " +
                "SafeLogging=$safeLogging RefuseUnknownExits=$refuseUnknownExits " +
                "SocksPolicy=$socksPolicy EntryGuards=$entryGuards Isolation=$socksIsolation" +
                (if (socksPort != null) " ports=$socksPort/$dnsPort" else ""),
        )
    }

    private fun checkDnsPort(id: String, label: String, host: String, port: Int): ValidationCheck {
        return try {
            DatagramSocket().use { socket ->
                // Exit resolve via DNSPort can exceed 5s on cold circuits ("Poll timed out").
                socket.soTimeout = DNS_PORT_TIMEOUT_MS
                val query = minimalDnsQuery()
                socket.send(DatagramPacket(query, query.size, InetAddress.getByName(host), port))
                val response = DatagramPacket(ByteArray(512), 512)
                socket.receive(response)
            }
            ValidationCheck(id, label, ValidationStatus.Pass, "$host:$port (UDP)")
        } catch (error: Exception) {
            ValidationCheck(
                id,
                label,
                ValidationStatus.Fail,
                error.message ?: "unreachable",
                tripsKillSwitch = false,
            )
        }
    }

    private fun checkTcp(id: String, label: String, host: String, port: Int): ValidationCheck {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 3_000)
            }
            ValidationCheck(id, label, ValidationStatus.Pass, "$host:$port")
        } catch (error: Exception) {
            ValidationCheck(
                id,
                label,
                ValidationStatus.Fail,
                error.message ?: "unreachable",
                tripsKillSwitch = id == "tor.socks",
            )
        }
    }

    /**
     * SOCKS5A via [Socks5Client] with probe IsolateSOCKSAuth tokens.
     * Java [java.net.Proxy] SOCKS often stalls / mis-auths against our SocksPorts.
     */
    private fun checkRemoteDns(host: String, port: Int): ValidationCheck {
        return try {
            Socks5Client(
                proxyHost = host,
                proxyPort = port,
                username = TunnelEndpoints.SOCKS_PROBE_USER,
                password = TunnelEndpoints.SOCKS_PROBE_PASS,
                connectTimeoutMs = REMOTE_DNS_TIMEOUT_MS,
            ).connect("example.com", 80).use { /* handshake + CONNECT OK */ }
            ValidationCheck(
                id = "tor.remote.dns",
                label = "SOCKS5A remote DNS via Tor",
                status = ValidationStatus.Pass,
                detail = "Resolved example.com through SOCKS5A (probe auth)",
            )
        } catch (error: Exception) {
            ValidationCheck(
                id = "tor.remote.dns",
                label = "SOCKS5A remote DNS via Tor",
                status = ValidationStatus.Fail,
                detail = error.message ?: "remote DNS failed",
                tripsKillSwitch = false,
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

    private const val DNS_PORT_TIMEOUT_MS = 15_000
    private const val REMOTE_DNS_TIMEOUT_MS = 25_000
}
