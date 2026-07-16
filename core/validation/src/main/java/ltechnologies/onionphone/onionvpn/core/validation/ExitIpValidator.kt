package ltechnologies.onionphone.onionvpn.core.validation

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.core.content.getSystemService
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import timber.log.Timber

/**
 * Proves egress is a Tor exit — not the device ISP/LAN IP (Whonix Reliable IP Hiding +
 * Tor Project check.torproject.org).
 *
 * Fetches [https://check.torproject.org/api/ip] over the **app** Tor SocksPort and
 * compares the reported IP to every non-VPN interface address Android still exposes
 * (Tor VPN Threat Model §5.1.1 — apps can see those; egress must not equal them).
 */
object ExitIpValidator {
    private const val TOR_CHECK_URL = "https://check.torproject.org/api/ip"
    private val IPV4_REGEX = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")

    suspend fun validate(
        context: Context,
        socksHost: String = TunnelEndpoints.LOOPBACK,
        socksPort: Int = TunnelEndpoints.TOR_SOCKS_PORT,
    ): List<ValidationCheck> = withContext(Dispatchers.IO) {
        val underlying = collectUnderlyingAddresses(context)
        val egress = fetchTorCheck(socksHost, socksPort)
        buildList {
            add(checkEgressNotLocal(egress, underlying))
            add(checkReportedAsTor(egress))
            add(checkVpnOnlyAddresses(context))
        }.also { checks ->
            checks.filter { it.status == ValidationStatus.Fail }.forEach { check ->
                Timber.e("Request FAIL [%s] %s: %s", check.id, check.label, check.detail)
            }
        }
    }

    private data class TorCheckResult(
        val ip: String?,
        val isTor: Boolean?,
        val error: String? = null,
    )

    private fun fetchTorCheck(socksHost: String, socksPort: Int): TorCheckResult {
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort))
        val client = OkHttpClient.Builder()
            .proxy(proxy)
            .connectTimeout(25, TimeUnit.SECONDS)
            .readTimeout(25, TimeUnit.SECONDS)
            .writeTimeout(25, TimeUnit.SECONDS)
            .followRedirects(true)
            .build()
        return try {
            val body = client.newCall(
                Request.Builder().url(TOR_CHECK_URL).header("User-Agent", "OnionVPN").build(),
            ).execute().use { response ->
                if (!response.isSuccessful) {
                    return@use null to "HTTP ${response.code}"
                }
                response.body?.string().orEmpty() to null
            }
            val err = body.second
            if (err != null) {
                return TorCheckResult(null, null, err)
            }
            val json = JSONObject(body.first.orEmpty())
            TorCheckResult(
                ip = json.optString("IP").takeIf { it.isNotBlank() },
                isTor = if (json.has("IsTor")) json.getBoolean("IsTor") else null,
            )
        } catch (error: Exception) {
            Timber.w(error, "Tor exit IP check failed")
            TorCheckResult(null, null, error.message ?: "fetch failed")
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }
    private fun checkEgressNotLocal(
        egress: TorCheckResult,
        underlying: Set<String>,
    ): ValidationCheck {
        val ip = egress.ip
        if (ip == null) {
            return ValidationCheck(
                id = "tor.exit.ip",
                label = "Egress IP is Tor exit (not ISP/LAN)",
                status = ValidationStatus.Fail,
                detail = egress.error ?: "No IP from check.torproject.org via SOCKS",
                tripsKillSwitch = true,
            )
        }
        if (isPrivateOrLocal(ip)) {
            return ValidationCheck(
                id = "tor.exit.ip",
                label = "Egress IP is Tor exit (not ISP/LAN)",
                status = ValidationStatus.Fail,
                detail = "Egress $ip is private/local — clearnet leak or misroute",
                tripsKillSwitch = true,
            )
        }
        if (ip in underlying) {
            return ValidationCheck(
                id = "tor.exit.ip",
                label = "Egress IP is Tor exit (not ISP/LAN)",
                status = ValidationStatus.Fail,
                detail = "Egress $ip equals device non-VPN address — ISP IP leak",
                tripsKillSwitch = true,
            )
        }
        val underlyingPublic = underlying.filter { !isPrivateOrLocal(it) }
        return ValidationCheck(
            id = "tor.exit.ip",
            label = "Egress IP is Tor exit (not ISP/LAN)",
            status = ValidationStatus.Pass,
            detail = "exit=$ip; deviceNonVpn=${underlyingPublic.ifEmpty { listOf("none-public") }}",
            tripsKillSwitch = true,
        )
    }

    private fun checkReportedAsTor(egress: TorCheckResult): ValidationCheck {
        return when (egress.isTor) {
            true -> ValidationCheck(
                id = "tor.exit.istor",
                label = "check.torproject.org IsTor=true",
                status = ValidationStatus.Pass,
                detail = "API confirms Tor exit IP=${egress.ip}",
                tripsKillSwitch = true,
            )
            false -> ValidationCheck(
                id = "tor.exit.istor",
                label = "check.torproject.org IsTor=true",
                status = ValidationStatus.Fail,
                detail = "IsTor=false IP=${egress.ip} — traffic not leaving via Tor",
                tripsKillSwitch = true,
            )
            null -> ValidationCheck(
                id = "tor.exit.istor",
                label = "check.torproject.org IsTor=true",
                status = ValidationStatus.Skipped,
                detail = egress.error ?: "IsTor field missing",
                tripsKillSwitch = false,
            )
        }
    }

    /**
     * VPN LinkAddresses must be OnionVPN ULA/CGNAT only — never a public or Wi‑Fi IP
     * (Orbot/InviZible virtual gateway pattern).
     */
    private fun checkVpnOnlyAddresses(context: Context): ValidationCheck {
        val cm = context.getSystemService<ConnectivityManager>()
            ?: return ValidationCheck(
                id = "vpn.address.not.public",
                label = "VPN addresses are virtual (not ISP)",
                status = ValidationStatus.Skipped,
                detail = "ConnectivityManager unavailable",
                tripsKillSwitch = false,
            )

        val vpnAddrs = cm.allNetworks.flatMap { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@flatMap emptyList()
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@flatMap emptyList()
            cm.getLinkProperties(network)?.linkAddresses.orEmpty().mapNotNull { la ->
                la.address.hostAddress?.substringBefore('%')
            }
        }.toSet()

        if (vpnAddrs.isEmpty()) {
            return ValidationCheck(
                id = "vpn.address.not.public",
                label = "VPN addresses are virtual (not ISP)",
                status = ValidationStatus.Fail,
                detail = "No VPN link addresses found",
                tripsKillSwitch = true,
            )
        }

        val expected = setOf(
            TunnelEndpoints.VPN_CLIENT_ADDRESS,
            TunnelEndpoints.VPN_CLIENT_ADDRESS_V6,
        )
        val unexpected = vpnAddrs.filter { addr ->
            addr !in expected && !isOnionVpnVirtual(addr)
        }
        val publicOnVpn = vpnAddrs.filter { !isPrivateOrLocal(it) && it !in expected }

        return if (publicOnVpn.isEmpty() && unexpected.isEmpty()) {
            ValidationCheck(
                id = "vpn.address.not.public",
                label = "VPN addresses are virtual (not ISP)",
                status = ValidationStatus.Pass,
                detail = "vpnAddrs=$vpnAddrs",
                tripsKillSwitch = true,
            )
        } else {
            ValidationCheck(
                id = "vpn.address.not.public",
                label = "VPN addresses are virtual (not ISP)",
                status = ValidationStatus.Fail,
                detail = "unexpected=$unexpected publicOnVpn=$publicOnVpn",
                tripsKillSwitch = true,
            )
        }
    }

    private fun collectUnderlyingAddresses(context: Context): Set<String> {
        val cm = context.getSystemService<ConnectivityManager>() ?: return emptySet()
        return cm.allNetworks.flatMap { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@flatMap emptyList()
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                return@flatMap emptyList()
            }
            cm.getLinkProperties(network)?.linkAddresses.orEmpty().mapNotNull { la ->
                la.address.hostAddress?.substringBefore('%')
            }
        }.toSet()
    }

    private fun isOnionVpnVirtual(host: String): Boolean {
        if (host == TunnelEndpoints.VPN_CLIENT_ADDRESS) return true
        if (host == TunnelEndpoints.VPN_CLIENT_ADDRESS_V6) return true
        if (host.startsWith("10.8.0.")) return true
        if (host.startsWith("fd00:8:8:8:")) return true
        // FakeDNS CGNAT pool (Orbot-style mapdns)
        if (host.startsWith("100.")) {
            val parts = host.split('.')
            if (parts.size == 4) {
                val second = parts[1].toIntOrNull() ?: return false
                return second in 64..127
            }
        }
        return false
    }

    fun isPrivateOrLocal(host: String): Boolean {
        if (host == "::1" || host == "127.0.0.1" || host.startsWith("127.")) return true
        if (host.startsWith("fe80:", ignoreCase = true)) return true
        if (host.startsWith("fc", ignoreCase = true) || host.startsWith("fd", ignoreCase = true)) {
            // ULA — private (includes OnionVPN fd00:8:8:8::2)
            return true
        }
        if (!IPV4_REGEX.matches(host)) {
            // Global IPv6 is not private; only ULA/link-local handled above.
            return false
        }
        return try {
            val addr = InetAddress.getByName(host)
            addr.isAnyLocalAddress || addr.isLoopbackAddress ||
                addr.isLinkLocalAddress || addr.isSiteLocalAddress ||
                isOnionVpnVirtual(host) ||
                host.startsWith("100.") // CGNAT
        } catch (_: Exception) {
            false
        }
    }
}
