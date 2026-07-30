package ltechnologies.onionphone.onionvpn.core.validation.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import androidx.core.content.getSystemService
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.vpn.profile.VpnProfileBuilder
import timber.log.Timber

/**
 * VPN routing and leak checks using official Android APIs.
 *
 * Always targets **this app's** VPN network (by owner UID + tunnel address/DNS),
 * never the first VPN in [ConnectivityManager.allNetworks] — another VPN (e.g.
 * InviZible on a work profile) may own `tun0` while OnionVPN owns `tun1`.
 */
object AndroidVpnInspector {
    private val VPN_SESSION_NAME = VpnProfileBuilder.SESSION_NAME

    fun inspect(
        context: Context,
        killSwitchExpected: Boolean = true,
    ): List<ValidationCheck> {
        return try {
            inspectInternal(context, killSwitchExpected)
        } catch (error: SecurityException) {
            listOf(
                ValidationCheck(
                    id = "android.connectivity.permission",
                    label = "ConnectivityManager access",
                    status = ValidationStatus.Fail,
                    detail = error.message ?: "ACCESS_NETWORK_STATE required",
                ),
            )
        }
    }

    private fun inspectInternal(
        context: Context,
        @Suppress("UNUSED_PARAMETER") killSwitchExpected: Boolean,
    ): List<ValidationCheck> {
        val connectivity = context.getSystemService<ConnectivityManager>()
            ?: return listOf(
                ValidationCheck(
                    id = "android.connectivity.unavailable",
                    label = "ConnectivityManager available",
                    status = ValidationStatus.Fail,
                    detail = "System service missing",
                ),
            )

        val ownUid = Process.myUid()
        val vpnNetworks = listVpnNetworks(connectivity)
        val ours = selectOwnVpnNetwork(connectivity, vpnNetworks, ownUid)
        val others = vpnNetworks.filter { it != ours }

        return buildList {
            add(checkOwnVpnRegistered(connectivity, ours, ownUid))
            add(checkCompetingVpns(connectivity, others, ownUid))
            addAll(checkVpnLinkProperties(connectivity, ours))
            // Validated Wi‑Fi/cell alongside the VPN is required (Tor is self-excluded from TUN).
            // Do NOT flag it as a kill-switch failure — that was a false "Skip" alarm in the UI.
            add(checkUnderlyingNonVpnNetwork(connectivity))
        }.also { checks ->
            checks.filter { it.status == ValidationStatus.Fail }.forEach { check ->
                Timber.e(
                    "Request FAIL [%s] %s: %s",
                    check.id,
                    check.label,
                    check.detail,
                )
            }
        }
    }

    /**
     * Tor upstream must ride a real Wi‑Fi/cellular network (VpnService.setUnderlyingNetworks).
     */
    private fun checkUnderlyingNonVpnNetwork(cm: ConnectivityManager): ValidationCheck {
        val underlying = cm.allNetworks.filter { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@filter false
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        val best = underlying.firstOrNull { network ->
            cm.getNetworkCapabilities(network)
                ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        } ?: underlying.firstOrNull()
        val caps = best?.let { cm.getNetworkCapabilities(it) }
        return ValidationCheck(
            id = "android.vpn.underlying",
            label = "Clearnet upstream for Tor (self-excluded)",
            status = if (best != null) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = if (best != null) {
                buildString {
                    append("OK — Tor needs a parallel NOT_VPN path; ")
                    append("net=$best")
                    if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) append(" WIFI")
                    if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) append(" CELL")
                    if (caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true) {
                        append(" VALIDATED")
                    }
                }
            } else {
                "No INTERNET+NOT_VPN upstream — Tor cannot reach guards"
            },
            // Soft: Wi‑Fi blip — keep Tor; Blocking would drop correctly-routable streams.
            tripsKillSwitch = false,
        )
    }

    private fun checkOwnVpnRegistered(
        cm: ConnectivityManager,
        ours: Network?,
        ownUid: Int,
    ): ValidationCheck {
        val activeCaps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) }
        val link = ours?.let { cm.getLinkProperties(it) }
        val caps = ours?.let { cm.getNetworkCapabilities(it) }

        return ValidationCheck(
            id = "android.vpn.default.network",
            label = "OnionVPN network registered",
            status = if (ours != null) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = when {
                ours == null -> "No OnionVPN network (uid=$ownUid, active=${activeCaps?.describe()})"
                else -> buildString {
                    append("iface=${link?.interfaceName}")
                    append(" ownerUid=${caps?.ownerUidOrNull() ?: "?"}")
                    // Session id is @SystemApi / blocked under targetSdk 37 — do not reflect.
                    append(" session=$VPN_SESSION_NAME")
                    append("; app excluded from TUN (active=${activeCaps?.describe()})")
                }
            },
        )
    }

    private fun checkCompetingVpns(
        cm: ConnectivityManager,
        others: List<Network>,
        ownUid: Int,
    ): ValidationCheck {
        if (others.isEmpty()) {
            return ValidationCheck(
                id = "android.vpn.competing",
                label = "No competing VPN networks",
                status = ValidationStatus.Pass,
                detail = "Only OnionVPN VPN network present",
            )
        }

        val details = others.map { network ->
            val caps = cm.getNetworkCapabilities(network)
            val link = cm.getLinkProperties(network)
            val otherUid = caps?.ownerUidOrNull()
            val iface = link?.interfaceName ?: "?"
            "iface=$iface ownerUid=${otherUid ?: "?"}"
        }

        val sameUserConflict = others.any { network ->
            val otherUid = cm.getNetworkCapabilities(network)?.ownerUidOrNull() ?: return@any false
            userIdOf(otherUid) == userIdOf(ownUid) && otherUid != ownUid
        }

        return ValidationCheck(
            id = "android.vpn.competing",
            label = "Competing VPN networks",
            status = if (sameUserConflict) ValidationStatus.Fail else ValidationStatus.Skipped,
            detail = if (sameUserConflict) {
                "Another VPN on the same Android user may steal routes: ${details.joinToString("; ")}. " +
                    "Stop the other VPN and restart OnionVPN."
            } else {
                "Other VPN(s) on another profile/user (ignored): ${details.joinToString("; ")}"
            },
        )
    }

    private fun checkVpnLinkProperties(
        cm: ConnectivityManager,
        vpnNetwork: Network?,
    ): List<ValidationCheck> {
        val link = vpnNetwork?.let { cm.getLinkProperties(it) }

        if (vpnNetwork == null || link == null) {
            return listOf(
                ValidationCheck(
                    id = "android.vpn.link.missing",
                    label = "VPN LinkProperties",
                    status = ValidationStatus.Fail,
                    detail = "OnionVPN network not found in ConnectivityManager",
                ),
            )
        }

        val hasDefaultRoute = hasIpv4DefaultRoute(link)
        val dnsServers = link.dnsServers.mapNotNull { it.hostAddress }
        val dnsOk = dnsServers.any {
            it == TunnelEndpoints.VPN_DNS_ADDRESS || it == TunnelEndpoints.FALLBACK_BLOCKING_DNS
        }
        val addressOk = link.linkAddresses.any { la ->
            la.address.hostAddress == TunnelEndpoints.VPN_CLIENT_ADDRESS
        }

        return listOf(
            ValidationCheck(
                id = "android.vpn.route.default",
                label = "VPN carries default IPv4 route",
                status = if (hasDefaultRoute) ValidationStatus.Pass else ValidationStatus.Fail,
                detail = "iface=${link.interfaceName}; " +
                    link.routes.joinToString { route ->
                        "${route.destination?.address?.hostAddress}/${route.destination?.prefixLength} " +
                            "dev ${route.`interface`}"
                    },
            ),
            ValidationCheck(
                id = "android.vpn.route.ipv6",
                label = "VPN captures default IPv6 route (::/0)",
                status = if (hasIpv6DefaultRoute(link)) ValidationStatus.Pass else ValidationStatus.Fail,
                detail = "Orbot/InviZible pattern — without ::/0, IPv6 can leak clearnet. " +
                    "routes=" + link.routes.filter {
                        it.destination?.address?.hostAddress?.contains(':') == true
                    }.joinToString { r ->
                        "${r.destination?.address?.hostAddress}/${r.destination?.prefixLength}"
                    },
            ),
            ValidationCheck(
                id = "android.vpn.dns.servers",
                label = "VPN DNS locked to tunnel resolver",
                status = if (dnsOk) ValidationStatus.Pass else ValidationStatus.Fail,
                detail = "expected ${TunnelEndpoints.VPN_DNS_ADDRESS}, got: ${dnsServers.joinToString()}",
            ),
            ValidationCheck(
                id = "android.vpn.address",
                label = "VPN tunnel address is OnionVPN",
                status = if (addressOk) ValidationStatus.Pass else ValidationStatus.Fail,
                detail = "expected ${TunnelEndpoints.VPN_CLIENT_ADDRESS}, " +
                    "got=${link.linkAddresses.joinToString { it.address.hostAddress ?: "?" }}",
            ),
            ValidationCheck(
                id = "android.vpn.interface",
                label = "VPN tunnel interface present",
                status = if (link.interfaceName?.startsWith("tun") == true) {
                    ValidationStatus.Pass
                } else {
                    ValidationStatus.Fail
                },
                detail = "interface=${link.interfaceName}",
            ),
        )
    }

    private fun hasIpv6DefaultRoute(link: LinkProperties): Boolean {
        return link.routes.any { route ->
            val dest = route.destination ?: return@any false
            val host = dest.address?.hostAddress ?: return@any false
            (host == "::" || host == "0:0:0:0:0:0:0:0") && dest.prefixLength == 0
        }
    }

    private fun hasIpv4DefaultRoute(link: LinkProperties): Boolean {
        if (
            link.routes.any { route ->
                val dest = route.destination ?: return@any false
                val host = dest.address?.hostAddress
                host == "0.0.0.0" && dest.prefixLength == 0
            }
        ) {
            return true
        }
        val ipv4 = link.routes.mapNotNull { route ->
            val dest = route.destination ?: return@mapNotNull null
            val host = dest.address?.hostAddress ?: return@mapNotNull null
            if (host.contains(':')) return@mapNotNull null
            host to dest.prefixLength
        }
        return coversFullIpv4(ipv4)
    }

    private fun coversFullIpv4(routes: List<Pair<String, Int>>): Boolean {
        val hasLow = routes.any { (h, p) -> h == "0.0.0.0" && p <= 1 }
        val hasHigh = routes.any { (h, p) -> h == "128.0.0.0" && p <= 1 }
        return hasLow && hasHigh
    }

    private fun listVpnNetworks(cm: ConnectivityManager): List<Network> =
        cm.allNetworks.filter { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@filter false
            isVpnTransport(caps)
        }

    private fun selectOwnVpnNetwork(
        cm: ConnectivityManager,
        vpnNetworks: List<Network>,
        ownUid: Int,
    ): Network? {
        vpnNetworks.firstOrNull { network ->
            cm.getNetworkCapabilities(network)?.ownerUidOrNull() == ownUid
        }?.let { return it }

        // Do not read VpnTransportInfo.getSessionId() — hidden / blocked at runtime
        // (targetSdk 37). ownerUid + TUN fingerprint are enough to pick our network.
        vpnNetworks.firstOrNull { network ->
            val link = cm.getLinkProperties(network) ?: return@firstOrNull false
            matchesOnionVpnFingerprint(link)
        }?.let { return it }

        return null
    }

    private fun matchesOnionVpnFingerprint(link: LinkProperties): Boolean {
        val hasAddress = link.linkAddresses.any {
            it.address.hostAddress == TunnelEndpoints.VPN_CLIENT_ADDRESS
        }
        val hasDns = link.dnsServers.any {
            it.hostAddress == TunnelEndpoints.VPN_DNS_ADDRESS ||
                it.hostAddress == TunnelEndpoints.FALLBACK_BLOCKING_DNS
        }
        return hasAddress || hasDns
    }

    private fun isVpnTransport(caps: NetworkCapabilities): Boolean =
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)

    private fun userIdOf(uid: Int): Int = uid / 100_000

    private fun NetworkCapabilities.ownerUidOrNull(): Int? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { ownerUid }.getOrNull()?.takeIf { it != -1 }
        } else {
            null
        }

    private fun NetworkCapabilities.describe(): String =
        buildString {
            append("transports=")
            if (hasTransport(NetworkCapabilities.TRANSPORT_VPN)) append("VPN,")
            if (hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) append("WIFI,")
            if (hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) append("CELL,")
            append(" caps=")
            if (hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) append("INTERNET,")
            if (hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) append("VALIDATED,")
            if (hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) append("NOT_VPN,")
        }
}
