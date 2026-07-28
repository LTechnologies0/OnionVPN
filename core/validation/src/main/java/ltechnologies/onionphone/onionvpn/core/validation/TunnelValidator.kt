package ltechnologies.onionphone.onionvpn.core.validation

import android.content.Context
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.validation.android.AndroidVpnInspector
import ltechnologies.onionphone.onionvpn.core.validation.leak.SystemLeakInspector
import ltechnologies.onionphone.onionvpn.core.validation.path.DnsCryptPathValidator
import ltechnologies.onionphone.onionvpn.core.validation.path.ExitIpValidator
import ltechnologies.onionphone.onionvpn.core.validation.path.TorPathValidator
import ltechnologies.onionphone.onionvpn.core.vpn.profile.VpnProfileBuilder

/**
 * Orchestrates the full tunnel validation graph (configs → path probes → Android VPN → leaks).
 *
 * Imported by [ltechnologies.onionphone.onionvpn.service.TunnelForegroundService].
 * Leaf validators live under `path/`, `android/`, `leak/` packages.
 */
object TunnelValidator {
    suspend fun validateAll(
        context: Context,
        torConfigFile: File? = null,
        dnsCryptConfigFile: File? = null,
        vpnEstablished: Boolean,
        killSwitchEnabled: Boolean = true,
        runtimePorts: TunnelRuntimePorts? = null,
        dnsResolverMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    ): List<ValidationCheck> = withContext(Dispatchers.Default) {
        val hevConfigFile = File(context.applicationContext.filesDir, "hev-socks5-tunnel.yaml")
        buildList {
            addAll(validateRuntimeConfigs(torConfigFile, dnsCryptConfigFile, runtimePorts))
            if (runtimePorts != null) {
                addAll(
                    TorPathValidator.validate(
                        socksPort = runtimePorts.torProbeSocksPort,
                        dnsPort = runtimePorts.torDnsPort,
                    ),
                )
                addAll(
                    ExitIpValidator.validate(
                        context = context.applicationContext,
                        socksPort = runtimePorts.torProbeSocksPort,
                    ),
                )
                addAll(DnsCryptPathValidator.validate(listenPort = runtimePorts.dnsCryptListenPort))
                add(validateHevForwarderWiring(hevConfigFile, runtimePorts, dnsResolverMode))
                add(validateDnsCryptTorWiring(dnsCryptConfigFile, runtimePorts))
                add(validateDnsModeLeakProperties(dnsResolverMode, hevConfigFile))
            } else {
                addAll(TorPathValidator.validate())
                addAll(DnsCryptPathValidator.validate())
            }
            if (vpnEstablished) {
                addAll(
                    AndroidVpnInspector.inspect(
                        context = context.applicationContext,
                        killSwitchExpected = killSwitchEnabled,
                    ),
                )
            } else {
                add(
                    ValidationCheck(
                        id = "vpn.not.established",
                        label = "VPN interface established",
                        status = ValidationStatus.Fail,
                        detail = "Skipped Android routing probes",
                    ),
                )
            }
            addAll(
                SystemLeakInspector.inspect(
                    context = context.applicationContext,
                    killSwitchExpected = killSwitchEnabled,
                ),
            )
            add(blockedDnsRoutesConfigured())
        }
    }

    /**
     * Failures that must trip the kill-switch. Checks with [ValidationCheck.tripsKillSwitch]
     * set to false are advisory only (e.g. Always-on lockdown lives in system Settings).
     */
    fun isKillSwitchFailure(check: ValidationCheck): Boolean =
        check.status == ValidationStatus.Fail && check.tripsKillSwitch

    /**
     * Hard kill-switch only when **app packets cannot be routed through Tor** (or would
     * clearnet-leak). Soft probe flakes (DNSCrypt, remote DNS, exit-IP fetch timeout,
     * underlying Wi‑Fi blip) must NOT blackhole traffic that Tor is still carrying.
     *
     * Kill-switch action = Blocking TUN (drop unroutable app packets). Tor/DNSCrypt stay
     * up for recovery unless Tor SOCKS itself is dead.
     */
    fun isHardKillSwitchFailure(check: ValidationCheck): Boolean {
        if (!isKillSwitchFailure(check)) return false
        return when (check.id) {
            // Tor SOCKS gone → nothing can be circuit-routed.
            "tor.socks" -> true
            // Confirmed non-Tor egress / ISP IP on SOCKS path.
            "tor.exit.istor" -> true
            "tor.exit.ip" -> {
                val d = check.detail.lowercase()
                d.contains("equals device") ||
                    d.contains("isp ip") ||
                    d.contains("private/local") ||
                    d.contains("clearnet leak")
            }
            // hev wiring broken → TUN packets won't reach Tor SOCKS.
            "hev.config.missing", "hev.forwarder.wiring" -> true
            // VPN interface / route ownership lost or stolen.
            "vpn.not.established",
            "android.vpn.link.missing",
            "android.vpn.default.network",
            "android.vpn.competing",
            "android.vpn.permission",
            -> true
            // Another app owns Always-on — our TUN can be displaced.
            "android.vpn.always_on" -> true
            // Soft: DNSCrypt / DNSPort / SOCKS5A example.com / underlying / timeout / config cosmetics.
            else -> false
        }
    }


    /**
     * Mode A: mapdns FakeDNS on 10.8.0.1:53 + fake-IP pool outside VPN subnet.
     * Mode B: no mapdns — TunDnsMux forwards UDP/53 to DNSCrypt; hev socks → Tor only.
     */
    private fun validateHevForwarderWiring(
        hevConfigFile: File?,
        ports: TunnelRuntimePorts,
        dnsMode: DnsResolverMode,
    ): ValidationCheck {
        val config = hevConfigFile?.takeIf { it.exists() }?.readText()
            ?: return ValidationCheck(
                id = "hev.config.missing",
                label = "hev-socks5 DNS + Tor SOCKS wiring",
                status = ValidationStatus.Fail,
                detail = "hev-socks5-tunnel.yaml not found",
            )

        val socksBlock = config.substringAfter("socks5:", "")
            .substringBefore("mapdns:")
            .substringBefore("misc:")
        val socksPortOk = socksBlock.contains("port: ${ports.torSocksPort}")
        val socksAddrOk = socksBlock.contains("address: '${TunnelEndpoints.LOOPBACK}'") ||
            socksBlock.contains("address: ${TunnelEndpoints.LOOPBACK}")

        return when (dnsMode) {
            DnsResolverMode.DNSCRYPT_MUX -> {
                val noMapDns = !config.contains("mapdns:")
                val icmpOff = config.contains("icmp: 'off'")
                val socksAuth = config.contains("username: '${TunnelEndpoints.SOCKS_ISOLATION_USER}'")
                val ipv6 = config.contains("ipv6: '${TunnelEndpoints.VPN_CLIENT_ADDRESS_V6}'")
                val ok = socksPortOk && socksAddrOk && noMapDns && icmpOff && socksAuth && ipv6
                ValidationCheck(
                    id = "hev.forwarder.wiring",
                    label = "Internet→Tor SOCKS; DNS via TunDnsMux→DNSCrypt",
                    status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
                    detail = "mode=DNSCRYPT_MUX socks=$socksPortOk auth=$socksAuth " +
                        "icmpOff=$icmpOff ipv6=$ipv6 noMapDns=$noMapDns " +
                        "(expect socks ${ports.torSocksPort})",
                    tripsKillSwitch = true,
                )
            }
            DnsResolverMode.FAKE_IP_SOCKS5A -> {
                val mapdnsBlock = config.substringAfter("mapdns:", "")
                val mapAddrOk = mapdnsBlock.contains("address: ${TunnelEndpoints.VPN_DNS_ADDRESS}")
                val mapPortOk = mapdnsBlock.contains("port: 53")
                val poolOk = mapdnsBlock.contains("network: ${TunnelEndpoints.FAKE_DNS_NETWORK}") &&
                    mapdnsBlock.contains("netmask: ${TunnelEndpoints.FAKE_DNS_NETMASK}")
                val ok = socksPortOk && socksAddrOk && mapAddrOk && mapPortOk && poolOk
                ValidationCheck(
                    id = "hev.forwarder.wiring",
                    label = "Internet→Tor SOCKS; FakeDNS on VPN DNS",
                    status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
                    detail = "mode=FAKE_IP socksPortOk=$socksPortOk mapAddrOk=$mapAddrOk " +
                        "mapPortOk=$mapPortOk poolOk=$poolOk",
                    tripsKillSwitch = true,
                )
            }
        }
    }

    private fun validateDnsCryptTorWiring(
        dnsCryptConfigFile: File?,
        ports: TunnelRuntimePorts,
    ): ValidationCheck {
        val config = dnsCryptConfigFile?.takeIf { it.exists() }?.readText()
            ?: return ValidationCheck(
                id = "dnscrypt.tor.wiring.missing",
                label = "DNSCrypt upstream via Tor SOCKS + DNSPort bootstrap",
                status = ValidationStatus.Fail,
                detail = "dnscrypt config missing",
            )

        val proxy =
            "socks5://${TunnelEndpoints.SOCKS_DNSCRYPT_USER}:${TunnelEndpoints.SOCKS_DNSCRYPT_PASS}" +
                "@${TunnelEndpoints.LOOPBACK}:${ports.torDnsCryptSocksPort}"
        val bootstrap = "${TunnelEndpoints.LOOPBACK}:${ports.torDnsPort}"
        val listen = "${TunnelEndpoints.LOOPBACK}:${ports.dnsCryptListenPort}"
        val proxyOk = config.contains("proxy = '$proxy'")
        val bootstrapOk = config.contains("bootstrap_resolvers = ['$bootstrap']")
        val netprobeOk = config.contains("netprobe_address = '$bootstrap'")
        val listenOk = config.contains("listen_addresses = ['$listen']")
        val ignoreSystem = config.contains("ignore_system_dns = true")
        val ok = proxyOk && bootstrapOk && netprobeOk && listenOk && ignoreSystem

        return ValidationCheck(
            id = "dnscrypt.tor.wiring",
            label = "DNSCrypt uses dedicated Tor SocksPort",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "listen=$listenOk proxy=$proxyOk bootstrap=$bootstrapOk " +
                "netprobe=$netprobeOk ignore_system_dns=$ignoreSystem " +
                "socks=${ports.torDnsCryptSocksPort}",
            tripsKillSwitch = false,
        )
    }

    private fun validateRuntimeConfigs(
        torConfigFile: File?,
        dnsCryptConfigFile: File?,
        runtimePorts: TunnelRuntimePorts?,
    ): List<ValidationCheck> {
        val dnsCryptConfig = dnsCryptConfigFile?.takeIf { it.exists() }?.readText()
        val torConfig = torConfigFile?.takeIf { it.exists() }?.readText()

        return listOf(
            if (dnsCryptConfig != null) {
                DnsCryptPathValidator.validateConfigContent(
                    dnsCryptConfig,
                    source = dnsCryptConfigFile.name,
                    listenPort = runtimePorts?.dnsCryptListenPort,
                    torSocksPort = runtimePorts?.torDnsCryptSocksPort,
                    torDnsPort = runtimePorts?.torDnsPort,
                )
            } else {
                ValidationCheck(
                    id = "dnscrypt.config.missing",
                    label = "DNSCrypt runtime config",
                    status = ValidationStatus.Fail,
                    detail = "Config file not found",
                )
            },
            if (torConfig != null) {
                TorPathValidator.validateTorrcContent(
                    torConfig,
                    source = torConfigFile.name,
                    socksPort = runtimePorts?.torSocksPort,
                    dnsPort = runtimePorts?.torDnsPort,
                )
            } else {
                ValidationCheck(
                    id = "tor.config.missing",
                    label = "Tor runtime config",
                    status = ValidationStatus.Fail,
                    detail = "torrc not found",
                )
            },
        )
    }

    private fun blockedDnsRoutesConfigured(): ValidationCheck {
        val blocked = VpnProfileBuilder.BLOCKED_PUBLIC_DNS
        return ValidationCheck(
            id = "vpn.blocked.dns.routes",
            label = "Public DNS endpoints routed into tunnel",
            status = if (blocked.isNotEmpty()) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = blocked.joinToString(),
        )
    }

    /**
     * Orbot FakeDNS: apps receive CGNAT fake A records; hostnames resolve at the Tor exit
     * via SOCKS5A — destination public IPs never appear in local DNS answers.
     * DNSCrypt mux: apps receive real A records (resolved over Tor) then connect by IP
     * through SOCKS — egress is still Tor, but local DNS cache holds real dest IPs.
     */
    private fun validateDnsModeLeakProperties(
        dnsMode: DnsResolverMode,
        hevConfigFile: File?,
    ): ValidationCheck {
        return when (dnsMode) {
            DnsResolverMode.FAKE_IP_SOCKS5A -> {
                val config = hevConfigFile?.takeIf { it.exists() }?.readText().orEmpty()
                val mapOk = config.contains("mapdns:") &&
                    config.contains("network: ${TunnelEndpoints.FAKE_DNS_NETWORK}")
                ValidationCheck(
                    id = "dns.mode.fakeip",
                    label = "FakeDNS hides destination IPs locally (Orbot)",
                    status = if (mapOk) ValidationStatus.Pass else ValidationStatus.Fail,
                    detail = "Apps get ${TunnelEndpoints.FAKE_DNS_NETWORK}/10 fakes; " +
                        "SOCKS5A recovers hostname at Tor exit (SafeSocks on)",
                    tripsKillSwitch = true,
                )
            }
            DnsResolverMode.DNSCRYPT_MUX -> ValidationCheck(
                id = "dns.mode.dnscrypt",
                label = "DNSCrypt-over-Tor (real A records, Tor egress)",
                status = ValidationStatus.Pass,
                detail = "DNS answers are real IPs resolved via Tor SOCKS; " +
                    "TCP still exits Tor. Prefer FakeDNS if local malware must not see dest IPs.",
                tripsKillSwitch = false,
            )
        }
    }
}
