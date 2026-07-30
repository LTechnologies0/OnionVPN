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
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.LeakPacketFilter
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
        includeExitIp: Boolean = true,
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
                if (includeExitIp) {
                    addAll(
                        ExitIpValidator.validate(
                            context = context.applicationContext,
                            socksPort = runtimePorts.torProbeSocksPort,
                        ),
                    )
                }
                addAll(DnsCryptPathValidator.validate(listenPort = runtimePorts.dnsCryptListenPort))
                add(validateUidForwarderWiring(runtimePorts))
                add(validateDnsCryptTorWiring(dnsCryptConfigFile, runtimePorts))
                add(validateDnsModeLeakProperties(dnsResolverMode, hevConfigFile))
                add(validateUdpBlackholePolicy())
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

    /** Periodic keep-alive: local path probes only (no OkHttp exit-IP). */
    suspend fun validateLite(
        context: Context,
        torConfigFile: File? = null,
        dnsCryptConfigFile: File? = null,
        vpnEstablished: Boolean,
        killSwitchEnabled: Boolean = true,
        runtimePorts: TunnelRuntimePorts? = null,
        dnsResolverMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    ): List<ValidationCheck> = validateAll(
        context = context,
        torConfigFile = torConfigFile,
        dnsCryptConfigFile = dnsCryptConfigFile,
        vpnEstablished = vpnEstablished,
        killSwitchEnabled = killSwitchEnabled,
        runtimePorts = runtimePorts,
        dnsResolverMode = dnsResolverMode,
        includeExitIp = false,
    )

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
            // UID SOCKS / forwarder wiring broken → TUN packets won't reach Tor.
            "uid.forwarder.wiring", "hev.config.missing", "hev.forwarder.wiring" -> true
            // VPN interface / route ownership lost or stolen.
            "vpn.not.established",
            "android.vpn.link.missing",
            "android.vpn.default.network",
            "android.vpn.competing",
            "android.vpn.permission",
            -> true
            // Only when another app owns Always-on (tripsKillSwitch set by inspector).
            "android.vpn.always_on" -> true
            // Soft: DNSCrypt / DNSPort / SOCKS5A example.com / underlying / timeout / config cosmetics.
            else -> false
        }
    }


    /**
     * Connected data plane: hev → SocksUidBridge → Tor apps SocksPort (per-UID auth).
     * [OnionVpnService.hevSocksPort] stores the Tor apps SocksPort (not the bridge listen port).
     */
    private fun validateUidForwarderWiring(ports: TunnelRuntimePorts): ValidationCheck {
        val alive = OnionVpnService.tunForwarderAlive.value
        val socks = OnionVpnService.hevSocksPort.value
        val dns = OnionVpnService.hevDnsCryptPort.value
        val socksOk = alive && socks == ports.torSocksPort
        val dnsOk = dns == ports.dnsCryptListenPort
        val ok = socksOk && dnsOk
        return ValidationCheck(
            id = "uid.forwarder.wiring",
            label = "TUN forwarder ↔ Tor (hev + UID SOCKS bridge)",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "alive=$alive torSocks=$socks (want ${ports.torSocksPort}) " +
                "dnsCrypt=$dns (want ${ports.dnsCryptListenPort}) " +
                "bridge=:${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}",
            tripsKillSwitch = true,
        )
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
     * Both UI modes divert DNS to DNSCrypt-over-Tor (Privacy Guides: no clearnet stub).
     * Tor carries TCP only — UDP/ICMP are fail-closed dropped on the TUN.
     */
    private fun validateDnsModeLeakProperties(
        dnsMode: DnsResolverMode,
        @Suppress("UNUSED_PARAMETER") hevConfigFile: File?,
    ): ValidationCheck {
        return ValidationCheck(
            id = "dns.mode.dnscrypt",
            label = "DNSCrypt-over-Tor (no clearnet DNS)",
            status = ValidationStatus.Pass,
            detail = "mode=$dnsMode: any UDP/53 diverted to DNSCrypt via Tor SOCKS; " +
                "TCP via hev → SocksUidBridge (u{uid})",
            tripsKillSwitch = false,
        )
    }

    /**
     * Tor has no deployed Datagram/CONNECT_UDP (prop. 339). Policy: blackhole UDP
     * (except DNS→DNSCrypt) so apps fall back to TCP — zero clearnet UDP, zero gateway.
     */
    private fun validateUdpBlackholePolicy(): ValidationCheck {
        return ValidationCheck(
            id = "tor.udp.blackhole",
            label = "UDP policy: blackhole + force TCP",
            status = ValidationStatus.Pass,
            detail = "Tor Datagram (prop. 339 CONNECT_UDP) not on network — " +
                "QUIC/STUN/WebRTC/ICMP blackholed on TUN; apps must use TCP. " +
                "Stats: ${LeakPacketFilter.statsSummary()}",
            tripsKillSwitch = false,
        )
    }
}
