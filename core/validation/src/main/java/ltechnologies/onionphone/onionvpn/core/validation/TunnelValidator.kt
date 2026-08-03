package ltechnologies.onionphone.onionvpn.core.validation

import android.content.Context
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelRuntimePorts
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.validation.android.AndroidVpnInspector
import ltechnologies.onionphone.onionvpn.core.validation.leak.SystemLeakInspector
import ltechnologies.onionphone.onionvpn.core.validation.path.DnsCryptPathValidator
import ltechnologies.onionphone.onionvpn.core.validation.path.ExitIpValidator
import ltechnologies.onionphone.onionvpn.core.validation.path.TorPathValidator
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.LeakPacketFilter
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.OnionmasqSocksSidecar
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
        torEngine: TorEngine = TorEngine.LITTLE_T,
    ): List<ValidationCheck> = withContext(Dispatchers.Default) {
        OpTrace.stepSuspending("validate", "validateAll", ProcessLogLevel.DEBUG) {
            val hevConfigFile = File(context.applicationContext.filesDir, "hev-socks5-tunnel.yaml")
            buildList {
                OpTrace.trace("validate", "runtime_configs")
                addAll(
                    validateRuntimeConfigs(
                        torConfigFile,
                        dnsCryptConfigFile,
                        runtimePorts,
                        torEngine,
                    ),
                )
                if (runtimePorts != null) {
                    val plane = OnionVpnService.vpnDataPlane.value
                    OpTrace.trace("validate", "tor_path")
                    addAll(
                        TorPathValidator.validate(
                            socksPort = runtimePorts.torProbeSocksPort,
                            dnsPort = runtimePorts.torDnsPort,
                        ),
                    )
                    if (includeExitIp) {
                        OpTrace.trace("validate", "exit_ip")
                        addAll(
                            ExitIpValidator.validate(
                                context = context.applicationContext,
                                socksPort = runtimePorts.torProbeSocksPort,
                            ),
                        )
                    }
                    OpTrace.trace("validate", "dnscrypt_path")
                    addAll(DnsCryptPathValidator.validate(listenPort = runtimePorts.dnsCryptListenPort))
                    if (plane == TunDataPlane.ONIONMASQ) {
                        add(validateOnionmasqPlane(runtimePorts))
                    } else {
                        add(validateUidForwarderWiring(runtimePorts))
                        // HEV yaml only — stale mapdns must not hard-fail onionmasq.
                        add(validateDnsModeLeakProperties(dnsResolverMode, hevConfigFile))
                    }
                    add(validateDnsCryptTorWiring(dnsCryptConfigFile, runtimePorts, torEngine))
                    add(validateUdpBlackholePolicy())
                } else {
                    addAll(TorPathValidator.validate())
                    addAll(DnsCryptPathValidator.validate())
                }
                if (vpnEstablished) {
                    OpTrace.trace("validate", "android_vpn")
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
        torEngine: TorEngine = TorEngine.LITTLE_T,
    ): List<ValidationCheck> = validateAll(
        context = context,
        torConfigFile = torConfigFile,
        dnsCryptConfigFile = dnsCryptConfigFile,
        vpnEstablished = vpnEstablished,
        killSwitchEnabled = killSwitchEnabled,
        runtimePorts = runtimePorts,
        dnsResolverMode = dnsResolverMode,
        includeExitIp = false,
        torEngine = torEngine,
    )

    /**
     * Fast hard-gate after a full [validateAll] timeout: local wiring + OS leak posture only.
     * Never promotes Connected on SOCKS TCP accept alone (Exit-IP / DNSPort flakes excluded).
     */
    suspend fun validateHardGate(
        context: Context,
        dnsCryptConfigFile: File? = null,
        vpnEstablished: Boolean,
        killSwitchEnabled: Boolean = true,
        runtimePorts: TunnelRuntimePorts,
        dnsResolverMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    ): List<ValidationCheck> = withContext(Dispatchers.Default) {
        val hevConfigFile = File(context.applicationContext.filesDir, "hev-socks5-tunnel.yaml")
        buildList {
            add(
                TorPathValidator.validateSocksOnly(
                    socksPort = runtimePorts.torProbeSocksPort,
                ),
            )
            // Local path proofs (Soft Fail) — prove Tor/DNSCrypt answer, not bare TCP accept.
            add(
                TorPathValidator.validateSocks5a(
                    socksPort = runtimePorts.torProbeSocksPort,
                ),
            )
            addAll(DnsCryptPathValidator.validate(listenPort = runtimePorts.dnsCryptListenPort))
            if (OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ) {
                add(validateOnionmasqPlane(runtimePorts))
            } else {
                add(validateUidForwarderWiring(runtimePorts))
                add(validateDnsModeLeakProperties(dnsResolverMode, hevConfigFile))
            }
            add(validateDnsCryptTorWiring(dnsCryptConfigFile, runtimePorts))
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
            // IsTor=false alone is Soft (ExitIpValidator) — unlisted exits must not Block.
            "tor.exit.ip" -> {
                val d = check.detail.lowercase()
                d.contains("equals device") ||
                    d.contains("isp ip") ||
                    d.contains("private/local") ||
                    d.contains("clearnet leak")
            }
            // Tor/Arti config / status readiness (tripsKillSwitch on content validators).
            "tor.arti.status",
            "tor.config.content",
            "tor.config.missing",
            -> true
            // UID SOCKS / forwarder wiring broken → TUN packets won't reach Tor.
            "uid.forwarder.wiring", "hev.config.missing", "hev.forwarder.wiring" -> true
            // onionmasq data plane not ready / sidecar missing.
            "onionmasq.plane.wiring" -> true
            // DNSCrypt not actually over Tor → clearnet DNS from VPN-excluded process.
            "dnscrypt.tor.wiring",
            "dnscrypt.tor.wiring.missing",
            "dnscrypt.config.runtime",
            "dnscrypt.config.missing",
            "dns.mode.mapdns",
            -> true
            // VPN interface / route ownership lost or stolen.
            "vpn.not.established",
            "android.vpn.link.missing",
            "android.vpn.default.network",
            "android.vpn.competing",
            "android.vpn.permission",
            -> true
            // Missing default routes → clearnet IPv4/IPv6 bypass.
            "android.vpn.route.default",
            "android.vpn.route.ipv6",
            -> true
            // OS Private DNS DoT actually active / forced hostname (Tor VPN §5.2.4).
            // tripsKillSwitch set by SystemLeakInspector — opportunistic-only is Soft.
            "android.dns.private" -> true
            // Another app owns Always-on, or Always-on without Lockdown (tripsKillSwitch).
            // Missing Always-on entirely stays Soft (user has not opted into OS Lockdown yet).
            "android.vpn.always_on" -> true
            // VPN iface shows a public/ISP address (not OnionVPN virtual gateway).
            "vpn.address.not.public" -> true
            // Hard-gate itself timed out / threw — never promote Connected on SOCKS TCP alone.
            "validation.hard_gate" -> true
            // Soft: validation.timeout / DNSCrypt listener / DNSPort / SOCKS5A / Wi‑Fi blip.
            // Timeout alone must not Block when Tor SOCKS still answers (ExitIp can exceed budget).
            else -> false
        }
    }


    /**
     * onionmasq plane: BootstrapEvent ready + SOCKS sidecar == DNSCrypt/probe ports.
     */
    private fun validateOnionmasqPlane(ports: TunnelRuntimePorts): ValidationCheck {
        val ready = OnionVpnService.onionmasqReady.value
        val alive = OnionVpnService.tunForwarderAlive.value
        val sidecar = OnionmasqSocksSidecar.socksPortOrZero()
        val dnsOk = OnionVpnService.hevDnsCryptPort.value == ports.dnsCryptListenPort
        val sidecarOk = sidecar > 0 &&
            sidecar == ports.torDnsCryptSocksPort &&
            sidecar == ports.torProbeSocksPort
        val ok = ready && alive && dnsOk && sidecarOk
        return ValidationCheck(
            id = "onionmasq.plane.wiring",
            label = "onionmasq TUN ↔ SOCKS sidecar (single TorClient)",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "ready=$ready alive=$alive sidecar=$sidecar " +
                "dnsCryptSocks=${ports.torDnsCryptSocksPort} probe=${ports.torProbeSocksPort} " +
                "dnsListenOk=$dnsOk",
            tripsKillSwitch = true,
        )
    }

    /**
     * Connected data plane: hev → SocksUidBridge → Tor apps SocksPort (per-UID auth).
     * [OnionVpnService.hevSocksPort] stores the Tor apps SocksPort (not the bridge listen port).
     */
    private fun validateUidForwarderWiring(ports: TunnelRuntimePorts): ValidationCheck {
        // Brief retry: hevSocksPort / dnsCrypt port publish can race TUN rebind.
        var alive = false
        var socks = 0
        var dns = 0
        repeat(4) { attempt ->
            alive = OnionVpnService.tunForwarderAlive.value
            socks = OnionVpnService.hevSocksPort.value
            dns = OnionVpnService.hevDnsCryptPort.value
            if (alive && socks == ports.torSocksPort && dns == ports.dnsCryptListenPort) {
                return ValidationCheck(
                    id = "uid.forwarder.wiring",
                    label = "TUN forwarder ↔ Tor (hev + UID SOCKS bridge)",
                    status = ValidationStatus.Pass,
                    detail = "alive=$alive torSocks=$socks dnsCrypt=$dns " +
                        "bridge=:${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}",
                    tripsKillSwitch = true,
                )
            }
            if (attempt < 3) Thread.sleep(50)
        }
        return ValidationCheck(
            id = "uid.forwarder.wiring",
            label = "TUN forwarder ↔ Tor (hev + UID SOCKS bridge)",
            status = ValidationStatus.Fail,
            detail = "alive=$alive torSocks=$socks (want ${ports.torSocksPort}) " +
                "dnsCrypt=$dns (want ${ports.dnsCryptListenPort}) " +
                "bridge=:${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}",
            tripsKillSwitch = true,
        )
    }

    private fun validateDnsCryptTorWiring(
        dnsCryptConfigFile: File?,
        ports: TunnelRuntimePorts,
        torEngine: TorEngine = TorEngine.LITTLE_T,
    ): ValidationCheck {
        val config = dnsCryptConfigFile?.takeIf { it.exists() }?.readText()
            ?: return ValidationCheck(
                id = "dnscrypt.tor.wiring.missing",
                label = "DNSCrypt upstream via Tor SOCKS + DNSPort bootstrap",
                status = ValidationStatus.Fail,
                detail = "dnscrypt config missing",
                tripsKillSwitch = true,
            )

        // Proxy user may be `dnscrypt` or `dnscrypt-nN` after onionmasq NEWNYM token rotate.
        val proxyHostPort =
            "@${TunnelEndpoints.LOOPBACK}:${ports.torDnsCryptSocksPort}"
        val bootstrap = "${TunnelEndpoints.LOOPBACK}:${ports.torDnsPort}"
        val listen = "${TunnelEndpoints.LOOPBACK}:${ports.dnsCryptListenPort}"
        val proxyOk = config.contains("proxy = 'socks5://") &&
            config.contains(proxyHostPort) &&
            config.contains(":${TunnelEndpoints.SOCKS_DNSCRYPT_PASS}@")
        val bootstrapOk = config.contains("bootstrap_resolvers = ['$bootstrap']")
        val netprobeOk = config.contains("netprobe_address = '$bootstrap'")
        val listenOk = config.contains("listen_addresses = ['$listen']")
        val ignoreSystem = config.contains("ignore_system_dns = true")
        val forceTcp = config.contains("force_tcp = true")
        val ok = proxyOk && bootstrapOk && netprobeOk && listenOk && ignoreSystem && forceTcp
        val socksLabel = when {
            OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ ->
                "onionmasq SOCKS sidecar"
            torEngine.capabilities.multiSocksSessionGroups ->
                "dedicated Tor SocksPort"
            else -> "Tor SOCKS (shared on Arti)"
        }

        return ValidationCheck(
            id = "dnscrypt.tor.wiring",
            label = "DNSCrypt uses $socksLabel",
            status = if (ok) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = "listen=$listenOk proxy=$proxyOk bootstrap=$bootstrapOk " +
                "netprobe=$netprobeOk ignore_system_dns=$ignoreSystem force_tcp=$forceTcp " +
                "socks=${ports.torDnsCryptSocksPort} engine=$torEngine",
            tripsKillSwitch = true,
        )
    }

    private fun validateRuntimeConfigs(
        torConfigFile: File?,
        dnsCryptConfigFile: File?,
        runtimePorts: TunnelRuntimePorts?,
        torEngine: TorEngine = TorEngine.LITTLE_T,
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
            when {
                OnionVpnService.vpnDataPlane.value == TunDataPlane.ONIONMASQ -> {
                    val ready = OnionVpnService.onionmasqReady.value
                    ValidationCheck(
                        id = "tor.arti.status",
                        label = "onionmasq TorClient (no arti-mobile)",
                        status = if (ready) ValidationStatus.Pass else ValidationStatus.Fail,
                        detail = "single TorClient via onionmasq ready=$ready " +
                            "sidecar=${OnionmasqSocksSidecar.socksPortOrZero()}",
                        tripsKillSwitch = true,
                    )
                }
                torEngine == TorEngine.ARTI && torConfig != null -> {
                    TorPathValidator.validateArtiStatusContent(
                        torConfig,
                        source = torConfigFile.name,
                        socksPort = runtimePorts?.torSocksPort,
                        dnsPort = runtimePorts?.torDnsPort,
                    )
                }
                torEngine == TorEngine.ARTI -> {
                    ValidationCheck(
                        id = "tor.config.missing",
                        label = "Arti runtime status",
                        status = ValidationStatus.Fail,
                        detail = "arti.status not found",
                    )
                }
                torConfig != null -> {
                    TorPathValidator.validateTorrcContent(
                        torConfig,
                        source = torConfigFile.name,
                        socksPort = runtimePorts?.torSocksPort,
                        dnsPort = runtimePorts?.torDnsPort,
                    )
                }
                else -> {
                    ValidationCheck(
                        id = "tor.config.missing",
                        label = "Tor runtime config",
                        status = ValidationStatus.Fail,
                        detail = "torrc not found",
                    )
                }
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
        hevConfigFile: File?,
    ): ValidationCheck {
        val hev = hevConfigFile?.takeIf { it.isFile }?.readText().orEmpty()
        val hasMapDns = hev.contains("mapdns:")
        val socksToBridge = hev.contains("port: ${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}") ||
            hev.contains("port: ${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}\n") ||
            Regex("""port:\s*${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}\b""").containsMatchIn(hev)
        return when {
            hev.isNotBlank() && hasMapDns -> ValidationCheck(
                id = "dns.mode.mapdns",
                label = "hev FakeDNS disabled (Automap/DNSCrypt only)",
                status = ValidationStatus.Fail,
                detail = "mode=$dnsMode hev.yaml still has mapdns — clearnet/Automap conflict",
                tripsKillSwitch = true,
            )
            hev.isNotBlank() && !socksToBridge -> ValidationCheck(
                id = "dns.mode.mapdns",
                label = "hev FakeDNS disabled (Automap/DNSCrypt only)",
                status = ValidationStatus.Fail,
                detail = "mode=$dnsMode hev socks not aimed at UID bridge :${TunnelEndpoints.SOCKS_UID_BRIDGE_PORT}",
                tripsKillSwitch = true,
            )
            else -> ValidationCheck(
                id = "dns.mode.dnscrypt",
                label = "DNSCrypt-over-Tor (no clearnet DNS)",
                status = ValidationStatus.Pass,
                detail = "mode=$dnsMode: UDP/53 → DNSCrypt via Tor SOCKS; " +
                    "TCP → hev → SocksUidBridge u{uid}; mapdns absent",
                tripsKillSwitch = false,
            )
        }
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
