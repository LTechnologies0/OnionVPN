package ltechnologies.onionphone.onionvpn.core.validation.leak

import android.content.Context
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.core.content.getSystemService
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.PacketFirewall
import timber.log.Timber

/**
 * System-level leak surfaces the TUN cannot fix alone (Tor VPN Threat Model):
 * Always-on/lockdown, Private DNS (DoT), captive portal, HTTP proxy, VPN permission,
 * firewall engine wiring.
 */
object SystemLeakInspector {
    fun inspect(context: Context, killSwitchExpected: Boolean): List<ValidationCheck> {
        OpTrace.debug("validate", "SystemLeakInspector begin killSwitchExpected=$killSwitchExpected")
        val checks = buildList {
            add(checkAlwaysOnLockdown(context, killSwitchExpected))
            add(checkPrivateDns(context))
            add(checkCaptivePortal(context))
            add(checkGlobalHttpProxy(context))
            add(checkVpnPermission(context))
            add(checkFirewallEngine())
            add(checkFirewallProxyCoverage())
        }
        val fails = checks.count { it.status == ValidationStatus.Fail }
        val soft = checks.count {
            it.status == ValidationStatus.Fail && !it.tripsKillSwitch
        }
        Timber.i(
            "SystemLeakInspector done checks=%d fail=%d softFail≈%d",
            checks.size,
            fails,
            soft,
        )
        checks.filter { it.status == ValidationStatus.Fail }.forEach { c ->
            val level = if (c.tripsKillSwitch) "HARD" else "SOFT"
            Timber.w("[%s FAIL] %s: %s", level, c.id, c.detail)
            OpTrace.warn("validate", "[$level] ${c.id}: ${c.detail}")
        }
        return checks
    }

    private fun checkAlwaysOnLockdown(
        context: Context,
        killSwitchExpected: Boolean,
    ): ValidationCheck {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Skipped,
                detail = "API < 29 — enable Always-on VPN manually in system Settings",
                tripsKillSwitch = false,
            )
        }

        val liveAlwaysOn = OnionVpnService.vpnAlwaysOn.value
        val liveLockdown = OnionVpnService.vpnLockdown.value
        val vpnUp = OnionVpnService.vpnEstablished.value
        val alwaysOnPkg = readAlwaysOnPackage(context)
        val ourPkg = context.packageName

        return when {
            !killSwitchExpected -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Skipped,
                detail = "App kill-switch disabled — OS lockdown still recommended",
                tripsKillSwitch = false,
            )
            vpnUp && liveLockdown -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Pass,
                detail = "VpnService.isLockdownEnabled=true alwaysOn=$liveAlwaysOn",
                tripsKillSwitch = false,
            )
            // Soft when Always-on not configured yet (user must opt into OS Lockdown).
            // Hard when Always-on is ON without Lockdown — apps can bindProcessToNetwork past TUN.
            vpnUp && liveAlwaysOn && !liveLockdown -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Fail,
                detail = "Always-on ON but Lockdown OFF — enable “Block connections without VPN” " +
                    "(Privacy Guides / GrapheneOS). Hard kill-switch: clearnet bypass possible.",
                tripsKillSwitch = true,
            )
            alwaysOnPkg == ourPkg && !liveLockdown -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Fail,
                detail = "Always-on=$ourPkg but Lockdown not confirmed — enable " +
                    "“Block connections without VPN”. Hard while Always-on claims ownership.",
                tripsKillSwitch = true,
            )
            // Hard: another app owns Always-on and can displace our TUN.
            alwaysOnPkg != null && alwaysOnPkg != ourPkg -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Fail,
                detail = "Always-on is set to $alwaysOnPkg — switch it to OnionVPN + Lockdown",
                tripsKillSwitch = true,
            )
            else -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Fail,
                detail = "Settings → Network → VPN → OnionVPN → Always-on ON + " +
                    "Block connections without VPN ON (recommended; Soft until set — " +
                    "does not blackhole working Tor)",
                tripsKillSwitch = false,
            )
        }
    }

    private fun checkPrivateDns(context: Context): ValidationCheck {
        val mode = runCatching {
            Settings.Global.getString(context.contentResolver, "private_dns_mode")
        }.getOrNull().orEmpty()

        val cm = context.getSystemService<ConnectivityManager>()
        // Scan all networks — VPN as activeNetwork can hide DoT on the underlying path.
        val privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            cm?.allNetworks?.any { network ->
                cm.getLinkProperties(network)?.isPrivateDnsActive == true
            } == true
        } else {
            false
        }

        // Stock Android often ships mode=opportunistic. That alone must NOT Hard-Block a
        // healthy Tor TUN (false blackhole). Hard only when DoT is actually active or the
        // user forced a Private DNS hostname (Tor VPN §5.2.4 / Privacy Guides).
        val forcedHostname = mode.equals("hostname", ignoreCase = true)
        val riskyActive = privateDnsActive || forcedHostname

        return when {
            riskyActive -> ValidationCheck(
                id = "android.dns.private",
                label = "Android Private DNS (DoT) off",
                status = ValidationStatus.Fail,
                detail = "Private DNS mode='$mode' active=$privateDnsActive — " +
                    "DoT can resolve outside the TUN. Set Private DNS → Off",
                tripsKillSwitch = true,
            )
            mode.equals("opportunistic", ignoreCase = true) -> ValidationCheck(
                id = "android.dns.private",
                label = "Android Private DNS (DoT) off",
                status = ValidationStatus.Fail,
                detail = "Private DNS mode=opportunistic (stock default) — Soft warn; " +
                    "set Off for defense-in-depth. Hard only when DoT is active.",
                tripsKillSwitch = false,
            )
            else -> ValidationCheck(
                id = "android.dns.private",
                label = "Android Private DNS (DoT) off",
                status = ValidationStatus.Pass,
                detail = "Private DNS mode='${mode.ifEmpty { "off/unset" }}'",
                tripsKillSwitch = false,
            )
        }
    }

    /**
     * Captive portal HTTP checks can phone home on the underlying network
     * (local MITM / hotel Wi‑Fi). Prefer mode 0 (ignore).
     */
    private fun checkCaptivePortal(context: Context): ValidationCheck {
        val mode = runCatching {
            Settings.Global.getInt(context.contentResolver, "captive_portal_mode", 1)
        }.getOrDefault(1)
        return if (mode == 0) {
            ValidationCheck(
                id = "android.captive_portal",
                label = "Captive portal detection off",
                status = ValidationStatus.Pass,
                detail = "captive_portal_mode=0",
                tripsKillSwitch = false,
            )
        } else {
            ValidationCheck(
                id = "android.captive_portal",
                label = "Captive portal detection",
                status = ValidationStatus.Skipped,
                detail = "captive_portal_mode=$mode (advisory: set 0 to avoid clearnet probes). " +
                    "ADB: settings put global captive_portal_mode 0",
                tripsKillSwitch = false,
            )
        }
    }

    private fun checkGlobalHttpProxy(context: Context): ValidationCheck {
        val host = runCatching {
            Settings.Global.getString(context.contentResolver, "http_proxy")
        }.getOrNull().orEmpty()
        return if (host.isBlank() || host.equals(":0", ignoreCase = true)) {
            ValidationCheck(
                id = "android.http_proxy",
                label = "No global HTTP proxy",
                status = ValidationStatus.Pass,
                detail = "http_proxy unset",
                tripsKillSwitch = false,
            )
        } else {
            ValidationCheck(
                id = "android.http_proxy",
                label = "No global HTTP proxy",
                status = ValidationStatus.Fail,
                detail = "Global HTTP proxy='$host' — clear it (local MITM risk)",
                tripsKillSwitch = false,
            )
        }
    }

    private fun checkVpnPermission(context: Context): ValidationCheck {
        val needsPrep = VpnService.prepare(context) != null
        return ValidationCheck(
            id = "android.vpn.permission",
            label = "VPN permission granted",
            status = if (needsPrep) ValidationStatus.Fail else ValidationStatus.Pass,
            detail = if (needsPrep) "User must approve VPN" else "VpnService.prepare() == null",
            tripsKillSwitch = true,
        )
    }

    private fun checkFirewallEngine(): ValidationCheck {
        val wired = FirewallBridge.engine !== PacketFirewall.AllowAll
        return ValidationCheck(
            id = "firewall.engine",
            label = "Interactive firewall engine wired",
            status = if (wired) ValidationStatus.Pass else ValidationStatus.Fail,
            detail = if (wired) {
                "FirewallBridge != AllowAll — enable in Settings for OpenSnitch-style prompts; " +
                    "UDP/ICMP kill-switch is always enforced by LeakPacketFilter"
            } else {
                "FirewallBridge still AllowAll — Application did not install engine"
            },
            tripsKillSwitch = false,
        )
    }

    /**
     * Residual: raw Tor/onionmasq SocksPort on 127.0.0.1 accepts any local process
     * (SocksPolicy is IP-only). TUN + PAC + SocksUidBridge are firewalled; a hostile
     * app that dials the ephemeral SocksPort with forged `u{uid}/p{uid}` skips ASK/DENY.
     * Still Tor-routed (not clearnet), but policy bypass.
     */
    private fun checkFirewallProxyCoverage(): ValidationCheck {
        val wired = FirewallBridge.engine !== PacketFirewall.AllowAll
        return ValidationCheck(
            id = "firewall.proxy_coverage",
            label = "Firewall covers TUN/PAC/UID-bridge (not raw Tor SOCKS)",
            status = if (wired) ValidationStatus.Pass else ValidationStatus.Skipped,
            detail = "Gated: TunDnsMux allowOutbound, PAC allowSocksConnect, SocksUidBridge " +
                "peer-UID + allowSocksConnect, ArtiSocksRoleMux peer-UID. Residual: apps may " +
                "dial C Tor / onionmasq sidecar SocksPort on loopback with forged IsolateSOCKSAuth " +
                "(predictable u{uid}/p{uid}). Traffic stays on Tor — not a clearnet leak.",
            tripsKillSwitch = false,
        )
    }

    private fun readAlwaysOnPackage(context: Context): String? {
        return runCatching {
            Settings.Secure.getString(context.contentResolver, "always_on_vpn_app")
        }.getOrNull()?.takeIf { it.isNotBlank() && it.contains('.') }
    }
}
