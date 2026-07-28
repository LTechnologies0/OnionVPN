package ltechnologies.onionphone.onionvpn.core.validation.leak

import android.content.Context
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.core.content.getSystemService
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.PacketFirewall

/**
 * System-level leak surfaces the TUN cannot fix alone (Tor VPN Threat Model):
 * Always-on/lockdown, Private DNS (DoT), captive portal, HTTP proxy, VPN permission,
 * firewall engine wiring.
 */
object SystemLeakInspector {
    fun inspect(context: Context, killSwitchExpected: Boolean): List<ValidationCheck> {
        return buildList {
            add(checkAlwaysOnLockdown(context, killSwitchExpected))
            add(checkPrivateDns(context))
            add(checkCaptivePortal(context))
            add(checkGlobalHttpProxy(context))
            add(checkVpnPermission(context))
            add(checkFirewallEngine())
        }
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
            vpnUp && liveAlwaysOn && !liveLockdown -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Fail,
                detail = "Always-on ON but Lockdown OFF — enable “Block connections without VPN”",
                tripsKillSwitch = false,
            )
            alwaysOnPkg == ourPkg -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Pass,
                detail = "Always-on=$ourPkg — confirm Lockdown is ON",
                tripsKillSwitch = false,
            )
            alwaysOnPkg != null -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Fail,
                detail = "Always-on is set to $alwaysOnPkg — switch it to OnionVPN + Lockdown",
                tripsKillSwitch = true,
            )
            else -> ValidationCheck(
                id = "android.vpn.always_on",
                label = "Android Always-on VPN lockdown",
                status = ValidationStatus.Skipped,
                detail = "Settings → Network → VPN → OnionVPN → Always-on ON + " +
                    "Block connections without VPN ON",
                tripsKillSwitch = false,
            )
        }
    }

    private fun checkPrivateDns(context: Context): ValidationCheck {
        val mode = runCatching {
            Settings.Global.getString(context.contentResolver, "private_dns_mode")
        }.getOrNull().orEmpty()

        val cm = context.getSystemService<ConnectivityManager>()
        val privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            cm?.activeNetwork?.let { network ->
                cm.getLinkProperties(network)?.isPrivateDnsActive == true
            } == true
        } else {
            false
        }

        val risky = mode.equals("hostname", ignoreCase = true) ||
            mode.equals("opportunistic", ignoreCase = true) ||
            privateDnsActive

        return if (risky) {
            ValidationCheck(
                id = "android.dns.private",
                label = "Android Private DNS (DoT) off",
                status = ValidationStatus.Fail,
                detail = "Private DNS mode='$mode' active=$privateDnsActive — " +
                    "DoT can resolve outside the TUN (Tor VPN §5.2.4). Set Private DNS → Off",
                tripsKillSwitch = false,
            )
        } else {
            ValidationCheck(
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
                label = "Captive portal detection off",
                status = ValidationStatus.Fail,
                detail = "captive_portal_mode=$mode — probes may leak on underlying net. " +
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
                "FirewallBridge != AllowAll (enable in Settings to enforce)"
            } else {
                "FirewallBridge still AllowAll — Application did not install engine"
            },
            tripsKillSwitch = false,
        )
    }

    private fun readAlwaysOnPackage(context: Context): String? {
        return runCatching {
            Settings.Secure.getString(context.contentResolver, "always_on_vpn_app")
        }.getOrNull()?.takeIf { it.isNotBlank() && it.contains('.') }
    }
}
