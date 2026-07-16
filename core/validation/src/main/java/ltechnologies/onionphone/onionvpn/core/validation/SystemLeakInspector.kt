package ltechnologies.onionphone.onionvpn.core.validation

import android.content.Context
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import androidx.core.content.getSystemService
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService

/**
 * System-level leak surfaces the TUN cannot fix alone (Tor VPN Threat Model):
 * Always-on/lockdown (from live VpnService when possible), Private DNS (DoT), VPN permission.
 */
object SystemLeakInspector {
    fun inspect(context: Context, killSwitchExpected: Boolean): List<ValidationCheck> {
        return buildList {
            add(checkAlwaysOnLockdown(context, killSwitchExpected))
            add(checkPrivateDns(context))
            add(checkVpnPermission(context))
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

        // Prefer live VpnService flags (Orbot/Mullvad) over Settings.Secure scraping.
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

    private fun readAlwaysOnPackage(context: Context): String? {
        return runCatching {
            Settings.Secure.getString(context.contentResolver, "always_on_vpn_app")
        }.getOrNull()?.takeIf { it.isNotBlank() && it.contains('.') }
    }
}
