package ltechnologies.onionphone.onionvpn.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import androidx.core.content.getSystemService

/**
 * OnionShare / Briar-style Doze whitelist: OS dialog via
 * [Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS].
 *
 * Keeps Tor/DNSCrypt alive under OEM Doze after the VPN FGS is up.
 * User can deny — tunnel start must still proceed (same as OnionShare).
 */
object BatteryOptimization {
    fun needsWhitelisting(context: Context): Boolean {
        val pm = context.getSystemService<PowerManager>() ?: return false
        return !pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /** System permission dialog for this package. May throw if Activity missing. */
    @SuppressLint("BatteryLife")
    fun requestIgnoreIntent(context: Context): Intent =
        Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
        }

    /** Settings screen fallback when the one-shot dialog is unavailable. */
    fun openAppBatterySettings(context: Context): Boolean = try {
        val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
        true
    } catch (_: Exception) {
        try {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            true
        } catch (_: Exception) {
            false
        }
    }
}
