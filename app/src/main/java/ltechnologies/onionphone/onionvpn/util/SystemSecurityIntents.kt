package ltechnologies.onionphone.onionvpn.util

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import timber.log.Timber

/**
 * Deep-links into Android / GrapheneOS settings that OnionVPN cannot change itself
 * (Always-on VPN, Block connections without VPN, Private DNS).
 *
 * Aligns with GrapheneOS “Improved VPN leak blocking” guidance: Always-on + lockdown.
 */
object SystemSecurityIntents {
    fun openVpnSettings(context: Context): Boolean =
        start(context, Intent(Settings.ACTION_VPN_SETTINGS))

    fun openPrivateDnsSettings(context: Context): Boolean {
        // No public ACTION_PRIVATE_DNS; Settings.ACTION_WIRELESS_SETTINGS is closest portable.
        val candidates = buildList {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                add(Intent(Settings.ACTION_WIRELESS_SETTINGS))
            }
            add(Intent(Settings.ACTION_WIRELESS_SETTINGS))
            add(Intent(Settings.ACTION_SETTINGS))
        }
        return candidates.any { start(context, it) }
    }

    fun openSecuritySettings(context: Context): Boolean =
        start(context, Intent(Settings.ACTION_SECURITY_SETTINGS))

    private fun start(context: Context, intent: Intent): Boolean = try {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
        true
    } catch (error: Exception) {
        Timber.w(error, "Cannot open ${intent.action}")
        false
    }
}
