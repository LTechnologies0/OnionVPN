package ltechnologies.onionphone.onionvpn.firewall

import android.app.ActivityOptions
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import timber.log.Timber

/**
 * Reliable prompt surface when BAL blocks bare [Context.startActivity].
 *
 * Uses a high-importance channel + [NotificationCompat.Builder.setFullScreenIntent]
 * (OpenSnitch / call-style pattern) so the prompt can appear over other apps.
 */
internal class FirewallPromptNotifier(
    private val context: Context,
) {
    private val appContext = context.applicationContext
    private val nm = appContext.getSystemService(NotificationManager::class.java)

    fun ensureChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            appContext.getString(R.string.firewall_prompt_channel_name),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = appContext.getString(R.string.firewall_prompt_channel_desc)
            setShowBadge(true)
            enableVibration(true)
            lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
        }
        nm.createNotificationChannel(channel)
    }

    fun show(info: FirewallConnectionInfo) {
        ensureChannel()
        val content = appContext.getString(
            R.string.firewall_prompt_notif_text,
            info.appLabel,
            info.protocolLabel,
            info.destIp,
            info.destPort,
        )
        val pending = promptPendingIntent(info.requestId)
        val notification = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(appContext.getString(R.string.firewall_prompt_notif_title))
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(pending)
            .setFullScreenIntent(pending, true)
            .setOngoing(true)
            .setAutoCancel(false)
            .setOnlyAlertOnce(false)
            .build()
        try {
            NotificationManagerCompat.from(appContext).notify(NOTIFICATION_ID, notification)
        } catch (error: SecurityException) {
            Timber.w(error, "Firewall prompt notification blocked (POST_NOTIFICATIONS?)")
        }
        // Best-effort direct launch; FSI covers the cases BAL denies.
        launchActivity(info.requestId)
    }

    fun cancel() {
        NotificationManagerCompat.from(appContext).cancel(NOTIFICATION_ID)
    }

    private fun launchActivity(requestId: String) {
        try {
            val intent = promptIntent(requestId)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val opts = ActivityOptions.makeBasic().apply {
                    setPendingIntentBackgroundActivityStartMode(
                        ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED,
                    )
                }
                appContext.startActivity(intent, opts.toBundle())
            } else {
                appContext.startActivity(intent)
            }
        } catch (error: Exception) {
            Timber.w(error, "Direct firewall prompt launch failed; relying on notification/FSI")
        }
    }

    private fun promptIntent(requestId: String): Intent =
        Intent(appContext, FirewallPromptActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_REORDER_TO_FRONT,
            )
            putExtra(FirewallPromptActivity.EXTRA_REQUEST_ID, requestId)
        }

    private fun promptPendingIntent(requestId: String): PendingIntent {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val intent = promptIntent(requestId)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val opts = ActivityOptions.makeBasic().apply {
                setPendingIntentBackgroundActivityStartMode(
                    ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED,
                )
            }
            PendingIntent.getActivity(appContext, REQUEST_CODE, intent, flags, opts.toBundle())
        } else {
            PendingIntent.getActivity(appContext, REQUEST_CODE, intent, flags)
        }
    }

    companion object {
        const val CHANNEL_ID = "onionvpn_firewall_prompt"
        const val NOTIFICATION_ID = 43
        private const val REQUEST_CODE = 4301
    }
}
