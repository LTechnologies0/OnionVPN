package ltechnologies.onionphone.onionvpn.firewall

import android.app.ActivityOptions
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.graphics.createBitmap
import androidx.core.graphics.drawable.IconCompat
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import timber.log.Timber

/**
 * Heads-up firewall request notification with Accept / Deny actions and the
 * requesting app's icon. No overlay / full-screen popup.
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
            enableLights(true)
            lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
        }
        nm.createNotificationChannel(channel)
    }

    fun show(info: FirewallConnectionInfo) {
        ensureChannel()
        val dest = info.displayDestination()
        val content = appContext.getString(
            R.string.firewall_prompt_notif_text,
            info.protocolLabel,
            dest,
            info.destPort,
        )
        val openPending = detailPendingIntent(info.requestId)
        val allowPending = actionPendingIntent(
            FirewallPromptActionReceiver.ACTION_ALLOW,
            info.requestId,
            REQUEST_ALLOW,
        )
        val denyPending = actionPendingIntent(
            FirewallPromptActionReceiver.ACTION_DENY,
            info.requestId,
            REQUEST_DENY,
        )
        val appIcon = loadAppIcon(info.packageName)
        val builder = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setContentTitle(
                appContext.getString(R.string.firewall_prompt_notif_title, info.appLabel),
            )
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(openPending)
            .setOngoing(true)
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .addAction(
                0,
                appContext.getString(R.string.firewall_action_allow),
                allowPending,
            )
            .addAction(
                0,
                appContext.getString(R.string.firewall_action_deny),
                denyPending,
            )
        if (appIcon != null) {
            builder.setLargeIcon(appIcon)
            builder.setSmallIcon(IconCompat.createWithBitmap(appIcon))
        } else {
            builder.setSmallIcon(R.drawable.ic_vpn_notification)
        }
        try {
            NotificationManagerCompat.from(appContext).notify(NOTIFICATION_ID, builder.build())
        } catch (error: SecurityException) {
            Timber.w(error, "Firewall prompt notification blocked (POST_NOTIFICATIONS?)")
        }
    }

    fun cancel() {
        NotificationManagerCompat.from(appContext).cancel(NOTIFICATION_ID)
    }

    private fun detailIntent(requestId: String): Intent =
        Intent(appContext, FirewallPromptActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP,
            )
            putExtra(FirewallPromptActivity.EXTRA_REQUEST_ID, requestId)
        }

    private fun detailPendingIntent(requestId: String): PendingIntent {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val intent = detailIntent(requestId)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val opts = ActivityOptions.makeBasic().apply {
                setPendingIntentCreatorBackgroundActivityStartMode(
                    ActivityOptions.MODE_BACKGROUND_ACTIVITY_START_ALLOWED,
                )
            }
            PendingIntent.getActivity(appContext, REQUEST_OPEN, intent, flags, opts.toBundle())
        } else {
            PendingIntent.getActivity(appContext, REQUEST_OPEN, intent, flags)
        }
    }

    private fun actionPendingIntent(action: String, requestId: String, requestCode: Int): PendingIntent {
        val intent = Intent(appContext, FirewallPromptActionReceiver::class.java).apply {
            this.action = action
            setPackage(appContext.packageName)
            putExtra(FirewallPromptActionReceiver.EXTRA_REQUEST_ID, requestId)
        }
        return PendingIntent.getBroadcast(
            appContext,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun loadAppIcon(packageName: String): Bitmap? {
        if (packageName.isBlank()) return null
        return runCatching {
            val drawable = appContext.packageManager.getApplicationIcon(packageName)
            drawableToBitmap(drawable)
        }.onFailure { Timber.d(it, "No icon for $packageName") }.getOrNull()
    }

    private fun drawableToBitmap(drawable: Drawable): Bitmap {
        if (drawable is BitmapDrawable && drawable.bitmap != null) {
            return drawable.bitmap
        }
        val density = appContext.resources.displayMetrics.density
        val size = (64 * density).toInt().coerceIn(96, 256)
        val bitmap = createBitmap(size, size)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        return bitmap
    }

    companion object {
        const val CHANNEL_ID = "onionvpn_firewall_prompt_v2"
        const val NOTIFICATION_ID = 43
        private const val REQUEST_OPEN = 4301
        private const val REQUEST_ALLOW = 4302
        private const val REQUEST_DENY = 4303
    }
}
