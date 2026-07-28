package ltechnologies.onionphone.onionvpn.firewall

import android.app.ActivityOptions
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import timber.log.Timber

/**
 * System-visible firewall prompt when BAL blocks bare [Context.startActivity].
 *
 * Priority order:
 * 1. [FirewallOverlayController] TYPE_APPLICATION_OVERLAY (true popup over launcher)
 * 2. Full-screen intent + MAX priority heads-up (call-style)
 * 3. Best-effort startActivity from FGS / BAL options
 */
internal class FirewallPromptNotifier(
    private val context: Context,
    private val answerHandler: (requestId: String, verdict: FirewallVerdict, scope: FirewallRuleScope) -> Unit,
    private val tempMinutesProvider: () -> Int = { 5 },
) {
    private val appContext = context.applicationContext
    private val nm = appContext.getSystemService(NotificationManager::class.java)
    private val overlay = FirewallOverlayController(appContext, answerHandler)

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
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                setAllowBubbles(true)
            }
        }
        nm.createNotificationChannel(channel)
    }

    fun canUseFullScreenIntent(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            nm.canUseFullScreenIntent()
        } else {
            true
        }

    fun canDrawOverlays(): Boolean = overlay.canDrawOverlays()

    fun openOverlayPermissionSettings() = overlay.openOverlaySettings()

    fun openFullScreenIntentSettings() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        runCatching {
            val intent = Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT)
                .setData(android.net.Uri.parse("package:${appContext.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            appContext.startActivity(intent)
        }.onFailure { Timber.w(it, "Cannot open FSI settings") }
    }

    fun show(info: FirewallConnectionInfo) {
        ensureChannel()
        // 1) Real system overlay when permitted — works over launcher without opening app.
        if (overlay.canDrawOverlays()) {
            overlay.show(info, tempMinutesProvider())
        }
        // 2) Always post a high-priority notification + FSI as belt-and-suspenders.
        val content = appContext.getString(
            R.string.firewall_prompt_notif_text,
            info.appLabel,
            info.protocolLabel,
            info.destIp,
            info.destPort,
        )
        val pending = promptPendingIntent(info.requestId)
        val builder = NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setContentTitle(appContext.getString(R.string.firewall_prompt_notif_title))
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setContentIntent(pending)
            .setOngoing(true)
            .setAutoCancel(false)
            .setOnlyAlertOnce(false)
            .setTimeoutAfter(0)
            .addAction(
                0,
                appContext.getString(R.string.firewall_action_open),
                pending,
            )
        if (canUseFullScreenIntent()) {
            builder.setFullScreenIntent(pending, true)
        } else {
            Timber.w("Full-screen intent disabled — overlay/notification only")
        }
        try {
            NotificationManagerCompat.from(appContext).notify(NOTIFICATION_ID, builder.build())
        } catch (error: SecurityException) {
            Timber.w(error, "Firewall prompt notification blocked (POST_NOTIFICATIONS?)")
        }
        // 3) Best-effort direct activity launch (often blocked by BAL — OK).
        if (!overlay.canDrawOverlays()) {
            launchActivity(info.requestId)
        }
    }

    fun cancel() {
        overlay.dismiss()
        NotificationManagerCompat.from(appContext).cancel(NOTIFICATION_ID)
    }

    private fun launchActivity(requestId: String) {
        // Direct startActivity — do not pass PendingIntent BAL options here.
        // Those modes are only valid when creating/sending a PendingIntent.
        try {
            appContext.startActivity(promptIntent(requestId))
        } catch (error: Exception) {
            Timber.w(error, "Direct firewall prompt launch failed; relying on overlay/FSI")
        }
    }

    private fun promptIntent(requestId: String): Intent =
        Intent(appContext, FirewallPromptActivity::class.java).apply {
            addFlags(
                Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP or
                    Intent.FLAG_ACTIVITY_CLEAR_TOP or
                    Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or
                    Intent.FLAG_ACTIVITY_NO_USER_ACTION,
            )
            putExtra(FirewallPromptActivity.EXTRA_REQUEST_ID, requestId)
        }

    private fun promptPendingIntent(requestId: String): PendingIntent {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val intent = promptIntent(requestId)
        // Creator opt-in (API 34+): grant our BAL privileges to SystemUI when it
        // sends this PI. setPendingIntentBackgroundActivityStartMode is for the
        // *sender* only — using it at create time crashes on Android 15+ (IAE).
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val opts = ActivityOptions.makeBasic().apply {
                setPendingIntentCreatorBackgroundActivityStartMode(
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
