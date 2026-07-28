package ltechnologies.onionphone.onionvpn.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import ltechnologies.onionphone.onionvpn.MainActivity
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase

/**
 * Foreground notification + channel for [TunnelForegroundService].
 *
 * Separated so the service orchestrator stays a sequential pipeline, not UI glue.
 */
internal class TunnelNotifications(
    private val service: Service,
) {
    fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            service.getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = service.getString(R.string.notification_channel_desc)
            setShowBadge(false)
        }
        service.getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    fun startForeground(phase: TunnelPhase, throughputText: String) {
        val notification = build(phase, throughputText)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            service.startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            service.startForeground(NOTIFICATION_ID, notification)
        }
    }

    fun update(phase: TunnelPhase, throughputText: String) {
        service.getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, build(phase, throughputText))
    }

    fun build(phase: TunnelPhase, throughputText: String): Notification {
        val openIntent = PendingIntent.getActivity(
            service, 0,
            Intent(service, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            service, 1,
            Intent(service, TunnelForegroundService::class.java)
                .setAction(TunnelForegroundService.ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val phaseText = when (phase) {
            TunnelPhase.Connected -> service.getString(R.string.notification_connected)
            TunnelPhase.Blocking -> service.getString(R.string.notification_blocking)
            TunnelPhase.Error -> service.getString(R.string.notification_error)
            TunnelPhase.Stopping -> service.getString(R.string.notification_stopping)
            else -> service.getString(R.string.notification_starting)
        }
        val content = if (phase == TunnelPhase.Connected && throughputText.isNotBlank()) {
            throughputText
        } else {
            phaseText
        }
        return NotificationCompat.Builder(service, CHANNEL_ID)
            .setContentTitle(
                when (phase) {
                    TunnelPhase.Connected -> service.getString(R.string.notification_connected)
                    TunnelPhase.Blocking -> service.getString(R.string.notification_blocking)
                    else -> service.getString(R.string.app_name)
                },
            )
            .setContentText(content)
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setSmallIcon(R.drawable.ic_vpn_notification)
            .setOngoing(phase.isActiveNotification)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, service.getString(R.string.action_stop), stopIntent)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private val TunnelPhase.isActiveNotification: Boolean
        get() = when (this) {
            TunnelPhase.Idle, TunnelPhase.Error, TunnelPhase.Stopping -> false
            else -> true
        }

    companion object {
        const val CHANNEL_ID = "onionvpn_tunnel"
        const val NOTIFICATION_ID = 42
    }
}
