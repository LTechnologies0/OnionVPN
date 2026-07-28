package ltechnologies.onionphone.onionvpn.firewall

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import timber.log.Timber

/**
 * True system overlay for firewall prompts (OpenSnitch-style) when
 * [Settings.canDrawOverlays] is granted. Works over the launcher / other apps
 * without opening MainActivity.
 *
 * Falls back is handled by [FirewallPromptNotifier] (FSI notification).
 */
internal class FirewallOverlayController(
    private val context: Context,
    private val onAnswer: (requestId: String, verdict: FirewallVerdict, scope: FirewallRuleScope) -> Unit,
) {
    private val appContext = context.applicationContext
    private val wm = appContext.getSystemService(WindowManager::class.java)
    private var overlayView: android.view.View? = null

    fun canDrawOverlays(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Settings.canDrawOverlays(appContext)
        } else {
            true
        }

    fun openOverlaySettings() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        val intent = Intent(
            Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
            Uri.parse("package:${appContext.packageName}"),
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { appContext.startActivity(intent) }
            .onFailure { Timber.w(it, "Cannot open overlay settings") }
    }

    @SuppressLint("ClickableViewAccessibility")
    fun show(info: FirewallConnectionInfo, tempMinutes: Int) {
        if (!canDrawOverlays()) return
        dismiss()
        val pad = (16 * appContext.resources.displayMetrics.density).toInt()
        val root = ScrollView(appContext).apply {
            setBackgroundColor(0xF0FFFFFF.toInt())
            setPadding(pad, pad, pad, pad)
        }
        val col = LinearLayout(appContext).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        fun addText(text: String, sizeSp: Float, color: Int = 0xFF0F1A16.toInt()) {
            col.addView(
                TextView(appContext).apply {
                    this.text = text
                    textSize = sizeSp
                    setTextColor(color)
                    setPadding(0, 0, 0, pad / 2)
                },
            )
        }
        addText("Connection request", 20f)
        addText("${info.appLabel}\n${info.packageName}\nUID ${info.uid}", 14f, 0xFF3D4F47.toInt())
        addText("${info.protocolLabel} → ${info.destIp}:${info.destPort}", 16f)
        addText("No timeout — stays until you choose.", 12f, 0xFF3D4F47.toInt())

        fun addBtn(label: String, bg: Int, action: () -> Unit) {
            col.addView(
                Button(appContext).apply {
                    text = label
                    setBackgroundColor(bg)
                    setTextColor(0xFFFFFFFF.toInt())
                    setOnClickListener {
                        action()
                        dismiss()
                    }
                    val lp = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    )
                    lp.topMargin = pad / 3
                    layoutParams = lp
                },
            )
        }
        val green = 0xFF1B4332.toInt()
        val red = 0xFFB3261E.toInt()
        addBtn("Allow permanently", green) {
            onAnswer(info.requestId, FirewallVerdict.ALLOW, FirewallRuleScope.PERMANENT)
        }
        addBtn("Allow until VPN stops", green) {
            onAnswer(info.requestId, FirewallVerdict.ALLOW, FirewallRuleScope.SESSION)
        }
        addBtn("Allow for $tempMinutes min", green) {
            onAnswer(info.requestId, FirewallVerdict.ALLOW, FirewallRuleScope.TEMPORARY)
        }
        addBtn("Deny for $tempMinutes min", red) {
            onAnswer(info.requestId, FirewallVerdict.DENY, FirewallRuleScope.TEMPORARY)
        }
        addBtn("Deny until VPN stops", red) {
            onAnswer(info.requestId, FirewallVerdict.DENY, FirewallRuleScope.SESSION)
        }
        addBtn("Deny permanently", red) {
            onAnswer(info.requestId, FirewallVerdict.DENY, FirewallRuleScope.PERMANENT)
        }
        root.addView(col)

        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.CENTER
            title = appContext.getString(R.string.firewall_prompt_notif_title)
        }
        try {
            wm.addView(root, params)
            overlayView = root
            Timber.i("Firewall overlay shown for %s", info.appLabel)
        } catch (error: Exception) {
            Timber.w(error, "Firewall overlay addView failed")
            overlayView = null
        }
    }

    fun dismiss() {
        val v = overlayView ?: return
        overlayView = null
        runCatching { wm.removeView(v) }
    }
}
