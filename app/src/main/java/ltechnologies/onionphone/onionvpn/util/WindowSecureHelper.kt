package ltechnologies.onionphone.onionvpn.util

import android.app.Activity
import android.view.WindowManager

/** Applies [WindowManager.LayoutParams.FLAG_SECURE] to block screenshots / recents previews. */
object WindowSecureHelper {
    fun apply(activity: Activity, allowScreenshots: Boolean) {
        if (allowScreenshots) {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        }
    }
}
