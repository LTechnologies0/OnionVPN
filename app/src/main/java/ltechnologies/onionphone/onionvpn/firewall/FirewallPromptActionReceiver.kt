package ltechnologies.onionphone.onionvpn.firewall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import timber.log.Timber

/**
 * Handles Accept / Deny actions on the firewall request notification.
 * Defaults to permanent rules — finer scopes remain available in the Firewall screen.
 */
@AndroidEntryPoint
class FirewallPromptActionReceiver : BroadcastReceiver() {
    @Inject lateinit var engine: InteractiveFirewallEngine

    override fun onReceive(context: Context, intent: Intent?) {
        val requestId = intent?.getStringExtra(EXTRA_REQUEST_ID)?.takeIf { it.isNotBlank() }
        if (requestId == null) {
            Timber.w("Firewall action missing requestId")
            return
        }
        val verdict = when (intent.action) {
            ACTION_ALLOW -> FirewallVerdict.ALLOW
            ACTION_DENY -> FirewallVerdict.DENY
            else -> {
                Timber.w("Unknown firewall action ${intent.action}")
                return
            }
        }
        engine.answerPrompt(requestId, verdict, FirewallRuleScope.PERMANENT)
    }

    companion object {
        const val ACTION_ALLOW = "ltechnologies.onionphone.onionvpn.firewall.ALLOW"
        const val ACTION_DENY = "ltechnologies.onionphone.onionvpn.firewall.DENY"
        const val EXTRA_REQUEST_ID = "request_id"
    }
}
