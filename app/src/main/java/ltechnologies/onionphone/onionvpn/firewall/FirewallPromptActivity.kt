package ltechnologies.onionphone.onionvpn.firewall

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.delay
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.ui.theme.OnionVpnTheme

@AndroidEntryPoint
class FirewallPromptActivity : ComponentActivity() {
    @Inject lateinit var engine: InteractiveFirewallEngine
    @Inject lateinit var preferencesStore: TunnelPreferencesStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        }
        setContent {
            OnionVpnTheme {
                Surface {
                    val prompt by engine.pendingPrompt.collectAsStateWithLifecycle()
                    val prefs by preferencesStore.preferences.collectAsState(
                        initial = TunnelPreferences(),
                    )
                    val wantedId = intent?.getStringExtra(EXTRA_REQUEST_ID)
                    LaunchedEffect(prompt, wantedId) {
                        if (prompt == null) {
                            // Avoid finishing on a brief null flicker when promoting the queue.
                            delay(400)
                            if (engine.pendingPrompt.value == null) finish()
                            return@LaunchedEffect
                        }
                        // Stale notification for an already-answered request: ignore and wait
                        // for the live pending head (or finish if queue emptied).
                        if (wantedId != null && prompt!!.requestId != wantedId) {
                            // Still show current pending — FIFO head is what the user must answer.
                        }
                    }
                    val current = prompt
                    if (current != null) {
                        FirewallPromptContent(
                            info = current,
                            tempMinutes = prefs.firewallTempMinutes,
                            onAnswer = { verdict, scope ->
                                engine.answerPrompt(current.requestId, verdict, scope)
                            },
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    companion object {
        const val EXTRA_REQUEST_ID = "firewall_request_id"
    }
}
