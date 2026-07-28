package ltechnologies.onionphone.onionvpn.firewall

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore

@AndroidEntryPoint
class FirewallPromptActivity : ComponentActivity() {
    @Inject lateinit var engine: InteractiveFirewallEngine
    @Inject lateinit var preferencesStore: TunnelPreferencesStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface {
                    val prompt by engine.pendingPrompt.collectAsStateWithLifecycle()
                    val prefs by preferencesStore.preferences.collectAsState(
                        initial = TunnelPreferences(),
                    )
                    LaunchedEffect(prompt) {
                        if (prompt == null) finish()
                    }
                    val current = prompt
                    if (current != null) {
                        FirewallPromptContent(
                            info = current,
                            tempMinutes = prefs.firewallTempMinutes,
                            onAllow = { temporary ->
                                engine.answerPrompt(current.requestId, FirewallVerdict.ALLOW, temporary)
                                finish()
                            },
                            onDeny = { temporary ->
                                engine.answerPrompt(current.requestId, FirewallVerdict.DENY, temporary)
                                finish()
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
}

@Composable
private fun FirewallPromptContent(
    info: FirewallConnectionInfo,
    tempMinutes: Int,
    onAllow: (temporary: Boolean) -> Unit,
    onDeny: (temporary: Boolean) -> Unit,
) {
    val context = LocalContext.current
    val icon = runCatching {
        context.packageManager.getApplicationIcon(info.packageName).toBitmap(96, 96).asImageBitmap()
    }.getOrNull()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Connection request", style = MaterialTheme.typography.headlineSmall)
        Text(
            "A new outbound connection wants to leave through Tor.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Card(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (icon != null) {
                    Image(
                        bitmap = icon,
                        contentDescription = null,
                        modifier = Modifier.size(48.dp),
                    )
                }
                Column {
                    Text(info.appLabel, style = MaterialTheme.typography.titleMedium)
                    Text(
                        info.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text("UID ${info.uid}", style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        Text(
            "${info.protocolLabel} → ${info.destIp}:${info.destPort}",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            "Timeout without answer = deny (least privilege).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Button(
            onClick = { onAllow(false) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Allow permanently")
        }
        OutlinedButton(
            onClick = { onAllow(true) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Allow for $tempMinutes min")
        }
        OutlinedButton(
            onClick = { onDeny(true) },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = MaterialTheme.colorScheme.error,
            ),
        ) {
            Text("Deny for $tempMinutes min")
        }
        Button(
            onClick = { onDeny(false) },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
            ),
        ) {
            Text("Deny permanently")
        }
    }
}
