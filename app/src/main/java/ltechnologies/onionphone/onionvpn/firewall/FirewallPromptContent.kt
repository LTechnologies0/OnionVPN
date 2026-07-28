package ltechnologies.onionphone.onionvpn.firewall

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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict

@Composable
fun FirewallPromptContent(
    info: FirewallConnectionInfo,
    tempMinutes: Int,
    onAnswer: (verdict: FirewallVerdict, scope: FirewallRuleScope) -> Unit,
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
                        contentDescription = info.appLabel,
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
            "No timeout — this stays queued until you choose.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Button(
            onClick = { onAnswer(FirewallVerdict.ALLOW, FirewallRuleScope.PERMANENT) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Allow permanently")
        }
        OutlinedButton(
            onClick = { onAnswer(FirewallVerdict.ALLOW, FirewallRuleScope.SESSION) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Allow until VPN stops")
        }
        OutlinedButton(
            onClick = { onAnswer(FirewallVerdict.ALLOW, FirewallRuleScope.TEMPORARY) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Allow for $tempMinutes min")
        }
        OutlinedButton(
            onClick = { onAnswer(FirewallVerdict.DENY, FirewallRuleScope.TEMPORARY) },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = MaterialTheme.colorScheme.error,
            ),
        ) {
            Text("Deny for $tempMinutes min")
        }
        OutlinedButton(
            onClick = { onAnswer(FirewallVerdict.DENY, FirewallRuleScope.SESSION) },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = MaterialTheme.colorScheme.error,
            ),
        ) {
            Text("Deny until VPN stops")
        }
        Button(
            onClick = { onAnswer(FirewallVerdict.DENY, FirewallRuleScope.PERMANENT) },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
            ),
        ) {
            Text("Deny permanently")
        }
    }
}
