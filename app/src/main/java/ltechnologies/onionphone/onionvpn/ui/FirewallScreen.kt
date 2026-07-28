package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import ltechnologies.onionphone.onionvpn.core.model.FirewallJournalEntry
import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine

@Composable
fun FirewallScreen(
    engine: InteractiveFirewallEngine,
) {
    val journal by engine.journal.collectAsStateWithLifecycle()
    val rules by engine.rulesFlow().collectAsStateWithLifecycle()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Firewall journal", style = MaterialTheme.typography.titleLarge)
        Text(
            "Interactive decisions for outbound connections through Tor.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (rules.isNotEmpty()) {
            Text("Active rules", style = MaterialTheme.typography.titleMedium)
            LazyColumn(
                modifier = Modifier.weight(0.35f, fill = false),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                items(rules, key = { it.id }) { rule ->
                    RuleRow(rule = rule, onDelete = { engine.deleteRule(rule.id) })
                }
            }
        }

        Text("Timeline", style = MaterialTheme.typography.titleMedium)
        if (journal.isEmpty()) {
            Text(
                "No decisions yet. Enable the firewall in Settings, then start the VPN.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(journal, key = { it.id }) { entry ->
                    JournalRow(entry)
                }
            }
        }
    }
}

@Composable
private fun RuleRow(rule: FirewallRule, onDelete: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "${rule.appLabel} → ${destLabel(rule)}",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "${rule.verdict} · ${rule.scope}",
                style = MaterialTheme.typography.labelSmall,
                color = if (rule.verdict == FirewallVerdict.ALLOW) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.error
                },
            )
        }
        TextButton(onClick = onDelete) { Text("Delete") }
    }
}

@Composable
private fun JournalRow(entry: FirewallJournalEntry) {
    val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        .format(Date(entry.timestampEpochMs))
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            "$time  ${entry.verdict}  ${entry.appLabel}",
            style = MaterialTheme.typography.bodyMedium,
            color = if (entry.verdict == FirewallVerdict.ALLOW) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.error
            },
        )
        Text(
            "${entry.protocolLabel} ${entry.destIp}:${entry.destPort}" +
                if (entry.note.isNotBlank()) " · ${entry.note}" else "",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun destLabel(rule: FirewallRule): String {
    val host = rule.destHost.ifEmpty { "*" }
    val port = if (rule.destPort < 0) "*" else rule.destPort.toString()
    return "$host:$port"
}
