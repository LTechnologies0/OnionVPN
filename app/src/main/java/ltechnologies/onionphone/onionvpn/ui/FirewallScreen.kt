package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
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
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.firewall.FirewallPromptContent
import ltechnologies.onionphone.onionvpn.firewall.InteractiveFirewallEngine

@Composable
fun FirewallScreen(
    engine: InteractiveFirewallEngine,
    preferences: TunnelPreferences,
) {
    val journal by engine.journal.collectAsStateWithLifecycle()
    val rules by engine.rulesFlow().collectAsStateWithLifecycle()
    val queueDepth by engine.queueDepth.collectAsStateWithLifecycle()
    val pending by engine.pendingPrompt.collectAsStateWithLifecycle()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Text("Firewall journal", style = MaterialTheme.typography.titleLarge)
            Text(
                "Interactive decisions for outbound connections through Tor.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (pending != null) {
            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    FirewallPromptContent(
                        info = pending!!,
                        tempMinutes = preferences.firewallTempMinutes,
                        onAnswer = { verdict, scope ->
                            engine.answerPrompt(pending!!.requestId, verdict, scope)
                        },
                    )
                }
            }
        } else if (queueDepth > 0) {
            item {
                Text(
                    "Prompt queue: $queueDepth (waiting for surface)",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }

        if (rules.isNotEmpty()) {
            item {
                Text("Active rules", style = MaterialTheme.typography.titleMedium)
            }
            items(rules, key = { it.id }) { rule ->
                RuleRow(rule = rule, onDelete = { engine.deleteRule(rule.id) })
            }
        }

        item {
            Text("Timeline", style = MaterialTheme.typography.titleMedium)
        }
        if (journal.isEmpty()) {
            item {
                Text(
                    "No decisions yet. Enable the firewall in Settings, then start the VPN.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(journal, key = { it.id }) { entry ->
                JournalRow(entry)
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
                "${verdictLabel(rule.verdict)} · ${scopeLabel(rule)}",
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
            "$time  ${verdictLabel(entry.verdict)}  ${entry.appLabel}",
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

private fun verdictLabel(verdict: FirewallVerdict): String = when (verdict) {
    FirewallVerdict.ALLOW -> "Allow"
    FirewallVerdict.DENY -> "Deny"
}

private fun scopeLabel(rule: FirewallRule): String = when (rule.scope) {
    FirewallRuleScope.PERMANENT -> "Permanent"
    FirewallRuleScope.SESSION -> "Until VPN stops"
    FirewallRuleScope.TEMPORARY -> {
        val until = rule.expiresAtEpochMs
        if (until != null) {
            val time = SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(until))
            "Until $time"
        } else {
            "Temporary"
        }
    }
}
