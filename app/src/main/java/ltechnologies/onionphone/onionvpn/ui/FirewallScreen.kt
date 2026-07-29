package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
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
import ltechnologies.onionphone.onionvpn.firewall.threatLabelOrNull
import ltechnologies.onionphone.onionvpn.firewall.threatTextColor
import ltechnologies.onionphone.onionvpn.ui.components.EmptyStateHint
import ltechnologies.onionphone.onionvpn.ui.components.SectionHeader
import ltechnologies.onionphone.onionvpn.ui.components.TonalSection

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
            SectionHeader(
                title = "Firewall",
                subtitle = "Interactive decisions for outbound connections through Tor.",
            )
        }

        if (pending != null) {
            item {
                ElevatedCard(
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.large,
                    colors = CardDefaults.elevatedCardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                    ),
                    elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp),
                ) {
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
                Surface(
                    shape = MaterialTheme.shapes.medium,
                    color = MaterialTheme.colorScheme.tertiaryContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        "Prompt queue: $queueDepth (waiting for surface)",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onTertiaryContainer,
                        modifier = Modifier.padding(16.dp),
                    )
                }
            }
        }

        if (rules.isNotEmpty()) {
            item {
                SectionHeader(title = "Active rules")
            }
            items(rules, key = { it.id }) { rule ->
                RuleRow(rule = rule, onDelete = { engine.deleteRule(rule.id) })
            }
        }

        item {
            SectionHeader(title = "Timeline")
        }
        if (journal.isEmpty()) {
            item {
                EmptyStateHint(
                    "No decisions yet. Enable the firewall in Settings, then start the VPN.",
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
    TonalSection {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "${rule.appLabel} → ${ruleDisplayDest(rule)}",
                    style = MaterialTheme.typography.titleSmall,
                )
                if (rule.displayHost.isNotBlank()) {
                    Text(
                        "IP ${rule.destHost.ifEmpty { "*" }}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    "${verdictLabel(rule.verdict)} · ${scopeLabel(rule)}",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (rule.verdict == FirewallVerdict.ALLOW) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.error
                    },
                )
            }
            FilledTonalIconButton(onClick = onDelete) {
                Icon(Icons.Filled.Delete, contentDescription = "Delete rule")
            }
        }
    }
}

@Composable
private fun JournalRow(entry: FirewallJournalEntry) {
    val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        .format(Date(entry.timestampEpochMs))
    val threatLabel = threatLabelOrNull(entry.threatCategory)
    val destColor = threatTextColor(entry.threatCategory)
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerLow,
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Text(
                "$time  ${verdictLabel(entry.verdict)}  ${entry.appLabel}",
                style = MaterialTheme.typography.titleSmall,
                color = if (entry.verdict == FirewallVerdict.ALLOW) {
                    MaterialTheme.colorScheme.primary
                } else {
                    MaterialTheme.colorScheme.error
                },
            )
            Text(
                buildString {
                    append(entry.protocolLabel)
                    append(' ')
                    append(entry.displayDestination())
                    append(':')
                    append(entry.destPort)
                    if (threatLabel != null) {
                        append(" · ")
                        append(threatLabel)
                    }
                    if (entry.note.isNotBlank()) {
                        append(" · ")
                        append(entry.note)
                    }
                },
                style = MaterialTheme.typography.bodySmall,
                color = destColor,
            )
            if (!entry.destHost.isNullOrBlank()) {
                Text(
                    "IP ${entry.destIp}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

/** Hostname primary when known; match key (IP) otherwise — same pattern as prompts. */
private fun ruleDisplayDest(rule: FirewallRule): String {
    val host = rule.displayHost.ifBlank { rule.destHost.ifEmpty { "*" } }
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
