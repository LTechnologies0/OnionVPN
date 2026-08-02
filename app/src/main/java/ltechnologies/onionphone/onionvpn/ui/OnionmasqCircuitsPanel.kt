package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.firewall.AppUidResolver
import ltechnologies.onionphone.onionvpn.ui.components.EmptyStateHint
import ltechnologies.onionphone.onionvpn.ui.components.SectionHeader
import org.torproject.onionmasq.OnionMasq
import org.torproject.onionmasq.errors.ProxyStoppedException
import timber.log.Timber

/**
 * Tor-VPN-style per-app circuit hops (onionmasq CircuitStore / country codes).
 */
@Composable
fun OnionmasqCircuitsPanel(
    appUidResolver: AppUidResolver,
    modifier: Modifier = Modifier,
) {
    var rows by remember { mutableStateOf<List<AppCircuitRow>>(emptyList()) }

    LaunchedEffect(Unit) {
        while (true) {
            rows = collectOnionmasqRows(appUidResolver)
            delay(1_000)
        }
    }

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SectionHeader(
            title = "App circuits (onionmasq)",
            subtitle = "Hops by Android UID — New circuit refreshes isolation epoch for that app.",
        )
        FilledTonalButton(
            onClick = {
                runCatching { OnionMasq.refreshCircuits() }
                    .onFailure { Timber.w(it, "refreshCircuits failed") }
            },
        ) {
            Icon(Icons.Filled.Refresh, contentDescription = null)
            Spacer(Modifier.width(6.dp))
            Text("New identity (all apps)")
        }
        if (rows.isEmpty()) {
            EmptyStateHint("No onionmasq circuits yet. Use Arti + onionmasq TUN and open an app.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(rows, key = { it.uid }) { row ->
                    ElevatedCard(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp)) {
                            Text(row.label, style = MaterialTheme.typography.titleSmall)
                            Text(
                                "UID ${row.uid} · ↓${row.bytesIn} ↑${row.bytesOut}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                row.hops.joinToString(" → ").ifBlank { "(no hops yet)" },
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Spacer(Modifier.height(8.dp))
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                FilledTonalButton(
                                    onClick = {
                                        try {
                                            OnionMasq.refreshCircuitsForApp(row.uid.toLong())
                                            OnionVpnService.circuitRepository.removeCountryCodes(row.uid)
                                        } catch (e: ProxyStoppedException) {
                                            Timber.w(e, "refreshCircuitsForApp")
                                        }
                                    },
                                ) {
                                    Text("New circuit for app")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private data class AppCircuitRow(
    val uid: Int,
    val label: String,
    val hops: List<String>,
    val bytesIn: Long,
    val bytesOut: Long,
)

private fun collectOnionmasqRows(appUidResolver: AppUidResolver): List<AppCircuitRow> {
    val repo = OnionVpnService.circuitRepository
    return repo.knownAppUids().sorted().map { uid ->
        val hops = repo.countryCodesForAppUid(uid)
        val identity = appUidResolver.resolve(uid)
        val rx = runCatching { OnionMasq.getBytesReceivedForApp(uid.toLong()) }.getOrDefault(0L)
        val tx = runCatching { OnionMasq.getBytesSentForApp(uid.toLong()) }.getOrDefault(0L)
        AppCircuitRow(
            uid = uid,
            label = identity.label,
            hops = hops,
            bytesIn = rx,
            bytesOut = tx,
        )
    }
}
