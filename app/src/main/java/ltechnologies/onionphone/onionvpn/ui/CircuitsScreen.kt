package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager
import ltechnologies.onionphone.onionvpn.firewall.AppUidResolver

@Composable
fun CircuitsScreen(
    lifecycle: CircuitLifecycleManager,
    appUidResolver: AppUidResolver,
    onBack: () -> Unit,
) {
    val circuits by lifecycle.liveCircuits.collectAsStateWithLifecycle()
    val streams by lifecycle.liveStreams.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        lifecycle.refreshFromGetInfo()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text("Tor circuits", style = MaterialTheme.typography.headlineSmall)
            TextButton(onClick = onBack) { Text("Back") }
        }
        Text(
            text = "${circuits.size} circuits · ${streams.size} streams. " +
                "Per-app isolation via SOCKS u{uid}. Close uses CLOSECIRCUIT IfUnused.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { lifecycle.refreshFromGetInfo() }) {
                Text("Refresh")
            }
            OutlinedButton(
                onClick = {
                    lifecycle.extendNewCircuit()
                    lifecycle.refreshFromGetInfo()
                },
            ) {
                Text("Extend new")
            }
        }
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(circuits, key = { it.info.id }) { live ->
                CircuitCard(
                    live = live,
                    streamCount = live.streamIds.size,
                    appLabel = labelForSocksUser(live.socksUsername, appUidResolver),
                    onCloseUnused = {
                        lifecycle.closeCircuit(live.info.id, ifUnused = true)
                    },
                    onCloseForce = {
                        lifecycle.closeCircuit(live.info.id, ifUnused = false)
                    },
                )
            }
        }
    }
}

@Composable
private fun CircuitCard(
    live: CircuitLifecycleManager.LiveCircuit,
    streamCount: Int,
    appLabel: String,
    onCloseUnused: () -> Unit,
    onCloseForce: () -> Unit,
) {
    val info = live.info
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = "#${info.id} ${info.status}" +
                    if (live.stickyAuth) " · sticky-UID" else if (live.longLived) " · long-lived" else "",
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = appLabel,
                style = MaterialTheme.typography.bodyMedium,
            )
            if (info.path.isNotBlank()) {
                Text(
                    text = shortenPath(info.path),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = "streams=$streamCount purpose=${info.purpose.ifBlank { "?" }} " +
                    "auth=${live.socksUsername ?: "—"}",
                style = MaterialTheme.typography.labelSmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onCloseUnused) { Text("Close if unused") }
                OutlinedButton(onClick = onCloseForce) { Text("Force close") }
            }
        }
    }
}

private fun labelForSocksUser(user: String?, resolver: AppUidResolver): String {
    if (user.isNullOrBlank()) return "No SOCKS auth (internal?)"
    val uid = TunnelEndpoints.uidFromSocksUser(user) ?: return "auth=$user"
    if (uid < 0) return "Unknown app ($user)"
    val id = resolver.resolve(uid)
    return "${id.label} (uid=$uid)"
}

private fun shortenPath(path: String): String =
    path.split(',')
        .map { hop ->
            hop.substringAfter('~', hop.substringAfter('=', hop)).take(20)
        }
        .joinToString(" → ")
