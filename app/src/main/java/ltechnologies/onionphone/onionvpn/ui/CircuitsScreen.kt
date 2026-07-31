package ltechnologies.onionphone.onionvpn.ui

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AddRoad
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.control.geo.RelayCountryLookup
import ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager
import ltechnologies.onionphone.onionvpn.firewall.AppUidResolver
import ltechnologies.onionphone.onionvpn.ui.components.EmptyStateHint
import ltechnologies.onionphone.onionvpn.ui.components.MetricChip
import ltechnologies.onionphone.onionvpn.ui.components.SectionHeader

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
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
            SectionHeader(
                title = "Tor circuits",
                subtitle = "Per-app IsolateSOCKSAuth (RFC 1929) — SOCKS u{uid}. Close uses CLOSECIRCUIT IfUnused.",
                modifier = Modifier.weight(1f),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            MetricChip(label = "Circuits", value = circuits.size.toString())
            MetricChip(label = "Streams", value = streams.size.toString())
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton(onClick = { lifecycle.refreshFromGetInfo() }) {
                Icon(Icons.Filled.Refresh, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text("Refresh")
            }
            OutlinedButton(
                onClick = {
                    lifecycle.extendNewCircuit()
                    lifecycle.refreshFromGetInfo()
                },
            ) {
                Icon(Icons.Filled.AddRoad, contentDescription = null)
                Spacer(Modifier.width(6.dp))
                Text("Extend new")
            }
        }
        if (circuits.isEmpty()) {
            EmptyStateHint("No live circuits yet. Start the VPN and open an app.")
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(circuits, key = { it.info.id }) { live ->
                    val uid = live.socksUsername?.let { TunnelEndpoints.uidFromSocksUser(it) }
                    val appLabel = remember(live.socksUsername) {
                        labelForSocksUser(live.socksUsername, appUidResolver)
                    }
                    val appIcon = remember(uid) {
                        uid?.takeIf { it >= 0 }?.let { appUidResolver.iconDrawable(it) }
                    }
                    CircuitCard(
                        live = live,
                        streamCount = live.streamIds.size,
                        appLabel = appLabel,
                        appIcon = appIcon,
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
}

@Composable
private fun CircuitCard(
    live: CircuitLifecycleManager.LiveCircuit,
    streamCount: Int,
    appLabel: String,
    appIcon: Drawable?,
    onCloseUnused: () -> Unit,
    onCloseForce: () -> Unit,
) {
    val info = live.info
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow,
        ),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 0.dp),
    ) {
        Box(modifier = Modifier.fillMaxWidth()) {
            if (appIcon != null) {
                val bmp = remember(appIcon) { appIcon.toBitmap(96, 96).asImageBitmap() }
                Image(
                    bitmap = bmp,
                    contentDescription = appLabel,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(12.dp)
                        .size(40.dp),
                )
            }
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "#${info.id} ${info.status}" +
                        if (live.stickyAuth) {
                            " · sticky-UID"
                        } else if (live.longLived) {
                            " · long-lived"
                        } else {
                            ""
                        },
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(end = if (appIcon != null) 48.dp else 0.dp),
                )
                Text(
                    text = appLabel,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(end = if (appIcon != null) 48.dp else 0.dp),
                )
                val pathText = formatHops(live.hops).ifBlank {
                    if (info.path.isNotBlank()) shortenPath(info.path) else ""
                }
                if (pathText.isNotBlank()) {
                    Text(
                        text = pathText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    text = "streams=$streamCount purpose=${info.purpose.ifBlank { "?" }} " +
                        "auth=${live.socksUsername ?: "—"}",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = onCloseUnused,
                        shape = MaterialTheme.shapes.medium,
                    ) { Text("Close if unused") }
                    OutlinedButton(
                        onClick = onCloseForce,
                        shape = MaterialTheme.shapes.medium,
                    ) {
                        Icon(
                            Icons.Filled.Close,
                            contentDescription = null,
                            modifier = Modifier.padding(end = 4.dp),
                        )
                        Text("Force close")
                    }
                }
            }
        }
    }
}

private fun formatHops(hops: List<RelayCountryLookup.Hop>): String {
    if (hops.isEmpty()) return ""
    return hops.joinToString(" → ") { hop ->
        val flag = RelayCountryLookup.flagEmoji(hop.countryCode)
        val nick = hop.nickname.take(20)
        if (flag.isNotEmpty()) "$flag $nick" else nick
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
