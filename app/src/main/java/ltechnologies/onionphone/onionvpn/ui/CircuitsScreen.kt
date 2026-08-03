package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddRoad
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.control.geo.RelayCountryLookup
import ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager
import ltechnologies.onionphone.onionvpn.firewall.AppUidResolver
import ltechnologies.onionphone.onionvpn.ui.components.AppCircuitCard
import ltechnologies.onionphone.onionvpn.ui.components.CircuitActionButton
import ltechnologies.onionphone.onionvpn.ui.components.CircuitsScreenScaffold
import ltechnologies.onionphone.onionvpn.ui.components.MetricChip
import ltechnologies.onionphone.onionvpn.ui.components.redactSocksAuthForUi

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

    CircuitsScreenScaffold(
        title = "Tor circuits",
        subtitle = "Per-app IsolateSOCKSAuth — Close uses CLOSECIRCUIT IfUnused.",
        onBack = onBack,
        metrics = {
            MetricChip(label = "Circuits", value = circuits.size.toString())
            MetricChip(label = "Streams", value = streams.size.toString())
        },
        actions = {
            CircuitActionButton(
                label = "Refresh",
                onClick = { lifecycle.refreshFromGetInfo() },
                icon = Icons.Filled.Refresh,
            )
            CircuitActionButton(
                label = "Extend new",
                onClick = {
                    lifecycle.extendNewCircuit()
                    lifecycle.refreshFromGetInfo()
                },
                icon = Icons.Filled.AddRoad,
                tonal = false,
            )
        },
        empty = circuits.isEmpty(),
        emptyHint = "No live circuits yet. Start the VPN and open an app.",
    ) {
        items(circuits, key = { it.info.id }) { live ->
            val uid = live.socksUsername?.let { TunnelEndpoints.uidFromSocksUser(it) }
            val appLabel = remember(live.socksUsername) {
                labelForSocksUser(live.socksUsername, appUidResolver)
            }
            val appIcon = remember(uid) {
                uid?.takeIf { it >= 0 }?.let { appUidResolver.iconDrawable(it) }
            }
            val badge = when {
                live.stickyAuth -> " · sticky-UID"
                live.longLived -> " · long-lived"
                else -> ""
            }
            AppCircuitCard(
                title = "#${live.info.id} ${live.info.status}$badge",
                subtitle = appLabel,
                pathText = formatHops(live.hops).ifBlank {
                    if (live.info.path.isNotBlank()) shortenPath(live.info.path) else ""
                },
                metaText = "streams=${live.streamIds.size} " +
                    "purpose=${live.info.purpose.ifBlank { "?" }} " +
                    "auth=${redactSocksAuthForUi(live.socksUsername)}",
                appIcon = appIcon,
                appContentDescription = appLabel,
                primaryLabel = "Close if unused",
                onPrimary = { lifecycle.closeCircuit(live.info.id, ifUnused = true) },
                secondaryLabel = "Force close",
                onSecondary = { lifecycle.closeCircuit(live.info.id, ifUnused = false) },
                secondaryIcon = Icons.Filled.Close,
            )
        }
    }
}

private fun formatHops(hops: List<RelayCountryLookup.Hop>): String {
    if (hops.isEmpty()) return ""
    return hops.joinToString(" → ") { hop ->
        val flag = RelayCountryLookup.flagEmoji(hop.countryCode)
        // Nickname only — never fingerprint / OR address in the list UI.
        val nick = hop.nickname.take(20).ifBlank { hop.countryCode?.uppercase().orEmpty() }
        if (flag.isNotEmpty()) "$flag $nick" else nick
    }
}

private fun labelForSocksUser(user: String?, resolver: AppUidResolver): String {
    if (user.isNullOrBlank()) return "No SOCKS auth (internal?)"
    val uid = TunnelEndpoints.uidFromSocksUser(user) ?: return redactSocksAuthForUi(user)
    if (uid < 0) return "Unknown app"
    val id = resolver.resolve(uid)
    return "${id.label} (uid=$uid)"
}

/** ControlPort path: nicknames only, strip $fingerprint= / ~ forms. */
private fun shortenPath(path: String): String =
    path.split(',')
        .map { hop ->
            hop.substringAfter('~', hop.substringAfter('=', hop)).take(20)
        }
        .joinToString(" → ")
