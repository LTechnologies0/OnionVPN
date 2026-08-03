package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.onionmasq.OnionmasqNativeGate
import ltechnologies.onionphone.onionvpn.firewall.AppUidResolver
import ltechnologies.onionphone.onionvpn.ui.components.AppCircuitCard
import ltechnologies.onionphone.onionvpn.ui.components.CircuitActionButton
import ltechnologies.onionphone.onionvpn.ui.components.CircuitsScreenScaffold
import ltechnologies.onionphone.onionvpn.ui.components.MetricChip
import ltechnologies.onionphone.onionvpn.ui.components.formatByteCount
import ltechnologies.onionphone.onionvpn.ui.components.formatCountryHopPath
import org.torproject.onionmasq.OnionMasq
import org.torproject.onionmasq.errors.ProxyStoppedException
import timber.log.Timber

/**
 * Onionmasq CircuitStore UI — same chrome / cards as [CircuitsScreen] (C Tor).
 * Shows country-code hops only (never relay IPs / identities).
 */
@Composable
fun OnionmasqCircuitsScreen(
    appUidResolver: AppUidResolver,
    onBack: () -> Unit,
) {
    var rows by remember { mutableStateOf<List<AppCircuitRow>>(emptyList()) }
    var refreshTick by remember { mutableStateOf(0) }

    LaunchedEffect(refreshTick) {
        rows = withContext(Dispatchers.Default) {
            collectOnionmasqRows(appUidResolver)
        }
        while (true) {
            delay(1_000)
            rows = withContext(Dispatchers.Default) {
                collectOnionmasqRows(appUidResolver)
            }
        }
    }

    val openTotal = rows.sumOf { it.openConnections }
    CircuitsScreenScaffold(
        title = "Tor circuits",
        subtitle = "Per-app hops (onionmasq) — New circuit refreshes isolation for that UID.",
        onBack = onBack,
        metrics = {
            MetricChip(label = "Apps", value = rows.size.toString())
            MetricChip(label = "Open", value = openTotal.toString())
        },
        actions = {
            CircuitActionButton(
                label = "New identity (all)",
                onClick = {
                    if (!OnionmasqNativeGate.mayCommandRunningProxy(
                            javaInitialized = OnionMasq.isInitialized(),
                            nativeRunning = OnionMasq.isRunning(),
                        )
                    ) {
                        Timber.w("refreshCircuits skipped — onionmasq not running")
                        return@CircuitActionButton
                    }
                    runCatching { OnionMasq.refreshCircuits() }
                        .onFailure { Timber.w(it, "refreshCircuits failed") }
                    refreshTick++
                },
                icon = Icons.Filled.SwapHoriz,
            )
            CircuitActionButton(
                label = "Refresh",
                onClick = { refreshTick++ },
                icon = Icons.Filled.Refresh,
                tonal = false,
            )
        },
        empty = rows.isEmpty(),
        emptyHint = "No live circuits yet. Start the VPN (Arti + onionmasq) and open an app.",
    ) {
        items(rows, key = { it.uid }) { row ->
            val appIcon = remember(row.uid) {
                row.uid.takeIf { it >= 0 }?.let { appUidResolver.iconDrawable(it) }
            }
            AppCircuitCard(
                title = row.label,
                subtitle = "uid=${row.uid}",
                pathText = formatCountryHopPath(row.hops).ifBlank { "(no hops yet)" },
                metaText = "open=${row.openConnections} · " +
                    "↓${formatByteCount(row.bytesIn)} ↑${formatByteCount(row.bytesOut)}",
                appIcon = appIcon,
                appContentDescription = row.label,
                primaryLabel = "New circuit for app",
                onPrimary = {
                    if (!OnionmasqNativeGate.mayCommandRunningProxy(
                            javaInitialized = OnionMasq.isInitialized(),
                            nativeRunning = OnionMasq.isRunning(),
                        )
                    ) {
                        Timber.w("refreshCircuitsForApp skipped — not running")
                        return@AppCircuitCard
                    }
                    try {
                        OnionMasq.refreshCircuitsForApp(row.uid.toLong())
                        OnionVpnService.circuitRepository.removeCountryCodes(row.uid)
                    } catch (e: ProxyStoppedException) {
                        Timber.w(e, "refreshCircuitsForApp")
                    }
                },
            )
        }
    }
}

/** Prefer [OnionmasqCircuitsScreen] — thin alias for older call sites. */
@Composable
fun OnionmasqCircuitsPanel(
    appUidResolver: AppUidResolver,
    onBack: () -> Unit = {},
) {
    OnionmasqCircuitsScreen(
        appUidResolver = appUidResolver,
        onBack = onBack,
    )
}

private data class AppCircuitRow(
    val uid: Int,
    val label: String,
    val hops: List<String>,
    val bytesIn: Long,
    val bytesOut: Long,
    val openConnections: Int,
)

private fun collectOnionmasqRows(appUidResolver: AppUidResolver): List<AppCircuitRow> {
    val repo = OnionVpnService.circuitRepository
    val proxyReady = OnionmasqNativeGate.mayCommandRunningProxy(
        javaInitialized = OnionMasq.isInitialized(),
        nativeRunning = OnionMasq.isRunning(),
    )
    return repo.knownAppUids().sorted().map { uid ->
        val hops = repo.countryCodesForAppUid(uid)
        val identity = appUidResolver.resolve(uid)
        val open = repo.openConnectionsForAppUid(uid).size
        val rx = if (proxyReady) {
            runCatching { OnionMasq.getBytesReceivedForApp(uid.toLong()) }.getOrDefault(0L)
        } else {
            0L
        }
        val tx = if (proxyReady) {
            runCatching { OnionMasq.getBytesSentForApp(uid.toLong()) }.getOrDefault(0L)
        } else {
            0L
        }
        AppCircuitRow(
            uid = uid,
            label = identity.label,
            hops = hops,
            bytesIn = rx,
            bytesOut = tx,
            openConnections = open,
        )
    }
}
