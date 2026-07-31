package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.onionvpn.BuildConfig
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus
import ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.LeakPacketFilter
import ltechnologies.onionphone.onionvpn.diagnostics.ResourceSnapshot
import ltechnologies.onionphone.onionvpn.firewall.AppUidResolver
import ltechnologies.onionphone.onionvpn.ui.components.HeroIconBadge
import ltechnologies.onionphone.onionvpn.ui.components.MetricChip
import ltechnologies.onionphone.onionvpn.ui.components.SectionHeader
import ltechnologies.onionphone.onionvpn.ui.components.StatusDot
import ltechnologies.onionphone.onionvpn.ui.components.TonalSection
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun StatusScreen(
    snapshot: TunnelSnapshot,
    isBusy: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onNewNym: (() -> Unit)? = null,
    circuitLifecycle: CircuitLifecycleManager? = null,
    resourceSnapshot: StateFlow<ResourceSnapshot> = MutableStateFlow(ResourceSnapshot()).asStateFlow(),
    diagnosticsEnabled: Boolean = false,
) {
    var showCircuits by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val appUidResolver = remember { AppUidResolver(context) }
    val resources by resourceSnapshot.collectAsStateWithLifecycle()

    if (showCircuits && circuitLifecycle != null) {
        CircuitsScreen(
            lifecycle = circuitLifecycle,
            appUidResolver = appUidResolver,
            onBack = { showCircuits = false },
        )
        return
    }

    val connected = snapshot.phase == TunnelPhase.Connected
    val active = connected || snapshot.phase == TunnelPhase.Blocking
    val bootstrapping = snapshot.phase == TunnelPhase.StartingTor ||
        snapshot.phase == TunnelPhase.StartingDnsCrypt ||
        snapshot.phase == TunnelPhase.StartingVpn ||
        snapshot.phase == TunnelPhase.Validating

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "OnionVPN",
            style = MaterialTheme.typography.headlineMedium,
        )
        Text(
            text = "v${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        ElevatedCard(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.extraLarge,
            colors = CardDefaults.elevatedCardColors(
                containerColor = if (connected) {
                    MaterialTheme.colorScheme.primaryContainer
                } else if (snapshot.phase == TunnelPhase.Error || snapshot.phase == TunnelPhase.Blocking) {
                    MaterialTheme.colorScheme.errorContainer
                } else {
                    MaterialTheme.colorScheme.surfaceContainerHigh
                },
            ),
            elevation = CardDefaults.elevatedCardElevation(defaultElevation = 2.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                HeroIconBadge(
                    icon = if (connected) Icons.Filled.Shield else Icons.Outlined.Shield,
                    active = connected || bootstrapping,
                )
                Text(
                    text = phaseLabel(snapshot.phase),
                    style = MaterialTheme.typography.headlineSmall,
                    color = if (connected) {
                        MaterialTheme.colorScheme.onPrimaryContainer
                    } else if (snapshot.phase == TunnelPhase.Error || snapshot.phase == TunnelPhase.Blocking) {
                        MaterialTheme.colorScheme.onErrorContainer
                    } else {
                        MaterialTheme.colorScheme.onSurface
                    },
                )
                if (bootstrapping) {
                    LinearProgressIndicator(
                        progress = { (snapshot.torBootstrapProgress / 100f).coerceIn(0f, 1f) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp),
                    )
                    if (snapshot.torBootstrapSummary.isNotBlank()) {
                        Text(
                            text = snapshot.torBootstrapSummary,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                if (connected && snapshot.throughputText.isNotBlank()) {
                    Text(
                        text = snapshot.throughputText,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                }
                snapshot.lastError?.let { error ->
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            StatusDot(active = snapshot.torRunning, label = "Tor")
            StatusDot(active = snapshot.dnsCryptRunning, label = "DNSCrypt")
            StatusDot(active = snapshot.vpnEstablished, label = "VPN")
            StatusDot(active = snapshot.killSwitchEnabled, label = "Kill switch")
        }

        if (snapshot.torRuntimeReady || snapshot.torControlConnected || snapshot.torBootstrapProgress > 0) {
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                MetricChip("Bootstrap", "${snapshot.torBootstrapProgress}%")
                if (snapshot.torControlPlaneAvailable) {
                    MetricChip("Circuits", "${snapshot.torBuiltCircuits}")
                    MetricChip("Streams", "${snapshot.torStreamCount}")
                }
                MetricChip("Engine", snapshot.torEngine.displayName)
            }
            if (snapshot.torVersion.isNotBlank()) {
                Text(
                    text = "Tor ${snapshot.torVersion}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (diagnosticsEnabled && resources.timestampMs > 0L) {
            SectionHeader(
                title = "Resources",
                subtitle = "JVM + native process footprint (disabled when No logs is on).",
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                MetricChip("RSS", "${"%.0f".format(resources.vmRssMb)} MB")
                MetricChip("Heap", "${"%.0f".format(resources.heapUsedMb)} MB")
                MetricChip("Threads", "${resources.threads}")
                MetricChip("CPU", "${"%.0f".format(resources.cpuPercent)}%")
                resources.torChildRssMb?.let {
                    MetricChip("Tor RSS", "${"%.0f".format(it)} MB")
                }
            }
        }

        Button(
            onClick = if (active) onStop else onStart,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            enabled = !isBusy && snapshot.phase != TunnelPhase.Stopping,
            shape = MaterialTheme.shapes.large,
            colors = if (active) {
                ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                    contentColor = MaterialTheme.colorScheme.onError,
                )
            } else {
                ButtonDefaults.buttonColors()
            },
        ) {
            if (isBusy) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .height(22.dp)
                        .padding(end = 12.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            }
            Text(
                when (snapshot.phase) {
                    TunnelPhase.Connected -> "Stop tunnel"
                    TunnelPhase.Blocking -> "Stop (kill switch)"
                    else -> "Start tunnel"
                },
                style = MaterialTheme.typography.labelLarge,
            )
        }

        AnimatedVisibility(visible = connected, enter = fadeIn(), exit = fadeOut()) {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                if (onNewNym != null && snapshot.torEngine.capabilities.newIdentity) {
                    FilledTonalButton(
                        onClick = onNewNym,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        enabled = snapshot.torRuntimeReady || snapshot.torControlConnected,
                        shape = MaterialTheme.shapes.large,
                    ) {
                        Icon(Icons.Filled.SwapHoriz, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            if (snapshot.torEngine.capabilities.classicControlPlane) {
                                "New identity"
                            } else {
                                "New identity (restart Arti)"
                            },
                        )
                    }
                }
                if (circuitLifecycle != null && snapshot.torControlPlaneAvailable) {
                    OutlinedButton(
                        onClick = { showCircuits = true },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(52.dp),
                        enabled = snapshot.torControlPlaneAvailable,
                        shape = MaterialTheme.shapes.large,
                    ) {
                        Icon(Icons.Filled.Hub, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Circuits")
                    }
                }
            }
        }

        if (snapshot.vpnEstablished) {
            TonalSection {
                SectionHeader(
                    title = "Leak policy",
                    subtitle = "UDP blackhole · force TCP over Tor",
                )
                Text(
                    text = LeakPacketFilter.statsSummary(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        if (snapshot.pacUrl.isNotBlank()) {
            TonalSection {
                SectionHeader(
                    title = "PAC / proxy helpers",
                    subtitle = "DNS via DNSCrypt → Tor by IP",
                )
                Text(
                    text = snapshot.pacUrl,
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedButton(
                    onClick = {
                        val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                            as android.content.ClipboardManager
                        cm.setPrimaryClip(
                            android.content.ClipData.newPlainText("OnionVPN PAC", snapshot.pacUrl),
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.medium,
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Copy PAC URL")
                }
                if (snapshot.socksProxy.isNotBlank()) {
                    Text(
                        text = "SOCKS bridge ${snapshot.socksProxy}\nHTTPTunnelPort disabled — use PAC only.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedButton(
                        onClick = {
                            val cm = context.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                                as android.content.ClipboardManager
                            cm.setPrimaryClip(
                                android.content.ClipData.newPlainText(
                                    "OnionVPN SOCKS",
                                    "socks5://${snapshot.socksProxy}",
                                ),
                            )
                        },
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.medium,
                    ) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Copy socks5:// URL")
                    }
                }
            }
        }

        if (snapshot.torEntryGuards.isNotBlank() || snapshot.torLastCircEvent.isNotBlank()) {
            TonalSection {
                SectionHeader(title = "Tor detail")
                if (snapshot.torEntryGuards.isNotBlank()) {
                    Text(
                        text = "Guards: ${snapshot.torEntryGuards}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (snapshot.torLastCircEvent.isNotBlank()) {
                    Text(
                        text = "Last CIRC: ${snapshot.torLastCircEvent}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        if (snapshot.validations.isNotEmpty()) {
            SectionHeader(title = "Validation")
            snapshot.validations.forEach { check ->
                ValidationCard(check)
            }
        }
    }
}

@Composable
private fun ValidationCard(check: ValidationCheck) {
    val tone = when (check.status) {
        ValidationStatus.Pass -> MaterialTheme.colorScheme.secondaryContainer
        ValidationStatus.Fail -> MaterialTheme.colorScheme.errorContainer
        ValidationStatus.Skipped -> MaterialTheme.colorScheme.surfaceContainerHighest
    }
    val onTone = when (check.status) {
        ValidationStatus.Pass -> MaterialTheme.colorScheme.onSecondaryContainer
        ValidationStatus.Fail -> MaterialTheme.colorScheme.onErrorContainer
        ValidationStatus.Skipped -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.elevatedCardColors(containerColor = tone),
        elevation = CardDefaults.elevatedCardElevation(defaultElevation = 0.dp),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(text = check.label, style = MaterialTheme.typography.titleSmall, color = onTone)
                Text(
                    text = statusLabel(check.status),
                    style = MaterialTheme.typography.labelMedium,
                    color = onTone,
                )
            }
            Text(text = check.detail, style = MaterialTheme.typography.bodySmall, color = onTone)
        }
    }
}

private fun phaseLabel(phase: TunnelPhase): String = when (phase) {
    TunnelPhase.Idle -> "Ready"
    TunnelPhase.StartingTor -> "Starting Tor"
    TunnelPhase.StartingDnsCrypt -> "Starting DNSCrypt"
    TunnelPhase.StartingVpn -> "Starting VPN"
    TunnelPhase.Validating -> "Validating"
    TunnelPhase.Connected -> "Protected"
    TunnelPhase.Blocking -> "Kill switch"
    TunnelPhase.Stopping -> "Stopping"
    TunnelPhase.Error -> "Error"
}

private fun statusLabel(status: ValidationStatus): String = when (status) {
    ValidationStatus.Pass -> "Pass"
    ValidationStatus.Fail -> "Fail"
    ValidationStatus.Skipped -> "Skip"
}
