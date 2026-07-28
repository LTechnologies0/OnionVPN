package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.onionvpn.BuildConfig
import ltechnologies.onionphone.onionvpn.core.model.TunnelPhase
import ltechnologies.onionphone.onionvpn.core.model.TunnelSnapshot
import ltechnologies.onionphone.onionvpn.core.model.ValidationCheck
import ltechnologies.onionphone.onionvpn.core.model.ValidationStatus

@Composable
fun StatusScreen(
    snapshot: TunnelSnapshot,
    isBusy: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onNewNym: (() -> Unit)? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = "OnionVPN", style = MaterialTheme.typography.headlineMedium)
        Text(
            text = "v${BuildConfig.VERSION_NAME}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = "Phase: ${phaseLabel(snapshot.phase)}")
        Text(text = "Kill switch: ${if (snapshot.killSwitchEnabled) "On" else "Off"}")
        Text(text = "Tor: ${if (snapshot.torRunning) "up" else "down"}")
        Text(text = "DNSCrypt: ${if (snapshot.dnsCryptRunning) "up" else "down"}")
        Text(text = "VPN: ${if (snapshot.vpnEstablished) "up" else "down"}")
        if (snapshot.torControlConnected || snapshot.torBootstrapProgress > 0) {
            Text(
                text = buildString {
                    append("Control: ${if (snapshot.torControlConnected) "up" else "…"}  ")
                    append("bootstrap ${snapshot.torBootstrapProgress}%  ")
                    append("circuits=${snapshot.torBuiltCircuits}")
                    if (snapshot.torCircuitEstablished) append(" (established)")
                    append(" streams=${snapshot.torStreamCount}")
                    if (snapshot.torNetworkLive) append(" live")
                    if (snapshot.torDormant) append(" dormant")
                },
                style = MaterialTheme.typography.bodySmall,
            )
            if (snapshot.torVersion.isNotBlank()) {
                Text(
                    text = "Tor ${snapshot.torVersion}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (snapshot.torBootstrapSummary.isNotBlank() && snapshot.torBootstrapProgress < 100) {
                Text(
                    text = snapshot.torBootstrapSummary,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
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
        if (snapshot.phase == TunnelPhase.Connected && snapshot.throughputText.isNotBlank()) {
            Text(
                text = snapshot.throughputText,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
        snapshot.lastError?.let { error ->
            Text(
                text = "Error: $error",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        val active = snapshot.phase == TunnelPhase.Connected ||
            snapshot.phase == TunnelPhase.Blocking
        Button(
            onClick = if (active) onStop else onStart,
            modifier = Modifier.fillMaxWidth(),
            enabled = !isBusy && snapshot.phase != TunnelPhase.Stopping,
        ) {
            Text(
                when (snapshot.phase) {
                    TunnelPhase.Connected -> "Stop tunnel"
                    TunnelPhase.Blocking -> "Stop (kill switch active)"
                    else -> "Start tunnel"
                },
            )
        }
        if (snapshot.phase == TunnelPhase.Connected && onNewNym != null) {
            Button(
                onClick = onNewNym,
                modifier = Modifier.fillMaxWidth(),
                enabled = snapshot.torControlConnected,
            ) {
                Text("New identity (NEWNYM)")
            }
        }

        if (snapshot.validations.isNotEmpty()) {
            Text(text = "Validation", style = MaterialTheme.typography.titleMedium)
            snapshot.validations.forEach { check ->
                ValidationCard(check)
            }
        }
    }
}

@Composable
private fun ValidationCard(check: ValidationCheck) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(text = check.label, style = MaterialTheme.typography.titleSmall)
            Text(
                text = "${statusLabel(check.status)}: ${check.detail}",
                color = if (check.status == ValidationStatus.Fail) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
        }
    }
}

private fun phaseLabel(phase: TunnelPhase): String = when (phase) {
    TunnelPhase.Idle -> "Idle"
    TunnelPhase.StartingTor -> "Starting Tor"
    TunnelPhase.StartingDnsCrypt -> "Starting DNSCrypt"
    TunnelPhase.StartingVpn -> "Starting VPN"
    TunnelPhase.Validating -> "Validating"
    TunnelPhase.Connected -> "Connected"
    TunnelPhase.Blocking -> "Kill switch (blocking)"
    TunnelPhase.Stopping -> "Stopping"
    TunnelPhase.Error -> "Error"
}

private fun statusLabel(status: ValidationStatus): String = when (status) {
    ValidationStatus.Pass -> "Pass"
    ValidationStatus.Fail -> "Fail"
    ValidationStatus.Skipped -> "Skipped"
}
