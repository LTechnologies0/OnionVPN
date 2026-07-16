package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
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
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = "OnionVPN", style = MaterialTheme.typography.headlineMedium)
        Text(text = "Phase: ${snapshot.phase}")
        Text(text = "Kill switch: ${snapshot.killSwitchEnabled}")
        Text(text = "Tor: ${if (snapshot.torRunning) "up" else "down"}")
        Text(text = "DNSCrypt: ${if (snapshot.dnsCryptRunning) "up" else "down"}")
        Text(text = "VPN: ${if (snapshot.vpnEstablished) "up" else "down"}")
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

        if (snapshot.validations.isNotEmpty()) {
            Text(text = "Validation", style = MaterialTheme.typography.titleMedium)
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(snapshot.validations) { check ->
                    ValidationCard(check)
                }
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
                text = "${check.status}: ${check.detail}",
                color = if (check.status == ValidationStatus.Fail) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
        }
    }
}
