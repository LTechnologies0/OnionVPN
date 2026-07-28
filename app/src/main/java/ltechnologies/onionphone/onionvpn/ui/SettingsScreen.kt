package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.FirewallDefaultAction
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

@Composable
fun SettingsScreen(
    preferences: TunnelPreferences,
    onLoadTorrc: () -> String,
    onLoadDnsCryptToml: () -> String,
    onSavePreferences: (TunnelPreferences) -> Unit,
    onSaveTorrc: (String) -> Unit,
    onSaveDnsCryptToml: (String) -> Unit,
) {
    var local by remember(preferences) { mutableStateOf(preferences) }
    var editingTorrc by remember { mutableStateOf(false) }
    var editingToml by remember { mutableStateOf(false) }
    var torrcDraft by remember { mutableStateOf("") }
    var tomlDraft by remember { mutableStateOf("") }

    if (editingTorrc) {
        ConfigEditor(
            title = "Edit torrc",
            text = torrcDraft,
            onTextChange = { torrcDraft = it },
            onSave = {
                onSaveTorrc(torrcDraft)
                editingTorrc = false
            },
            onCancel = { editingTorrc = false },
        )
        return
    }
    if (editingToml) {
        ConfigEditor(
            title = "Edit dnscrypt-proxy.toml",
            text = tomlDraft,
            onTextChange = { tomlDraft = it },
            onSave = {
                onSaveDnsCryptToml(tomlDraft)
                editingToml = false
            },
            onCancel = { editingToml = false },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("DNS mode", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "FakeDNS (Orbot): apps see fake 100.64.x IPs; hostname resolved at Tor exit.\n" +
                "DNSCrypt mux: apps see real dest IPs (looked up over Tor); TCP still via Tor exit.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = local.dnsResolverMode == DnsResolverMode.FAKE_IP_SOCKS5A,
                onClick = { local = local.copy(dnsResolverMode = DnsResolverMode.FAKE_IP_SOCKS5A) },
                label = { Text("FakeDNS (Orbot)") },
            )
            FilterChip(
                selected = local.dnsResolverMode == DnsResolverMode.DNSCRYPT_MUX,
                onClick = { local = local.copy(dnsResolverMode = DnsResolverMode.DNSCRYPT_MUX) },
                label = { Text("DNSCrypt mux") },
            )
        }

        PrefSwitch(
            label = "Route all traffic through Tor",
            checked = local.routeAllTrafficThroughTor,
            onChecked = { local = local.copy(routeAllTrafficThroughTor = it) },
        )
        PrefSwitch(
            label = "Kill switch",
            checked = local.killSwitchEnabled,
            onChecked = { local = local.copy(killSwitchEnabled = it) },
        )
        Text(
            text = "Kill switch drops only app packets that cannot go through Tor " +
                "(Blocking TUN / no clearnet). Working Tor circuits stay up — soft probe " +
                "flakes (DNSCrypt, exit-IP fetch, Wi‑Fi blip) do not tear them down.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Text("Interactive firewall", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "OpenSnitch-style prompts for new outbound connections on the TUN. " +
                "Allow / deny permanently or for a few minutes. Timeout = deny.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Enable firewall",
            checked = local.firewallEnabled,
            onChecked = { local = local.copy(firewallEnabled = it) },
        )
        Text("Default when no rule", style = MaterialTheme.typography.labelLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = local.firewallDefaultAction == FirewallDefaultAction.ASK,
                onClick = { local = local.copy(firewallDefaultAction = FirewallDefaultAction.ASK) },
                label = { Text("Ask") },
            )
            FilterChip(
                selected = local.firewallDefaultAction == FirewallDefaultAction.DENY,
                onClick = { local = local.copy(firewallDefaultAction = FirewallDefaultAction.DENY) },
                label = { Text("Deny") },
            )
            FilterChip(
                selected = local.firewallDefaultAction == FirewallDefaultAction.ALLOW,
                onClick = { local = local.copy(firewallDefaultAction = FirewallDefaultAction.ALLOW) },
                label = { Text("Allow") },
            )
        }
        OutlinedTextField(
            value = local.firewallTempMinutes.toString(),
            onValueChange = {
                it.toIntOrNull()?.let { v -> local = local.copy(firewallTempMinutes = v.coerceIn(1, 1440)) }
            },
            label = { Text("Temporary rule (minutes)") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = local.firewallPromptTimeoutSec.toString(),
            onValueChange = {
                it.toIntOrNull()?.let { v -> local = local.copy(firewallPromptTimeoutSec = v.coerceIn(5, 120)) }
            },
            label = { Text("Prompt timeout (seconds)") },
            modifier = Modifier.fillMaxWidth(),
        )

        Text("System leak checklist", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "TUN alone is not enough on Android:\n" +
                "1. Settings → Network → VPN → OnionVPN → Always-on ON\n" +
                "2. Block connections without VPN ON\n" +
                "3. Private DNS → Off (DoT can bypass tunnel DNS)\n" +
                "4. Stop other VPNs (InviZible/Orbot)\n" +
                "5. WebRTC/STUN is browser-side — Vanadium/Mull, not the VPN",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Text("Tor", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = local.torBridges,
            onValueChange = { local = local.copy(torBridges = it) },
            label = { Text("Bridges (one per line)") },
            modifier = Modifier
                .fillMaxWidth()
                .height(120.dp),
            minLines = 3,
        )
        OutlinedTextField(
            value = local.torEntryNodes,
            onValueChange = { local = local.copy(torEntryNodes = it) },
            label = { Text("EntryNodes") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = local.torExitNodes,
            onValueChange = { local = local.copy(torExitNodes = it) },
            label = { Text("ExitNodes") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = local.torExcludeNodes,
            onValueChange = { local = local.copy(torExcludeNodes = it) },
            label = { Text("ExcludeNodes") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = local.torNewCircuitPeriodSec.toString(),
            onValueChange = {
                it.toIntOrNull()?.let { v -> local = local.copy(torNewCircuitPeriodSec = v) }
            },
            label = { Text("NewCircuitPeriod (sec)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            text = "MaxCircuitDirtiness (sec) — lower = more circuit rotation " +
                "(path-spec; app SocksPort has no KeepAliveIsolateSOCKSAuth).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = local.torMaxCircuitDirtinessSec.toString(),
            onValueChange = {
                it.toIntOrNull()?.let { v -> local = local.copy(torMaxCircuitDirtinessSec = v) }
            },
            label = { Text("MaxCircuitDirtiness (sec)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                torrcDraft = onLoadTorrc()
                editingTorrc = true
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Edit torrc")
        }

        Text("DNSCrypt", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            DnsCryptConfigWriter.knownServers.keys.forEach { name ->
                FilterChip(
                    selected = local.dnsCryptServerName == name,
                    onClick = { local = local.copy(dnsCryptServerName = name) },
                    label = { Text(name) },
                )
            }
        }
        PrefSwitch(
            label = "require_nolog",
            checked = local.dnsCryptRequireNoLog,
            onChecked = { local = local.copy(dnsCryptRequireNoLog = it) },
        )
        PrefSwitch(
            label = "require_nofilter",
            checked = local.dnsCryptRequireNoFilter,
            onChecked = { local = local.copy(dnsCryptRequireNoFilter = it) },
        )
        PrefSwitch(
            label = "force_tcp",
            checked = local.dnsCryptForceTcp,
            onChecked = { local = local.copy(dnsCryptForceTcp = it) },
        )
        PrefSwitch(
            label = "require_dnssec",
            checked = local.dnsCryptRequireDnssec,
            onChecked = { local = local.copy(dnsCryptRequireDnssec = it) },
        )
        Button(
            onClick = {
                tomlDraft = onLoadDnsCryptToml()
                editingToml = true
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Edit dnscrypt-proxy.toml")
        }

        Button(
            onClick = { onSavePreferences(local) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Save settings")
        }
        Text(
            text = "Changes apply on next tunnel start (restart if already connected).",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun PrefSwitch(
    label: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChecked)
    }
}

@Composable
private fun ConfigEditor(
    title: String,
    text: String,
    onTextChange: (String) -> Unit,
    onSave: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleLarge)
        OutlinedTextField(
            value = text,
            onValueChange = onTextChange,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            textStyle = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onCancel, modifier = Modifier.weight(1f)) { Text("Cancel") }
            Button(onClick = onSave, modifier = Modifier.weight(1f)) { Text("Save") }
        }
    }
}
