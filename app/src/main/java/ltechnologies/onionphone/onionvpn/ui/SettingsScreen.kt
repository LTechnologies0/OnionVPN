package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptPublicResolvers
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.FirewallDefaultAction
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.threat.DomainReputationRepository
import ltechnologies.onionphone.onionvpn.util.SystemSecurityIntents

@Composable
fun SettingsScreen(
    preferences: TunnelPreferences,
    domainReputation: DomainReputationRepository,
    onLoadTorrc: () -> String,
    onLoadDnsCryptToml: () -> String,
    onSavePreferences: (TunnelPreferences, restartIfConnected: Boolean) -> Unit,
    onSaveTorrc: (String) -> Unit,
    onSaveDnsCryptToml: (String) -> Unit,
) {
    var local by remember(preferences) { mutableStateOf(preferences) }
    val latestLocal = remember { AtomicReference(local) }
    val saveRef = remember { AtomicReference(onSavePreferences) }
    SideEffect {
        latestLocal.set(local)
        saveRef.set(onSavePreferences)
    }
    // Persist draft when leaving Settings (tab switch / overlay permission / app background).
    DisposableEffect(Unit) {
        onDispose {
            saveRef.get().invoke(latestLocal.get(), false)
        }
    }
    fun commit(next: TunnelPreferences, restart: Boolean = false) {
        local = next
        latestLocal.set(next)
        onSavePreferences(next, restart)
    }
    var editingTorrc by remember { mutableStateOf(false) }
    var editingToml by remember { mutableStateOf(false) }
    var pickingResolver by remember { mutableStateOf(false) }
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
        val context = LocalContext.current

        Text("App security", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "Uses the Android / GrapheneOS screen lock (PIN, pattern, biometric). " +
                "The VPN tunnel and kill switch keep running while the UI is locked.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Require device lock to open app",
            checked = local.appLockEnabled,
            onChecked = { commit(local.copy(appLockEnabled = it)) },
        )
        PrefSwitch(
            label = "Allow screenshots",
            checked = local.allowScreenshots,
            onChecked = { commit(local.copy(allowScreenshots = it)) },
        )
        Text(
            text = "Off (recommended): FLAG_SECURE blocks screenshots, screen recording, " +
                "and recents thumbnails of firewall/rules/logs.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Text("System leak protection", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "GrapheneOS improves VPN leak blocking when Always-on VPN + " +
                "“Block connections without VPN” are on. OnionVPN cannot flip those itself.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = { SystemSecurityIntents.openVpnSettings(context) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Open VPN settings (Always-on / lockdown)")
        }
        Button(
            onClick = { SystemSecurityIntents.openPrivateDnsSettings(context) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Open network settings (set Private DNS Off)")
        }
        Text(
            text = "Checklist:\n" +
                "1. Always-on VPN → OnionVPN ON\n" +
                "2. Block connections without VPN ON\n" +
                "3. Private DNS → Off (DoT bypasses tunnel DNS)\n" +
                "4. Stop other VPNs\n" +
                "5. Prefer Vanadium; disable WebRTC if possible",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Text("DNS mode", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "FakeDNS (Orbot): apps see fake 100.64.x IPs; hostname resolved at Tor exit.\n" +
                "DNSCrypt mux: apps see real dest IPs (looked up over Tor); TCP still via Tor exit.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.dnsResolverMode == DnsResolverMode.FAKE_IP_SOCKS5A,
                onClick = { commit(local.copy(dnsResolverMode = DnsResolverMode.FAKE_IP_SOCKS5A)) },
                label = { Text("FakeDNS (Orbot)") },
            )
            FilterChip(
                selected = local.dnsResolverMode == DnsResolverMode.DNSCRYPT_MUX,
                onClick = { commit(local.copy(dnsResolverMode = DnsResolverMode.DNSCRYPT_MUX)) },
                label = { Text("DNSCrypt mux") },
            )
        }

        PrefSwitch(
            label = "Prefer IPv4+IPv6 VPN families (API 29+)",
            checked = local.routeAllTrafficThroughTor,
            onChecked = { commit(local.copy(routeAllTrafficThroughTor = it)) },
        )
        Text(
            text = "Always installs a full default route (0.0.0.0/0 + ::/0). " +
                "When on (Android 10+), also calls allowFamily for IPv4 and IPv6. " +
                "Off does not enable split-tunnel.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Kill switch",
            checked = local.killSwitchEnabled,
            onChecked = { commit(local.copy(killSwitchEnabled = it)) },
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
                "Requests wait in a FIFO queue (one at a time) until you answer — no timeout. " +
                "A heads-up notification shows the app icon with Accept / Deny " +
                "(permanent rule). Tap the notification for more scope options.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Enable firewall",
            checked = local.firewallEnabled,
            onChecked = { commit(local.copy(firewallEnabled = it)) },
        )
        Text("Default when no rule", style = MaterialTheme.typography.labelLarge)
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.firewallDefaultAction == FirewallDefaultAction.ASK,
                onClick = { commit(local.copy(firewallDefaultAction = FirewallDefaultAction.ASK)) },
                enabled = local.firewallEnabled,
                label = { Text("Ask") },
            )
            FilterChip(
                selected = local.firewallDefaultAction == FirewallDefaultAction.DENY,
                onClick = { commit(local.copy(firewallDefaultAction = FirewallDefaultAction.DENY)) },
                enabled = local.firewallEnabled,
                label = { Text("Deny") },
            )
            FilterChip(
                selected = local.firewallDefaultAction == FirewallDefaultAction.ALLOW,
                onClick = { commit(local.copy(firewallDefaultAction = FirewallDefaultAction.ALLOW)) },
                enabled = local.firewallEnabled,
                label = { Text("Allow") },
            )
        }
        if (!local.firewallEnabled) {
            Text(
                text = "Default action is ignored while the firewall is off.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = local.firewallTempMinutes.toString(),
            onValueChange = {
                it.toIntOrNull()?.let { v ->
                    commit(local.copy(firewallTempMinutes = v.coerceIn(1, 1440)))
                }
            },
            label = { Text("Temporary rule (minutes)") },
            enabled = local.firewallEnabled,
            modifier = Modifier.fillMaxWidth(),
        )

        Text(stringResource(R.string.domain_lists_title), style = MaterialTheme.typography.titleMedium)
        Text(
            text = stringResource(R.string.domain_lists_desc),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        val reputation by domainReputation.status.collectAsStateWithLifecycle()
        val lastUpdate = if (reputation.lastSuccessEpochMs > 0L) {
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
                .format(Date(reputation.lastSuccessEpochMs))
        } else {
            stringResource(R.string.domain_lists_never)
        }
        val transport = when {
            reputation.lastSuccessEpochMs <= 0L -> ""
            reputation.lastViaTor -> stringResource(R.string.domain_lists_via_tor)
            else -> stringResource(R.string.domain_lists_via_direct)
        }
        Text(
            text = stringResource(
                R.string.domain_lists_status,
                reputation.trackingEntries,
                reputation.malwareEntries,
                lastUpdate,
                transport,
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (reputation.lastError != null) {
            Text(
                text = stringResource(R.string.domain_lists_last_error, reputation.lastError!!),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        Button(
            onClick = { domainReputation.requestUpdate() },
            enabled = !reputation.updating,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                if (reputation.updating) {
                    stringResource(R.string.domain_lists_updating)
                } else {
                    stringResource(R.string.domain_lists_update)
                },
            )
        }

        Text("Tor", style = MaterialTheme.typography.titleMedium)
        Text(
            text = "Circuit rotation presets (tor-spec path-spec / MaxCircuitDirtiness). " +
                "Vanguards-lite, padding, ClientOnly, SafeLogging already forced in torrc.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.torNewCircuitPeriodSec == 30 &&
                    local.torMaxCircuitDirtinessSec == 180,
                onClick = {
                    commit(
                        local.copy(
                            torNewCircuitPeriodSec = 30,
                            torMaxCircuitDirtinessSec = 180,
                        ),
                    )
                },
                label = { Text("Balanced") },
            )
            FilterChip(
                selected = local.torNewCircuitPeriodSec == 15 &&
                    local.torMaxCircuitDirtinessSec == 60,
                onClick = {
                    commit(
                        local.copy(
                            torNewCircuitPeriodSec = 15,
                            torMaxCircuitDirtinessSec = 60,
                        ),
                    )
                },
                label = { Text("Paranoid") },
            )
        }
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
                it.toIntOrNull()?.let { v ->
                    local = local.copy(torNewCircuitPeriodSec = v.coerceIn(10, 86_400))
                }
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
                it.toIntOrNull()?.let { v ->
                    local = local.copy(torMaxCircuitDirtinessSec = v.coerceIn(60, 86_400))
                }
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
        Text(
            text = "Upstream forced through Tor SOCKS; bootstrap via Tor DNSPort; " +
                "full public-resolvers catalog (${DnsCryptPublicResolvers.knownServers.size} IPv4). " +
                "Auto uses every resolver matching the filters below.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Button(
            onClick = {
                commit(
                    local.copy(
                        dnsCryptRequireNoLog = true,
                        dnsCryptRequireDnssec = true,
                        dnsCryptForceTcp = true,
                        dnsCryptRequireNoFilter = false,
                        dnsCryptServerName = "adguard-dns",
                    ),
                )
            },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Apply hardened DNSCrypt profile")
        }
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.dnsCryptServerName == DnsCryptPublicResolvers.AUTO,
                onClick = { commit(local.copy(dnsCryptServerName = DnsCryptPublicResolvers.AUTO)) },
                label = { Text("Auto (all matching)") },
            )
            listOf("cloudflare", "adguard-dns", "quad9-dnscrypt-ip4-nofilter-pri").forEach { name ->
                FilterChip(
                    selected = local.dnsCryptServerName == name,
                    onClick = { commit(local.copy(dnsCryptServerName = name)) },
                    label = { Text(name.substringBefore("-dns").substringBefore("-dnscrypt")) },
                )
            }
        }
        Text(
            text = "Selected: ${local.dnsCryptServerName}",
            style = MaterialTheme.typography.bodyMedium,
        )
        Button(
            onClick = { pickingResolver = true },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Browse all DNSCrypt resolvers…")
        }
        if (pickingResolver) {
            DnsCryptResolverPickerDialog(
                selected = local.dnsCryptServerName,
                onSelect = {
                    commit(local.copy(dnsCryptServerName = it))
                    pickingResolver = false
                },
                onDismiss = { pickingResolver = false },
            )
        }
        PrefSwitch(
            label = "Require no-log resolvers",
            checked = local.dnsCryptRequireNoLog,
            onChecked = { commit(local.copy(dnsCryptRequireNoLog = it)) },
        )
        PrefSwitch(
            label = "Require unfiltered resolvers",
            checked = local.dnsCryptRequireNoFilter,
            onChecked = { commit(local.copy(dnsCryptRequireNoFilter = it)) },
        )
        PrefSwitch(
            label = "Force TCP to upstream",
            checked = local.dnsCryptForceTcp,
            onChecked = { commit(local.copy(dnsCryptForceTcp = it)) },
        )
        PrefSwitch(
            label = "Require DNSSEC",
            checked = local.dnsCryptRequireDnssec,
            onChecked = { commit(local.copy(dnsCryptRequireDnssec = it)) },
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
            onClick = { commit(local, restart = true) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("Apply & restart tunnel")
        }
        Text(
            text = "Toggles and chips save immediately (firewall stays on when you leave). " +
                "Text fields flush when you leave Settings. “Apply & restart tunnel” reloads " +
                "Tor/DNSCrypt while Connected; otherwise changes apply on the next Start.",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun DnsCryptResolverPickerDialog(
    selected: String,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var query by remember { mutableStateOf("") }
    val resolvers = remember { DnsCryptPublicResolvers.all.filterNot { it.ipv6 } }
    val filtered = remember(query) {
        val q = query.trim()
        if (q.isEmpty()) {
            resolvers
        } else {
            resolvers.filter {
                it.name.contains(q, ignoreCase = true) ||
                    it.description.contains(q, ignoreCase = true)
            }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("DNSCrypt resolvers (${resolvers.size})") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text("Search") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Text(
                    text = "${filtered.size} match(es). Filters (no-log / DNSSEC / …) still apply.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LazyColumn(modifier = Modifier.heightIn(max = 420.dp)) {
                    item {
                        Text(
                            text = "Auto (all matching filters)",
                            style = MaterialTheme.typography.titleSmall,
                            color = if (selected == DnsCryptPublicResolvers.AUTO) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurface
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelect(DnsCryptPublicResolvers.AUTO) }
                                .padding(vertical = 10.dp),
                        )
                    }
                    items(filtered, key = { it.name }) { entry ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelect(entry.name) }
                                .padding(vertical = 8.dp),
                        ) {
                            Text(
                                text = entry.name,
                                style = MaterialTheme.typography.bodyLarge,
                                color = if (entry.name == selected) {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.onSurface
                                },
                            )
                            if (entry.description.isNotBlank()) {
                                Text(
                                    text = entry.description,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 2,
                                )
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

@Composable
private fun PrefSwitch(
    label: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = checked,
                role = Role.Switch,
                onValueChange = onChecked,
            ),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = null)
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
