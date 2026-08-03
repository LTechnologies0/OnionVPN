package ltechnologies.onionphone.onionvpn.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.onionvpn.R
import ltechnologies.onionphone.onionvpn.bridges.BuiltinBridges
import ltechnologies.onionphone.onionvpn.bridges.MoatCircumventionClient
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptPublicResolvers
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.FirewallDefaultAction
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode
import ltechnologies.onionphone.onionvpn.core.tor.config.TorBridgeConfig
import ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TunDataPlaneFactory
import ltechnologies.onionphone.onionvpn.threat.repo.DomainReputationRepository
import ltechnologies.onionphone.onionvpn.ui.components.SectionHeader
import ltechnologies.onionphone.onionvpn.ui.components.TonalSection
import ltechnologies.onionphone.onionvpn.ui.settings.DnsCryptResolverMultiPickerDialog
import ltechnologies.onionphone.onionvpn.ui.settings.PerAppVpnDialog
import ltechnologies.onionphone.onionvpn.ui.settings.TorCountryCatalog
import ltechnologies.onionphone.onionvpn.ui.settings.TorNodePickerDialog
import ltechnologies.onionphone.onionvpn.util.BatteryOptimization
import ltechnologies.onionphone.onionvpn.util.SystemSecurityIntents
@Composable
fun SettingsScreen(
    preferences: TunnelPreferences,
    domainReputation: DomainReputationRepository,
    onLoadTorrc: suspend () -> String,
    onLoadDnsCryptToml: suspend () -> String,
    onSavePreferences: (TunnelPreferences, restartIfConnected: Boolean) -> Unit,
    onSaveTorrc: (String) -> Unit,
    onSaveDnsCryptToml: (String) -> Unit,
    /** Engine currently driving the tunnel, or null when idle. */
    activeEngine: TorEngine? = null,
    torSocksPort: () -> Int? = { null },
    /** False while start/stop/restart/identity — disable Apply & engine-switch mash. */
    controlsEnabled: Boolean = true,
) {
    var local by remember(preferences) { mutableStateOf(preferences) }
    val caps = local.torEngine.capabilities
    val latestLocal = remember { AtomicReference(local) }
    val saveRef = remember { AtomicReference(onSavePreferences) }
    val persistedRef = remember { AtomicReference(preferences) }
    SideEffect {
        latestLocal.set(local)
        saveRef.set(onSavePreferences)
        persistedRef.set(preferences)
    }
    // Persist draft when leaving Settings only if dirty (avoid hammering Tor on tab switch).
    DisposableEffect(Unit) {
        onDispose {
            val draft = latestLocal.get()
            if (draft != persistedRef.get()) {
                saveRef.get().invoke(draft, false)
            }
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
    var pickingEntry by remember { mutableStateOf(false) }
    var pickingPerApp by remember { mutableStateOf(false) }
    var pickingExit by remember { mutableStateOf(false) }
    var pickingExclude by remember { mutableStateOf(false) }
    var requestingBridges by remember { mutableStateOf(false) }
    var bridgeRequestStatus by remember { mutableStateOf<String?>(null) }
    var pickBridgeTransport by remember { mutableStateOf(false) }
    var torrcDraft by remember { mutableStateOf("") }
    var tomlDraft by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val bridgeCtx = LocalContext.current

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
        val onionmasqNative = remember(context) {
            TunDataPlaneFactory.isOnionmasqNativePresent(context)
        }

        SectionHeader(
            title = "App security",
            subtitle = "Uses the Android / GrapheneOS screen lock (PIN, pattern, biometric). " +
                "The VPN tunnel and kill switch keep running while the UI is locked.",
        )
        TonalSection {
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
            PrefSwitch(
                label = "No logs (privacy)",
                checked = local.noLogsEnabled,
                onChecked = { commit(local.copy(noLogsEnabled = it)) },
            )
            Text(
                text = "On (release default): disables Logs buffer, pipeline TRACE→ERROR, " +
                    "Tor/Arti/DNSCrypt UI logs, and the resource profiler. " +
                    "Debug builds default Off so diagnostics stay available.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        SectionHeader(
            title = "Per-app VPN",
            subtitle = "Orbot-style: choose which apps use the Tor tunnel. " +
                "Apps off the VPN use clearnet (except Tor-native BYPASS, signature-pinned). " +
                "INCLUDE + Android lockdown is refused at connect. Restart tunnel to apply.",
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.vpnAppRoutingMode == VpnAppRoutingMode.ALL,
                onClick = {
                    commit(local.copy(vpnAppRoutingMode = VpnAppRoutingMode.ALL), restart = true)
                },
                enabled = controlsEnabled,
                label = { Text("All apps") },
            )
            FilterChip(
                selected = local.vpnAppRoutingMode == VpnAppRoutingMode.INCLUDE,
                onClick = {
                    commit(local.copy(vpnAppRoutingMode = VpnAppRoutingMode.INCLUDE), restart = true)
                },
                enabled = controlsEnabled,
                label = { Text("Only selected") },
            )
            FilterChip(
                selected = local.vpnAppRoutingMode == VpnAppRoutingMode.EXCLUDE,
                onClick = {
                    commit(local.copy(vpnAppRoutingMode = VpnAppRoutingMode.EXCLUDE), restart = true)
                },
                enabled = controlsEnabled,
                label = { Text("Exclude selected") },
            )
        }
        if (local.vpnAppRoutingMode == VpnAppRoutingMode.INCLUDE && local.vpnAppPackages.isNotEmpty()) {
            Text(
                text = "With Always-on VPN lockdown enabled, INCLUDE mode cannot connect " +
                    "(Tor-native apps would be offline or Tor-over-Tor). Use ALL/EXCLUDE, or disable lockdown.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        if (local.vpnAppRoutingMode != VpnAppRoutingMode.ALL) {
            OutlinedButton(
                onClick = { pickingPerApp = true },
                modifier = Modifier.fillMaxWidth(),
                enabled = controlsEnabled,
                shape = MaterialTheme.shapes.large,
            ) {
                Text("Choose apps (${local.vpnAppPackages.size})")
            }
            if (local.vpnAppRoutingMode == VpnAppRoutingMode.INCLUDE && local.vpnAppPackages.isEmpty()) {
                Text(
                    text = "Empty include list → full tunnel until you pick apps.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (pickingPerApp) {
            PerAppVpnDialog(
                selected = local.vpnAppPackages,
                onDismiss = { pickingPerApp = false },
                onConfirm = { pkgs ->
                    pickingPerApp = false
                    commit(local.copy(vpnAppPackages = pkgs), restart = true)
                },
            )
        }

        SectionHeader(
            title = "TUN data plane",
            subtitle = "hev→SOCKS is the shipped Orbot-class path. onionmasq (Arti TUN) " +
                "needs libonionmasq_mobile.so + Arti engine — otherwise HEV is used.",
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.tunDataPlane == TunDataPlane.HEV_SOCKS,
                onClick = {
                    commit(local.copy(tunDataPlane = TunDataPlane.HEV_SOCKS), restart = true)
                },
                enabled = controlsEnabled,
                label = { Text("hev SOCKS") },
            )
            FilterChip(
                selected = local.tunDataPlane == TunDataPlane.ONIONMASQ,
                onClick = {
                    commit(
                        local.copy(
                            tunDataPlane = TunDataPlane.ONIONMASQ,
                            torEngine = TorEngine.ARTI,
                        ),
                        restart = true,
                    )
                },
                enabled = controlsEnabled && onionmasqNative,
                label = {
                    Text(if (onionmasqNative) "onionmasq" else "onionmasq (lib missing)")
                },
            )
        }

        SectionHeader(
            title = "System leak protection",
            subtitle = "GrapheneOS improves VPN leak blocking when Always-on VPN + " +
                "“Block connections without VPN” are on. OnionVPN cannot flip those itself.",
        )
        FilledTonalButton(
            onClick = { SystemSecurityIntents.openVpnSettings(context) },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("Open VPN settings (Always-on / lockdown)")
        }
        OutlinedButton(
            onClick = { SystemSecurityIntents.openPrivateDnsSettings(context) },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("Open network settings (set Private DNS Off)")
        }
        PrefSwitch(
            label = "Require OS lockdown to connect",
            checked = local.requireOsLockdown,
            onChecked = { commit(local.copy(requireOsLockdown = it)) },
        )
        Text(
            text = "When on, Connected fails unless Always-on VPN lockdown is enabled for OnionVPN " +
                "(same hard gate style as Private DNS).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Allow ADB clearnet leak (wireless)",
            checked = local.allowAdbClearnetLeak,
            onChecked = { commit(local.copy(allowAdbClearnetLeak = it), restart = true) },
        )
        Text(
            text = "Off by default (fail-closed): wireless adbd / com.android.shell stays on the " +
                "tunnel. On = exclude shell from VPN so network ADB / MCP Wi‑Fi can use clearnet. " +
                "USB ADB is unaffected. Requires tunnel restart. Not available under INCLUDE+lockdown.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(
            onClick = {
                if (BatteryOptimization.needsWhitelisting(context)) {
                    runCatching {
                        context.startActivity(
                            BatteryOptimization.requestIgnoreIntent(context).addFlags(
                                android.content.Intent.FLAG_ACTIVITY_NEW_TASK,
                            ),
                        )
                    }.onFailure {
                        BatteryOptimization.openAppBatterySettings(context)
                    }
                } else {
                    BatteryOptimization.openAppBatterySettings(context)
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text(
                if (BatteryOptimization.needsWhitelisting(context)) {
                    "Allow background (battery / Doze whitelist)"
                } else {
                    "Battery optimization already unrestricted"
                },
            )
        }
        Text(
            text = "Checklist (Privacy Guides / GrapheneOS VPN leak blocking):\n" +
                "1. Always-on VPN → OnionVPN ON\n" +
                "2. Block connections without VPN ON (OS kill switch)\n" +
                "3. Private DNS → Off (DoT bypasses tunnel DNS)\n" +
                "4. Unrestricted battery (Doze whitelist) — asked on Connect\n" +
                "5. Stop other VPNs\n" +
                "6. Prefer Vanadium; disable WebRTC if possible",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        SectionHeader(
            title = "UDP / Tor Datagram",
            subtitle = "Tor has no deployed CONNECT_UDP (prop. 339). OnionVPN policy:\n" +
                "• UDP/53 (IPv4+IPv6) → DNSCrypt over Tor\n" +
                "• TCP IPv4+IPv6 → hev → Tor SOCKS (ATYP 0x01/0x04)\n" +
                "• QUIC/HTTP3, STUN/WebRTC, DTLS, WireGuard, mDNS, NTP → blackhole\n" +
                "• Apps fall back to TCP (HTTP/2, no real UDP)\n" +
                "• Zero clearnet UDP side-channel, zero remote UDP gateway",
        )

        SectionHeader(
            title = "PAC / proxy for apps",
            subtitle = "Stable URL (while tunnel is up):\n" +
                "${TunnelEndpoints.pacUrl()}\n\n" +
                "PAC points at socks5://${TunnelEndpoints.pacSocksBridge()} — a local bridge that:\n" +
                "1. Resolves names via DNSCrypt (not Tor DNSPort / exit DNS)\n" +
                "2. Applies the interactive firewall (same rules as TUN)\n" +
                "3. CONNECTs to Tor SocksPort by IPv4\n" +
                ".onion hostnames skip DNSCrypt and go to Tor as hostname.\n" +
                "Do not point apps at raw Tor SOCKS (that uses Tor DNS).",
        )

        SectionHeader(
            title = "DNS mode",
            subtitle = buildString {
                append("Clearnet names: DNSCrypt over Tor (encrypted stub, no system resolver).\n")
                when {
                    caps.nativeAutomapDnsPort ->
                        append(
                            ".onion / .exit: Tor DNSPort AutomapHostsOnResolve → virtual IP in " +
                                "${TunnelEndpoints.VIRTUAL_ADDR_NETWORK}/" +
                                "${TunnelEndpoints.VIRTUAL_ADDR_PREFIX_LEN}, " +
                                "then SOCKS5A with the real hostname (DNSCrypt never asked for onion).\n",
                        )
                    caps.synthesizeOnionAutomap ->
                        append(
                            ".onion / .exit: app Automap synth → virtual IP in " +
                                "${TunnelEndpoints.VIRTUAL_ADDR_NETWORK}/" +
                                "${TunnelEndpoints.VIRTUAL_ADDR_PREFIX_LEN}, " +
                                "then SOCKS5A with the real hostname (no native DNSPort Automap).\n",
                        )
                    else ->
                        append(".onion / .exit: engine-specific Automap path.\n")
                }
                append("FakeDNS option is legacy — both modes divert UDP/53 through TunDnsMux.")
            },
        )
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.dnsResolverMode == DnsResolverMode.DNSCRYPT_MUX,
                onClick = { commit(local.copy(dnsResolverMode = DnsResolverMode.DNSCRYPT_MUX)) },
                label = { Text("DNSCrypt over Tor") },
            )
            FilterChip(
                selected = local.dnsResolverMode == DnsResolverMode.FAKE_IP_SOCKS5A,
                onClick = { commit(local.copy(dnsResolverMode = DnsResolverMode.FAKE_IP_SOCKS5A)) },
                label = { Text("Legacy FakeDNS→DNSCrypt") },
            )
        }

        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surfaceContainerHighest,
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Text(
                    "Full-tunnel IPv4+IPv6 (mandatory)",
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    text = "Always installs default routes (0.0.0.0/0 + ::/0) and claims both " +
                        "address families on Android 10+. Split-tunnel is not offered — " +
                        "partial routes would clearnet-leak.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.medium,
            color = MaterialTheme.colorScheme.surfaceContainerHighest,
        ) {
            Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                Text(
                    "Kill switch (always on)",
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    text = "Blocking TUN before Tor bootstrap and on hard wiring/leak fails. " +
                        "Cannot be disabled — working Tor traffic is never blackholed for Soft " +
                        "warnings. Also enable system Always-on VPN + Lockdown and Private DNS Off. " +
                        "Hard Block: other VPN owns Always-on, active DoT, missing routes, dead " +
                        "Tor SOCKS, or DNSCrypt not over Tor.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        PrefSwitch(
            label = "Start tunnel when app opens",
            checked = local.autoStartOnAppLaunch,
            onChecked = { commit(local.copy(autoStartOnAppLaunch = it), restart = false) },
        )
        Text(
            text = "Requests VPN permission if needed, then brings up Tor + DNSCrypt + TUN. " +
                "Runs even while the UI lock screen is showing. Turn off to start manually.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Start tunnel at device boot",
            checked = local.autoStartOnBoot,
            onChecked = { commit(local.copy(autoStartOnBoot = it), restart = false) },
        )
        Text(
            text = "Off by default. After reboot, starts Tor + DNSCrypt + TUN only if VPN " +
                "permission was already granted (open the app once first). " +
                "Also enable system Always-on VPN for strongest coverage.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        SectionHeader(
            title = "Interactive firewall",
            subtitle = buildString {
                append(
                    "OpenSnitch-style prompts for new outbound connections on the TUN. " +
                        "Requests wait in a FIFO queue (one at a time) until you answer — no timeout. " +
                        "A heads-up notification shows the app icon with Accept / Deny " +
                        "(permanent rule). Tap the notification for more scope options. ",
                )
                if (caps.socksAuthIsolation) {
                    append("Tor streams are isolated per app UID (SOCKS5 USERNAME/PASSWORD → u{uid})")
                    if (!caps.multiSocksSessionGroups) {
                        append(" on a shared SocksPort (no SessionGroups)")
                    }
                    append(".")
                }
            },
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

        SectionHeader(
            title = stringResource(R.string.domain_lists_title),
            subtitle = stringResource(R.string.domain_lists_desc),
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
                reputation.sourceFilesCached,
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

        SectionHeader(
            title = "Tor",
            subtitle = local.torEngine.settingsSubtitle(),
        )
        if (activeEngine != null && activeEngine != local.torEngine) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
                color = MaterialTheme.colorScheme.errorContainer,
            ) {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                    Text(
                        "Engine mismatch",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    Text(
                        text = "Settings prefer ${local.torEngine.displayName}, but the tunnel is " +
                            "running ${activeEngine.displayName}. Use “Apply & restart tunnel”.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
        }
        Text(
            text = "Tor engine",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = local.torEngine.enginePickerHint(),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = local.torEngine == TorEngine.LITTLE_T,
                onClick = {
                    commit(
                        local.copy(
                            torEngine = TorEngine.LITTLE_T,
                            tunDataPlane = TunDataPlane.HEV_SOCKS,
                        ),
                        restart = true,
                    )
                },
                enabled = controlsEnabled,
                label = { Text("C Tor") },
            )
            FilterChip(
                selected = local.torEngine == TorEngine.ARTI,
                onClick = {
                    val plane =
                        if (TunDataPlaneFactory.isOnionmasqNativePresent(context)) {
                            TunDataPlane.ONIONMASQ
                        } else {
                            TunDataPlane.HEV_SOCKS
                        }
                    commit(
                        local.copy(torEngine = TorEngine.ARTI, tunDataPlane = plane),
                        restart = true,
                    )
                },
                enabled = controlsEnabled,
                label = { Text("Arti") },
            )
        }
        if (caps.liveSetConf && local.tunDataPlane != TunDataPlane.ONIONMASQ) {
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = local.torNewCircuitPeriodSec == 30 &&
                        local.torMaxCircuitDirtinessSec == 600,
                    onClick = {
                        commit(
                            local.copy(
                                torNewCircuitPeriodSec = 30,
                                torMaxCircuitDirtinessSec = 600,
                            ),
                        )
                    },
                    label = { Text("Stable") },
                )
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
        } else if (caps.liveCircuitTiming && local.tunDataPlane != TunDataPlane.ONIONMASQ) {
            Row(
                modifier = Modifier.horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilterChip(
                    selected = local.torMaxCircuitDirtinessSec == 600,
                    onClick = {
                        commit(
                            local.copy(
                                torNewCircuitPeriodSec =
                                    local.torNewCircuitPeriodSec.coerceAtLeast(3_600),
                                torMaxCircuitDirtinessSec = 600,
                            ),
                        )
                    },
                    label = { Text("Stable dirtiness") },
                )
                FilterChip(
                    selected = local.torMaxCircuitDirtinessSec == 180,
                    onClick = {
                        commit(
                            local.copy(
                                torNewCircuitPeriodSec =
                                    local.torNewCircuitPeriodSec.coerceAtLeast(3_600),
                                torMaxCircuitDirtinessSec = 180,
                            ),
                        )
                    },
                    label = { Text("Balanced dirtiness") },
                )
                FilterChip(
                    selected = local.torMaxCircuitDirtinessSec == 60,
                    onClick = {
                        commit(
                            local.copy(
                                torNewCircuitPeriodSec =
                                    local.torNewCircuitPeriodSec.coerceAtLeast(3_600),
                                torMaxCircuitDirtinessSec = 60,
                            ),
                        )
                    },
                    label = { Text("Paranoid dirtiness") },
                )
            }
        } else if (local.tunDataPlane == TunDataPlane.ONIONMASQ) {
            Text(
                text = "onionmasq: no live MaxCircuitDirtiness API (Tor VPN same). " +
                    "Use New Identity / exit country; Arti Ext timing applies only on hev+arti-mobile.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            text = "Tor bridges",
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            text = if (caps.conjureBridges) {
                "Presets paste built-in Tor Browser PT lines (Lyrebird / Conjure). " +
                    "Request from Tor Project uses Moat (obfs4 / Snowflake / WebTunnel). " +
                    "WebTunnel gets utls=none so Lyrebird uses stdlib TLS. " +
                    "Apply & restart tunnel after changing."
            } else {
                "Lyrebird-backed bridges (obfs4 / Snowflake / meek / WebTunnel). " +
                    "Conjure is unavailable on this engine. Apply & restart tunnel after changing."
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        val bridgePreset = remember(local.torBridges) {
            BuiltinBridges.detectPreset(bridgeCtx, local.torBridges)
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilterChip(
                selected = bridgePreset == BuiltinBridges.PRESET_OFF,
                onClick = { commit(local.copy(torBridges = ""), restart = false) },
                label = { Text("Off") },
            )
            FilterChip(
                selected = bridgePreset == BuiltinBridges.PRESET_OBFS4,
                onClick = {
                    commit(
                        local.copy(torBridges = BuiltinBridges.linesForPreset(bridgeCtx, BuiltinBridges.PRESET_OBFS4)),
                        restart = false,
                    )
                },
                label = { Text("obfs4") },
            )
            FilterChip(
                selected = bridgePreset == BuiltinBridges.PRESET_SNOWFLAKE,
                onClick = {
                    commit(
                        local.copy(
                            torBridges = BuiltinBridges.linesForPreset(
                                bridgeCtx,
                                BuiltinBridges.PRESET_SNOWFLAKE,
                            ),
                        ),
                        restart = false,
                    )
                },
                label = { Text("Snowflake") },
            )
            FilterChip(
                selected = bridgePreset == BuiltinBridges.PRESET_MEEK,
                onClick = {
                    commit(
                        local.copy(
                            torBridges = BuiltinBridges.linesForPreset(
                                bridgeCtx,
                                BuiltinBridges.PRESET_MEEK,
                            ),
                        ),
                        restart = false,
                    )
                },
                label = { Text("meek") },
            )
            FilterChip(
                selected = bridgePreset == BuiltinBridges.PRESET_CUSTOM,
                onClick = { /* keep text */ },
                label = { Text("Own list") },
            )
        }
        PrefSwitch(
            label = "Request bridges via Tor",
            checked = local.moatRequestViaTor,
            onChecked = { commit(local.copy(moatRequestViaTor = it), restart = false) },
        )
        Text(
            text = "Off = clearnet HTTPS to bridges.torproject.org (default). " +
                "On = Moat through Tor SOCKS (needed when the site is blocked; tunnel must be up).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            FilledTonalButton(
                onClick = { pickBridgeTransport = true },
                enabled = !requestingBridges,
                modifier = Modifier.weight(1f),
                shape = MaterialTheme.shapes.large,
            ) {
                Text(if (requestingBridges) "Requesting…" else "Request bridges")
            }
            OutlinedButton(
                onClick = {
                    val cm = bridgeCtx.getSystemService(android.content.Context.CLIPBOARD_SERVICE)
                        as android.content.ClipboardManager
                    val text = cm.primaryClip?.getItemAt(0)?.coerceToText(bridgeCtx)?.toString().orEmpty()
                    if (text.isNotBlank()) {
                        commit(local.copy(torBridges = text.trim()), restart = false)
                        bridgeRequestStatus = "Pasted ${text.lines().count { it.isNotBlank() }} line(s)"
                    } else {
                        bridgeRequestStatus = "Clipboard empty"
                    }
                },
                modifier = Modifier.weight(1f),
                shape = MaterialTheme.shapes.large,
            ) {
                Text("Add from clipboard")
            }
        }
        bridgeRequestStatus?.let { status ->
            Text(
                text = status,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (pickBridgeTransport) {
            AlertDialog(
                onDismissRequest = { pickBridgeTransport = false },
                title = { Text("Bridge transport") },
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(
                            "Ask Tor Project (Moat) for bridge lines.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        listOf(
                            "obfs4" to "obfs4 (recommended)",
                            "snowflake" to "Snowflake",
                            "webtunnel" to "WebTunnel",
                        ).forEach { (transport, label) ->
                            TextButton(
                                onClick = {
                                    pickBridgeTransport = false
                                    requestingBridges = true
                                    bridgeRequestStatus = "Contacting bridges.torproject.org…"
                                    scope.launch {
                                        runCatching {
                                            val socks = torSocksPort()
                                            val outcome = MoatCircumventionClient.fetchBridges(
                                                transport = transport,
                                                viaTor = local.moatRequestViaTor || socks != null,
                                                socksPort = socks,
                                            )
                                            val normalized = TorBridgeConfig.parseLines(
                                                outcome.lines.joinToString("\n"),
                                            )
                                            val joined = normalized.joinToString("\n")
                                            commit(local.copy(torBridges = joined), restart = false)
                                            bridgeRequestStatus = buildString {
                                                append("Got ${normalized.size} ${outcome.transport} line(s)")
                                                append(" (${outcome.source}")
                                                outcome.country?.let { append(", $it") }
                                                append(")")
                                                outcome.note?.let { append(" — $it") }
                                            }
                                        }.onFailure { e ->
                                            bridgeRequestStatus = "Request failed: ${e.message}"
                                        }
                                        requestingBridges = false
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(label)
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { pickBridgeTransport = false }) { Text("Cancel") }
                },
            )
        }
        OutlinedTextField(
            value = local.torBridges,
            onValueChange = { local = local.copy(torBridges = it) },
            label = { Text("Bridge lines (own list)") },
            modifier = Modifier
                .fillMaxWidth()
                .height(120.dp),
            minLines = 3,
        )
        Text(
            text = "Node countries (StrictNodes)",
            style = MaterialTheme.typography.titleMedium,
        )
        when {
            caps.nodePrefs -> {
                Text(
                    text = "Pick countries / federations. Tor syntax: {cc},{cc}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            caps.exitCountryPrefs -> {
                Text(
                    text = "ExitNodes: pick a single country ({cc}). " +
                        "EntryNodes / ExcludeNodes need an engine with full node prefs (C Tor).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            else -> {
                Text(
                    text = "Entry/Exit/ExcludeNodes are unavailable on this engine.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        if (caps.nodePrefs || caps.exitCountryPrefs) {
        val onionExitCatalog = OnionVpnService.circuitRepository.relaysByCountry
        if (onionExitCatalog.isNotEmpty() && local.tunDataPlane == TunDataPlane.ONIONMASQ) {
            Text(
                text = "Directory exits (onionmasq): " +
                    onionExitCatalog.entries.sortedByDescending { it.value }
                        .take(8)
                        .joinToString { "${it.key}=${it.value}" },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (caps.nodePrefs) {
        OutlinedButton(
            onClick = { pickingEntry = true },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("EntryNodes — ${TorCountryCatalog.summarize(local.torEntryNodes)}")
        }
        }
        OutlinedButton(
            onClick = { pickingExit = true },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("ExitNodes — ${TorCountryCatalog.summarize(local.torExitNodes)}")
        }
        if (caps.nodePrefs) {
        OutlinedButton(
            onClick = { pickingExclude = true },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("ExcludeNodes — ${TorCountryCatalog.summarize(local.torExcludeNodes)}")
        }
        }
        if (pickingEntry && caps.nodePrefs) {
            TorNodePickerDialog(
                title = "EntryNodes",
                initialRaw = local.torEntryNodes,
                onConfirm = {
                    commit(local.copy(torEntryNodes = it), restart = false)
                    pickingEntry = false
                },
                onDismiss = { pickingEntry = false },
            )
        }
        if (pickingExit) {
            TorNodePickerDialog(
                title = if (caps.nodePrefs) "ExitNodes" else "ExitNodes (single country)",
                initialRaw = local.torExitNodes,
                onConfirm = {
                    val next = if (!caps.nodePrefs) {
                        val codes = TorCountryCatalog.parseNodeCodes(it)
                        when {
                            codes.isEmpty() -> ""
                            codes.size == 1 -> TorCountryCatalog.encodeNodeCodes(codes)
                            else -> TorCountryCatalog.encodeNodeCodes(setOf(codes.first())).also {
                                // Keep first only for Arti StreamPrefs::exit_country
                            }
                        }
                    } else {
                        it
                    }
                    commit(local.copy(torExitNodes = next), restart = false)
                    // Live apply under onionmasq (Tor VPN ExitSelection pattern).
                    // Never probe JNI before init — runCatching cannot catch SIGABRT.
                    if (local.tunDataPlane == TunDataPlane.ONIONMASQ &&
                        org.torproject.onionmasq.OnionMasq.isInitialized() &&
                        org.torproject.onionmasq.OnionMasq.isRunning()
                    ) {
                        val cc = TorCountryCatalog.parseNodeCodes(next).firstOrNull()
                        scope.launch(Dispatchers.IO) {
                            runCatching {
                                if (cc.isNullOrBlank()) {
                                    org.torproject.onionmasq.OnionMasq.setCountryCode(null)
                                } else {
                                    org.torproject.onionmasq.OnionMasq.setCountryCode(cc.uppercase())
                                }
                                org.torproject.onionmasq.OnionMasq.refreshCircuits()
                            }.onFailure { timber.log.Timber.w(it, "live exit country apply") }
                        }
                    }
                    pickingExit = false
                },
                onDismiss = { pickingExit = false },
            )
        }
        if (pickingExclude && caps.nodePrefs) {
            TorNodePickerDialog(
                title = "ExcludeNodes",
                initialRaw = local.torExcludeNodes,
                onConfirm = {
                    commit(local.copy(torExcludeNodes = it), restart = false)
                    pickingExclude = false
                },
                onDismiss = { pickingExclude = false },
            )
        }
        }
        val showCircuitTimingFields = (caps.liveSetConf && local.tunDataPlane != TunDataPlane.ONIONMASQ) ||
            caps.torrcConfig ||
            (caps.liveCircuitTiming && local.tunDataPlane != TunDataPlane.ONIONMASQ)
        if (showCircuitTimingFields) {
            val artiTiming = caps.liveCircuitTiming && !caps.torrcConfig
            OutlinedTextField(
                value = local.torNewCircuitPeriodSec.toString(),
                onValueChange = {
                    it.toIntOrNull()?.let { v ->
                        val min = if (artiTiming) 3_600 else 10
                        local = local.copy(torNewCircuitPeriodSec = v.coerceIn(min, 86_400))
                    }
                },
                label = {
                    Text(
                        if (artiTiming) {
                            "prediction_lifetime (sec, ≥3600)"
                        } else {
                            "NewCircuitPeriod (sec)"
                        },
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            )
            Text(
                text = if (artiTiming) {
                    "max_dirtiness (sec) — unused-circuit expiry via Ext JNI. " +
                        "prediction_lifetime is floored at 3600s (not a 1:1 NewCircuitPeriod map)."
                } else {
                    "MaxCircuitDirtiness (sec) — unused-circuit expiry. " +
                        "App SocksPort uses KeepAliveIsolateSOCKSAuth with per-UID tokens (sticky)."
                },
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
                label = {
                    Text(
                        if (artiTiming) "max_dirtiness (sec)" else "MaxCircuitDirtiness (sec)",
                    )
                },
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (caps.torrcConfig) {
            FilledTonalButton(
                onClick = {
                    scope.launch {
                        torrcDraft = onLoadTorrc()
                        editingTorrc = true
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
            ) {
                Text("Edit torrc")
            }
        }

        SectionHeader(
            title = "DNSCrypt",
            subtitle = "Upstream forced through Tor SOCKS; bootstrap via Tor DNSPort; " +
                "full public-resolvers catalog (${DnsCryptPublicResolvers.knownServers.size} IPv4). " +
                "Auto uses every resolver matching the filters below.",
        )
        FilledTonalButton(
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
            shape = MaterialTheme.shapes.large,
        ) {
            Text("Apply hardened DNSCrypt profile")
        }
        val resolverSummary = remember(local.dnsCryptServerName) {
            val names = DnsCryptPublicResolvers.resolveNames(local.dnsCryptServerName)
            when {
                names.size == 1 && names[0] == DnsCryptPublicResolvers.AUTO -> "Auto (all matching)"
                names.size == 1 -> names[0]
                else -> "${names.size} resolvers"
            }
        }
        OutlinedButton(
            onClick = { pickingResolver = true },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("DNSCrypt resolvers — $resolverSummary")
        }
        if (pickingResolver) {
            DnsCryptResolverMultiPickerDialog(
                selectedRaw = local.dnsCryptServerName,
                onConfirm = {
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
        Text(
            text = "Force TCP to upstream — always on (required for DNSCrypt-over-Tor).",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (!local.dnsCryptForceTcp) {
            SideEffect { commit(local.copy(dnsCryptForceTcp = true)) }
        }
        PrefSwitch(
            label = "Require DNSSEC",
            checked = local.dnsCryptRequireDnssec,
            onChecked = { commit(local.copy(dnsCryptRequireDnssec = it)) },
        )
        PrefSwitch(
            label = "Anonymized DNSCrypt (relays)",
            checked = local.dnsCryptAnonymized,
            onChecked = { commit(local.copy(dnsCryptAnonymized = it), restart = true) },
        )
        Text(
            text = "Adds a relay hop when the pinned dnscrypt-proxy supports [anonymized_dns]. " +
                "Filters out resolvers marked incompatible with anonymization.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PrefSwitch(
            label = "Prefer DNS query padding",
            checked = local.dnsCryptQueryPadding,
            onChecked = { commit(local.copy(dnsCryptQueryPadding = it), restart = true) },
        )
        PrefSwitch(
            label = "Block EDNS Client Subnet",
            checked = local.dnsCryptBlockEcs,
            onChecked = { commit(local.copy(dnsCryptBlockEcs = it), restart = true) },
        )
        OutlinedButton(
            onClick = {
                scope.launch {
                    tomlDraft = onLoadDnsCryptToml()
                    editingToml = true
                }
            },
            modifier = Modifier.fillMaxWidth(),
            shape = MaterialTheme.shapes.large,
        ) {
            Text("Edit dnscrypt-proxy.toml")
        }

        Button(
            onClick = { commit(local, restart = true) },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            enabled = controlsEnabled,
            shape = MaterialTheme.shapes.large,
        ) {
            Text(
                if (controlsEnabled) "Apply & restart tunnel" else "Tunnel busy…",
            )
        }
        Text(
            text = "Toggles and chips save immediately (firewall stays on when you leave). " +
                "Text fields flush when you leave Settings. “Apply & restart tunnel” reloads " +
                "Tor/DNSCrypt while Connected; otherwise changes apply on the next Start.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun PrefSwitch(
    label: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(
                value = checked,
                role = Role.Switch,
                onValueChange = onChecked,
            ),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                label,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyLarge,
            )
            Switch(checked = checked, onCheckedChange = null)
        }
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
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SectionHeader(title = title)
        OutlinedTextField(
            value = text,
            onValueChange = onTextChange,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            textStyle = MaterialTheme.typography.bodySmall,
            shape = MaterialTheme.shapes.large,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp),
                shape = MaterialTheme.shapes.large,
            ) { Text("Cancel") }
            Button(
                onClick = onSave,
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp),
                shape = MaterialTheme.shapes.large,
            ) { Text("Save") }
        }
    }
}
