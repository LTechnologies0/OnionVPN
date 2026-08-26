package ltechnologies.onionphone.onionvpn.prefs

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.FirewallDefaultAction
import ltechnologies.onionphone.onionvpn.core.model.TorEngine
import ltechnologies.onionphone.onionvpn.core.model.TunDataPlane
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.VpnAppRoutingMode
import ltechnologies.onionphone.onionvpn.ui.settings.TorCountryCatalog
import timber.log.Timber

private val Context.tunnelDataStore: DataStore<Preferences> by preferencesDataStore(name = "tunnel_prefs")

@Singleton
class TunnelPreferencesStore @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private object Keys {
        val routeAll = booleanPreferencesKey("route_all")
        val killSwitch = booleanPreferencesKey("kill_switch")
        val dnsServer = stringPreferencesKey("dns_server")
        val dnsMode = stringPreferencesKey("dns_mode")
        val torEngine = stringPreferencesKey("tor_engine")
        val torBridges = stringPreferencesKey("tor_bridges")
        val torEntry = stringPreferencesKey("tor_entry")
        val torExit = stringPreferencesKey("tor_exit")
        val torExclude = stringPreferencesKey("tor_exclude")
        val newCircuit = intPreferencesKey("tor_new_circuit")
        val maxDirtiness = intPreferencesKey("tor_max_dirtiness")
        val requireNoLog = booleanPreferencesKey("dns_nolog")
        val requireNoFilter = booleanPreferencesKey("dns_nofilter")
        val forceTcp = booleanPreferencesKey("dns_force_tcp")
        val requireDnssec = booleanPreferencesKey("dns_dnssec")
        val dnsAnonymized = booleanPreferencesKey("dns_anonymized")
        val dnsQueryPadding = booleanPreferencesKey("dns_query_padding")
        val dnsBlockEcs = booleanPreferencesKey("dns_block_ecs")
        val requireOsLockdown = booleanPreferencesKey("require_os_lockdown")
        val firewallEnabled = booleanPreferencesKey("firewall_enabled")
        val firewallDefault = stringPreferencesKey("firewall_default")
        val firewallTempMin = intPreferencesKey("firewall_temp_min")
        val appLock = booleanPreferencesKey("app_lock")
        val allowScreenshots = booleanPreferencesKey("allow_screenshots")
        val autoStartOnLaunch = booleanPreferencesKey("auto_start_on_launch")
        val autoStartOnBoot = booleanPreferencesKey("auto_start_on_boot")
        val moatRequestViaTor = booleanPreferencesKey("moat_request_via_tor")
        val noLogs = booleanPreferencesKey("no_logs")
        val vpnAppMode = stringPreferencesKey("vpn_app_mode")
        val vpnAppPackages = stringPreferencesKey("vpn_app_packages")
        val allowAdbClearnetLeak = booleanPreferencesKey("allow_adb_clearnet_leak")
        val tunDataPlane = stringPreferencesKey("tun_data_plane")
        val openVpnOverTor = booleanPreferencesKey("openvpn_over_tor")
        val openVpnProfileConfigured = booleanPreferencesKey("openvpn_profile_configured")
        val openVpnAuthUser = stringPreferencesKey("openvpn_auth_user")
        val openVpnAuthPassword = stringPreferencesKey("openvpn_auth_password")
        val welcomeCompleted = booleanPreferencesKey("welcome_completed")
    }

    /**
     * Debug APK (`FLAG_DEBUGGABLE`): looser defaults for MCP / wireless ADB / Logs.
     * Release APK: fail-closed defaults for public users.
     */
    private val isDebuggable: Boolean
        get() = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    val preferences: Flow<TunnelPreferences> = context.tunnelDataStore.data.map { prefs ->
        prefs.toModel()
    }

    suspend fun update(transform: (TunnelPreferences) -> TunnelPreferences) {
        context.tunnelDataStore.edit { prefs ->
            val next = transform(prefs.toModel())
            // Release never persists ADB clearnet leak — strip even if UI was bypassed.
            val toWrite = if (isDebuggable) {
                next
            } else {
                next.copy(allowAdbClearnetLeak = false)
            }
            prefs[Keys.routeAll] = toWrite.routeAllTrafficThroughTor
            prefs[Keys.killSwitch] = true // constant — never persist off
            prefs[Keys.dnsServer] = toWrite.dnsCryptServerName
            prefs[Keys.dnsMode] = toWrite.dnsResolverMode.name
            prefs[Keys.torEngine] = toWrite.torEngine.name
            prefs[Keys.torBridges] = toWrite.torBridges
            prefs[Keys.torEntry] = toWrite.torEntryNodes
            prefs[Keys.torExit] = toWrite.torExitNodes
            prefs[Keys.torExclude] = toWrite.torExcludeNodes
            prefs[Keys.newCircuit] = toWrite.torNewCircuitPeriodSec
            prefs[Keys.maxDirtiness] = toWrite.torMaxCircuitDirtinessSec
            prefs[Keys.requireNoLog] = toWrite.dnsCryptRequireNoLog
            prefs[Keys.requireNoFilter] = toWrite.dnsCryptRequireNoFilter
            prefs[Keys.forceTcp] = toWrite.dnsCryptForceTcp
            prefs[Keys.requireDnssec] = toWrite.dnsCryptRequireDnssec
            prefs[Keys.dnsAnonymized] = toWrite.dnsCryptAnonymized
            prefs[Keys.dnsQueryPadding] = toWrite.dnsCryptQueryPadding
            prefs[Keys.dnsBlockEcs] = toWrite.dnsCryptBlockEcs
            prefs[Keys.requireOsLockdown] = toWrite.requireOsLockdown
            prefs[Keys.firewallEnabled] = toWrite.firewallEnabled
            prefs[Keys.firewallDefault] = toWrite.firewallDefaultAction.name
            prefs[Keys.firewallTempMin] = toWrite.firewallTempMinutes
            prefs[Keys.appLock] = toWrite.appLockEnabled
            prefs[Keys.allowScreenshots] = toWrite.allowScreenshots
            prefs[Keys.autoStartOnLaunch] = toWrite.autoStartOnAppLaunch
            prefs[Keys.autoStartOnBoot] = toWrite.autoStartOnBoot
            prefs[Keys.moatRequestViaTor] = toWrite.moatRequestViaTor
            prefs[Keys.noLogs] = toWrite.noLogsEnabled
            prefs[Keys.vpnAppMode] = toWrite.vpnAppRoutingMode.name
            prefs[Keys.vpnAppPackages] = toWrite.vpnAppPackages.sorted().joinToString("\n")
            prefs[Keys.allowAdbClearnetLeak] = toWrite.allowAdbClearnetLeak
            prefs[Keys.tunDataPlane] = toWrite.tunDataPlane.name
            prefs[Keys.openVpnOverTor] = toWrite.openVpnOverTorEnabled
            prefs[Keys.openVpnProfileConfigured] = toWrite.openVpnProfileConfigured
            prefs[Keys.openVpnAuthUser] = toWrite.openVpnAuthUser
            prefs[Keys.openVpnAuthPassword] = toWrite.openVpnAuthPassword
            prefs[Keys.welcomeCompleted] = toWrite.welcomeCompleted
            Timber.d(
                "TunnelPreferences updated engine=%s plane=%s firewall=%s noLogs=%s ovpn=%s",
                toWrite.torEngine,
                toWrite.tunDataPlane,
                toWrite.firewallEnabled,
                toWrite.noLogsEnabled,
                toWrite.openVpnOverTorEnabled,
            )
        }
    }

    private fun Preferences.toModel(): TunnelPreferences = TunnelPreferences(
        routeAllTrafficThroughTor = this[Keys.routeAll] ?: true,
        killSwitchEnabled = true, // constant app kill-switch
        dnsCryptServerName = this[Keys.dnsServer] ?: "cloudflare",
        dnsResolverMode = this[Keys.dnsMode]
            ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
            ?: DnsResolverMode.DNSCRYPT_MUX,
        torEngine = TorEngine.fromPreference(this[Keys.torEngine]),
        torBridges = this[Keys.torBridges].orEmpty(),
        torEntryNodes = this[Keys.torEntry].orEmpty(),
        torExitNodes = this[Keys.torExit].orEmpty(),
        torExcludeNodes = TorCountryCatalog.ensureTorGeoIpEuInEuropeanExcludes(
            this[Keys.torExclude].orEmpty(),
        ),
        torNewCircuitPeriodSec = this[Keys.newCircuit] ?: 30,
        torMaxCircuitDirtinessSec = this[Keys.maxDirtiness] ?: 600,
        dnsCryptRequireNoLog = this[Keys.requireNoLog] ?: true,
        dnsCryptRequireNoFilter = this[Keys.requireNoFilter] ?: false,
        dnsCryptForceTcp = this[Keys.forceTcp] ?: true,
        dnsCryptRequireDnssec = this[Keys.requireDnssec] ?: true,
        dnsCryptAnonymized = this[Keys.dnsAnonymized] ?: false,
        dnsCryptQueryPadding = this[Keys.dnsQueryPadding] ?: true,
        dnsCryptBlockEcs = this[Keys.dnsBlockEcs] ?: true,
        requireOsLockdown = this[Keys.requireOsLockdown] ?: !isDebuggable,
        // Via OVPN needs the interactive firewall; never leave OVPN mode with firewall off.
        firewallEnabled = when {
            (this[Keys.openVpnOverTor] == true) -> true
            else -> this[Keys.firewallEnabled] ?: true
        },
        firewallDefaultAction = this[Keys.firewallDefault]
            ?.let { runCatching { FirewallDefaultAction.valueOf(it) }.getOrNull() }
            ?: FirewallDefaultAction.ASK,
        firewallTempMinutes = this[Keys.firewallTempMin] ?: 5,
        // Debug: MCP/adb can launch MainActivity without device PIN.
        appLockEnabled = this[Keys.appLock] ?: !isDebuggable,
        allowScreenshots = this[Keys.allowScreenshots] ?: false,
        autoStartOnAppLaunch = this[Keys.autoStartOnLaunch] ?: !isDebuggable,
        autoStartOnBoot = this[Keys.autoStartOnBoot] ?: !isDebuggable,
        moatRequestViaTor = this[Keys.moatRequestViaTor] ?: false,
        noLogsEnabled = this[Keys.noLogs] ?: !isDebuggable,
        vpnAppRoutingMode = this[Keys.vpnAppMode]
            ?.let { runCatching { VpnAppRoutingMode.valueOf(it) }.getOrNull() }
            ?: if (isDebuggable) VpnAppRoutingMode.EXCLUDE else VpnAppRoutingMode.ALL,
        vpnAppPackages = this[Keys.vpnAppPackages]
            ?.lineSequence()
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toSet()
            ?: emptySet(),
        // Release: always false (option removed from UI). Debug: default on for wireless ADB.
        allowAdbClearnetLeak = if (isDebuggable) {
            this[Keys.allowAdbClearnetLeak] ?: true
        } else {
            false
        },
        tunDataPlane = TunDataPlane.fromPreference(this[Keys.tunDataPlane]),
        openVpnOverTorEnabled = this[Keys.openVpnOverTor] ?: false,
        openVpnProfileConfigured = this[Keys.openVpnProfileConfigured] ?: false,
        openVpnAuthUser = this[Keys.openVpnAuthUser].orEmpty(),
        openVpnAuthPassword = this[Keys.openVpnAuthPassword].orEmpty(),
        welcomeCompleted = this[Keys.welcomeCompleted] ?: false,
    )
}
