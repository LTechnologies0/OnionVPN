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
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences

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
        val firewallEnabled = booleanPreferencesKey("firewall_enabled")
        val firewallDefault = stringPreferencesKey("firewall_default")
        val firewallTempMin = intPreferencesKey("firewall_temp_min")
        val appLock = booleanPreferencesKey("app_lock")
        val allowScreenshots = booleanPreferencesKey("allow_screenshots")
        val autoStartOnLaunch = booleanPreferencesKey("auto_start_on_launch")
        val autoStartOnBoot = booleanPreferencesKey("auto_start_on_boot")
        val moatRequestViaTor = booleanPreferencesKey("moat_request_via_tor")
        val noLogs = booleanPreferencesKey("no_logs")
    }

    /** Release (non-debuggable) → no-logs ON; debug builds → OFF. */
    private val defaultNoLogsEnabled: Boolean
        get() = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) == 0

    val preferences: Flow<TunnelPreferences> = context.tunnelDataStore.data.map { prefs ->
        prefs.toModel()
    }

    suspend fun update(transform: (TunnelPreferences) -> TunnelPreferences) {
        context.tunnelDataStore.edit { prefs ->
            val next = transform(prefs.toModel())
            prefs[Keys.routeAll] = next.routeAllTrafficThroughTor
            prefs[Keys.killSwitch] = true // constant — never persist off
            prefs[Keys.dnsServer] = next.dnsCryptServerName
            prefs[Keys.dnsMode] = next.dnsResolverMode.name
            prefs[Keys.torEngine] = next.torEngine.name
            prefs[Keys.torBridges] = next.torBridges
            prefs[Keys.torEntry] = next.torEntryNodes
            prefs[Keys.torExit] = next.torExitNodes
            prefs[Keys.torExclude] = next.torExcludeNodes
            prefs[Keys.newCircuit] = next.torNewCircuitPeriodSec
            prefs[Keys.maxDirtiness] = next.torMaxCircuitDirtinessSec
            prefs[Keys.requireNoLog] = next.dnsCryptRequireNoLog
            prefs[Keys.requireNoFilter] = next.dnsCryptRequireNoFilter
            prefs[Keys.forceTcp] = next.dnsCryptForceTcp
            prefs[Keys.requireDnssec] = next.dnsCryptRequireDnssec
            prefs[Keys.firewallEnabled] = next.firewallEnabled
            prefs[Keys.firewallDefault] = next.firewallDefaultAction.name
            prefs[Keys.firewallTempMin] = next.firewallTempMinutes
            prefs[Keys.appLock] = next.appLockEnabled
            prefs[Keys.allowScreenshots] = next.allowScreenshots
            prefs[Keys.autoStartOnLaunch] = next.autoStartOnAppLaunch
            prefs[Keys.autoStartOnBoot] = next.autoStartOnBoot
            prefs[Keys.moatRequestViaTor] = next.moatRequestViaTor
            prefs[Keys.noLogs] = next.noLogsEnabled
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
        torExcludeNodes = this[Keys.torExclude].orEmpty(),
        torNewCircuitPeriodSec = this[Keys.newCircuit] ?: 30,
        torMaxCircuitDirtinessSec = this[Keys.maxDirtiness] ?: 600,
        dnsCryptRequireNoLog = this[Keys.requireNoLog] ?: true,
        dnsCryptRequireNoFilter = this[Keys.requireNoFilter] ?: false,
        dnsCryptForceTcp = this[Keys.forceTcp] ?: true,
        dnsCryptRequireDnssec = this[Keys.requireDnssec] ?: true,
        firewallEnabled = this[Keys.firewallEnabled] ?: false,
        firewallDefaultAction = this[Keys.firewallDefault]
            ?.let { runCatching { FirewallDefaultAction.valueOf(it) }.getOrNull() }
            ?: FirewallDefaultAction.ASK,
        firewallTempMinutes = this[Keys.firewallTempMin] ?: 5,
        appLockEnabled = this[Keys.appLock] ?: true,
        allowScreenshots = this[Keys.allowScreenshots] ?: false,
        autoStartOnAppLaunch = this[Keys.autoStartOnLaunch] ?: true,
        autoStartOnBoot = this[Keys.autoStartOnBoot] ?: false,
        moatRequestViaTor = this[Keys.moatRequestViaTor] ?: false,
        noLogsEnabled = this[Keys.noLogs] ?: defaultNoLogsEnabled,
    )
}
