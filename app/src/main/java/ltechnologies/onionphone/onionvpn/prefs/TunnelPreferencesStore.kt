package ltechnologies.onionphone.onionvpn.prefs

import android.content.Context
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
    }

    val preferences: Flow<TunnelPreferences> = context.tunnelDataStore.data.map { prefs ->
        prefs.toModel()
    }

    suspend fun update(transform: (TunnelPreferences) -> TunnelPreferences) {
        context.tunnelDataStore.edit { prefs ->
            val next = transform(prefs.toModel())
            prefs[Keys.routeAll] = next.routeAllTrafficThroughTor
            prefs[Keys.killSwitch] = next.killSwitchEnabled
            prefs[Keys.dnsServer] = next.dnsCryptServerName
            prefs[Keys.dnsMode] = next.dnsResolverMode.name
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
        }
    }

    private fun Preferences.toModel(): TunnelPreferences = TunnelPreferences(
        routeAllTrafficThroughTor = this[Keys.routeAll] ?: true,
        killSwitchEnabled = this[Keys.killSwitch] ?: true,
        dnsCryptServerName = this[Keys.dnsServer] ?: "cloudflare",
        dnsResolverMode = this[Keys.dnsMode]
            ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
            ?: DnsResolverMode.DNSCRYPT_MUX,
        torBridges = this[Keys.torBridges].orEmpty(),
        torEntryNodes = this[Keys.torEntry].orEmpty(),
        torExitNodes = this[Keys.torExit].orEmpty(),
        torExcludeNodes = this[Keys.torExclude].orEmpty(),
        torNewCircuitPeriodSec = this[Keys.newCircuit] ?: 30,
        torMaxCircuitDirtinessSec = this[Keys.maxDirtiness] ?: 180,
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
    )
}
