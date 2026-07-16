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
    }

    val preferences: Flow<TunnelPreferences> = context.tunnelDataStore.data.map { prefs ->
        TunnelPreferences(
            routeAllTrafficThroughTor = prefs[Keys.routeAll] ?: true,
            killSwitchEnabled = prefs[Keys.killSwitch] ?: true,
            dnsCryptServerName = prefs[Keys.dnsServer] ?: "cloudflare",
            dnsResolverMode = prefs[Keys.dnsMode]
                ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
                ?: DnsResolverMode.DNSCRYPT_MUX,
            torBridges = prefs[Keys.torBridges].orEmpty(),
            torEntryNodes = prefs[Keys.torEntry].orEmpty(),
            torExitNodes = prefs[Keys.torExit].orEmpty(),
            torExcludeNodes = prefs[Keys.torExclude].orEmpty(),
            torNewCircuitPeriodSec = prefs[Keys.newCircuit] ?: 30,
            torMaxCircuitDirtinessSec = prefs[Keys.maxDirtiness] ?: 600,
            dnsCryptRequireNoLog = prefs[Keys.requireNoLog] ?: true,
            dnsCryptRequireNoFilter = prefs[Keys.requireNoFilter] ?: false,
            dnsCryptForceTcp = prefs[Keys.forceTcp] ?: true,
        )
    }

    suspend fun update(transform: (TunnelPreferences) -> TunnelPreferences) {
        context.tunnelDataStore.edit { prefs ->
            val current = TunnelPreferences(
                routeAllTrafficThroughTor = prefs[Keys.routeAll] ?: true,
                killSwitchEnabled = prefs[Keys.killSwitch] ?: true,
                dnsCryptServerName = prefs[Keys.dnsServer] ?: "cloudflare",
                dnsResolverMode = prefs[Keys.dnsMode]
                    ?.let { runCatching { DnsResolverMode.valueOf(it) }.getOrNull() }
                    ?: DnsResolverMode.DNSCRYPT_MUX,
                torBridges = prefs[Keys.torBridges].orEmpty(),
                torEntryNodes = prefs[Keys.torEntry].orEmpty(),
                torExitNodes = prefs[Keys.torExit].orEmpty(),
                torExcludeNodes = prefs[Keys.torExclude].orEmpty(),
                torNewCircuitPeriodSec = prefs[Keys.newCircuit] ?: 30,
                torMaxCircuitDirtinessSec = prefs[Keys.maxDirtiness] ?: 600,
                dnsCryptRequireNoLog = prefs[Keys.requireNoLog] ?: true,
                dnsCryptRequireNoFilter = prefs[Keys.requireNoFilter] ?: false,
                dnsCryptForceTcp = prefs[Keys.forceTcp] ?: true,
            )
            val next = transform(current)
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
        }
    }
}
