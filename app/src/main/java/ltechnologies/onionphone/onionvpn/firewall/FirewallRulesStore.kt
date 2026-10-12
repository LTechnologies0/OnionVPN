package ltechnologies.onionphone.onionvpn.firewall

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import ltechnologies.onionphone.onionvpn.core.model.FirewallJournalEntry
import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber

private val Context.firewallDataStore: DataStore<Preferences> by preferencesDataStore(name = "firewall_rules")

@Singleton
class FirewallRulesStore @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private object Keys {
        val rulesJson = stringPreferencesKey("rules_json")
        val journalJson = stringPreferencesKey("journal_json")
    }

    private val _rules = MutableStateFlow<List<FirewallRule>>(emptyList())
    val rules: StateFlow<List<FirewallRule>> = _rules.asStateFlow()

    private val _journal = MutableStateFlow<List<FirewallJournalEntry>>(emptyList())
    val persistedJournal: StateFlow<List<FirewallJournalEntry>> = _journal.asStateFlow()

    val rulesFlow: Flow<List<FirewallRule>> = context.firewallDataStore.data.map { prefs ->
        FirewallRulesCodec.decodeRules(prefs[Keys.rulesJson].orEmpty()).rules
    }

    suspend fun load() {
        val prefs = context.firewallDataStore.data.first()
        _rules.value = FirewallRulesCodec.decodeRules(prefs[Keys.rulesJson].orEmpty())
            .rules
            .filterNot { it.isExpired() }
        _journal.value = decodeJournal(prefs[Keys.journalJson].orEmpty())
        Timber.i(
            "FirewallRulesStore load rules=%d journal=%d",
            _rules.value.size,
            _journal.value.size,
        )
    }

    suspend fun upsert(rule: FirewallRule) {
        context.firewallDataStore.edit { prefs ->
            val decoded = FirewallRulesCodec.decodeRules(prefs[Keys.rulesJson].orEmpty())
            if (decoded is FirewallRulesCodec.DecodeResult.WholeListFailure) {
                Timber.e("Firewall rule upsert aborted — stored list failed to decode")
                return@edit
            }
            val current = decoded.rules.filterNot {
                it.uid == rule.uid &&
                    it.destHost == rule.destHost &&
                    it.destPort == rule.destPort &&
                    it.protocol == rule.protocol
            }
            val next = current + rule
            prefs[Keys.rulesJson] = FirewallRulesCodec.encodeRules(next)
            _rules.value = next.filterNot { it.isExpired() }
        }
        Timber.d(
            "Firewall rule upsert uid=%d dest_len=%d port=%d verdict=%s scope=%s",
            rule.uid,
            rule.destHost.length,
            rule.destPort,
            rule.verdict,
            rule.scope,
        )
    }

    suspend fun remove(id: String) {
        context.firewallDataStore.edit { prefs ->
            val decoded = FirewallRulesCodec.decodeRules(prefs[Keys.rulesJson].orEmpty())
            if (decoded is FirewallRulesCodec.DecodeResult.WholeListFailure) {
                Timber.e("Firewall rule remove aborted — stored list failed to decode")
                return@edit
            }
            val next = decoded.rules.filterNot { it.id == id }
            prefs[Keys.rulesJson] = FirewallRulesCodec.encodeRules(next)
            _rules.value = next
        }
        Timber.d("Firewall rule remove id=%s", id)
    }

    suspend fun removeWhere(predicate: (FirewallRule) -> Boolean) {
        context.firewallDataStore.edit { prefs ->
            val decoded = FirewallRulesCodec.decodeRules(prefs[Keys.rulesJson].orEmpty())
            if (decoded is FirewallRulesCodec.DecodeResult.WholeListFailure) {
                Timber.e("Firewall rule removeWhere aborted — stored list failed to decode")
                return@edit
            }
            val next = decoded.rules.filterNot(predicate)
            prefs[Keys.rulesJson] = FirewallRulesCodec.encodeRules(next)
            _rules.value = next
        }
    }

    suspend fun appendJournal(entry: FirewallJournalEntry) {
        context.firewallDataStore.edit { prefs ->
            val next = (listOf(entry) + decodeJournal(prefs[Keys.journalJson].orEmpty())).take(200)
            prefs[Keys.journalJson] = encodeJournal(next)
            _journal.value = next
        }
    }

    suspend fun clearJournal() {
        context.firewallDataStore.edit { prefs ->
            prefs[Keys.journalJson] = "[]"
            _journal.value = emptyList()
        }
    }

    private fun encodeJournal(entries: List<FirewallJournalEntry>): String {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(
                JSONObject()
                    .put("id", e.id)
                    .put("timestampEpochMs", e.timestampEpochMs)
                    .put("uid", e.uid)
                    .put("packageName", e.packageName)
                    .put("appLabel", e.appLabel)
                    .put("destIp", e.destIp)
                    .put("destHost", e.destHost.orEmpty())
                    .put("threatCategory", e.threatCategory.name)
                    .put("destPort", e.destPort)
                    .put("protocolLabel", e.protocolLabel)
                    .put("verdict", e.verdict.name)
                    .put("scope", e.scope.name)
                    .put("note", e.note),
            )
        }
        return arr.toString()
    }

    private fun decodeJournal(raw: String): List<FirewallJournalEntry> {
        if (raw.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    add(
                        FirewallJournalEntry(
                            id = o.getString("id"),
                            timestampEpochMs = o.getLong("timestampEpochMs"),
                            uid = o.getInt("uid"),
                            packageName = o.optString("packageName"),
                            appLabel = o.optString("appLabel"),
                            destIp = o.optString("destIp"),
                            destPort = o.optInt("destPort"),
                            protocolLabel = o.optString("protocolLabel"),
                            verdict = FirewallVerdict.parse(o.getString("verdict")),
                            scope = FirewallRuleScope.valueOf(o.getString("scope")),
                            note = o.optString("note"),
                            destHost = o.optString("destHost").takeIf { it.isNotBlank() },
                            threatCategory = runCatching {
                                DomainThreatCategory.valueOf(o.optString("threatCategory", "NONE"))
                            }.getOrDefault(DomainThreatCategory.NONE),
                        ),
                    )
                }
            }
        } catch (_: Exception) {
            emptyList()
        }
    }
}
