package ltechnologies.onionphone.onionvpn.firewall

import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import org.json.JSONArray
import org.json.JSONObject
import timber.log.Timber

/**
 * JSON codec for persisted firewall rules.
 *
 * Decode is per-item: a single corrupt object is skipped.
 * If the top-level array itself cannot be parsed, [DecodeResult.WholeListFailure]
 * so callers abort the save instead of wiping the store.
 */
object FirewallRulesCodec {
    sealed class DecodeResult {
        abstract val rules: List<FirewallRule>

        data class Ok(override val rules: List<FirewallRule>) : DecodeResult()
        data object WholeListFailure : DecodeResult() {
            override val rules: List<FirewallRule> get() = emptyList()
        }
    }

    fun encodeRules(rules: List<FirewallRule>): String {
        val arr = JSONArray()
        rules.forEach { r ->
            arr.put(
                JSONObject()
                    .put("id", r.id)
                    .put("uid", r.uid)
                    .put("packageName", r.packageName)
                    .put("appLabel", r.appLabel)
                    .put("destHost", r.destHost)
                    .put("displayHost", r.displayHost)
                    .put("destPort", r.destPort)
                    .put("protocol", r.protocol)
                    .put("verdict", r.verdict.name)
                    .put("scope", r.scope.name)
                    .put("expiresAtEpochMs", r.expiresAtEpochMs ?: JSONObject.NULL)
                    .put("createdAtEpochMs", r.createdAtEpochMs),
            )
        }
        return arr.toString()
    }

    fun decodeRules(raw: String): DecodeResult {
        if (raw.isBlank()) return DecodeResult.Ok(emptyList())
        val arr = try {
            JSONArray(raw)
        } catch (e: Exception) {
            Timber.w(e, "Firewall rules JSON array unreadable")
            return DecodeResult.WholeListFailure
        }
        val rules = buildList {
            for (i in 0 until arr.length()) {
                val item = try {
                    decodeOne(arr.getJSONObject(i))
                } catch (e: Exception) {
                    Timber.w(e, "Skipping corrupt firewall rule at index %d", i)
                    null
                }
                if (item != null) add(item)
            }
        }
        return DecodeResult.Ok(rules)
    }

    private fun decodeOne(o: JSONObject): FirewallRule {
        val expires = if (o.isNull("expiresAtEpochMs")) null else o.getLong("expiresAtEpochMs")
        return FirewallRule(
            id = o.getString("id"),
            uid = o.getInt("uid"),
            packageName = o.optString("packageName"),
            appLabel = o.optString("appLabel"),
            destHost = o.optString("destHost"),
            destPort = o.optInt("destPort", -1),
            protocol = o.optInt("protocol", -1),
            verdict = FirewallVerdict.parse(o.getString("verdict")),
            scope = FirewallRuleScope.valueOf(o.getString("scope")),
            expiresAtEpochMs = expires,
            createdAtEpochMs = o.optLong("createdAtEpochMs", 0L),
            displayHost = o.optString("displayHost"),
        )
    }
}
