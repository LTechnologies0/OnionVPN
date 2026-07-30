package ltechnologies.onionphone.onionvpn.firewall.engine

import java.util.concurrent.ConcurrentHashMap
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict

/**
 * Nested verdict caches with reverse dest indexes (Automap remaps invalidate scoped entries only).
 */
internal class FirewallVerdictCaches {
    val flowCache = ConcurrentHashMap<Long, FirewallVerdict>()
    val decisionCache = ConcurrentHashMap<Long, FirewallVerdict>()
    private val destDecisionKeys = ConcurrentHashMap<String, MutableSet<Long>>()
    private val destFlowKeys = ConcurrentHashMap<String, MutableSet<Long>>()

    fun clearAll() {
        flowCache.clear()
        decisionCache.clear()
        destDecisionKeys.clear()
        destFlowKeys.clear()
    }

    fun invalidateDestination(dest: String) {
        if (dest.isBlank()) return
        val needle = dest.lowercase()
        destDecisionKeys.remove(needle)?.forEach { decisionCache.remove(it) }
        destFlowKeys.remove(needle)?.forEach { flowCache.remove(it) }
    }

    fun rememberDecision(
        decisionKey: Long,
        flowKey: Long,
        verdict: FirewallVerdict,
        matchDest: String,
        tupleKey: Long? = null,
    ) {
        decisionCache[decisionKey] = verdict
        destDecisionKeys.getOrPut(matchDest.lowercase()) { ConcurrentHashMap.newKeySet() }.add(decisionKey)
        rememberFlow(flowKey, verdict, matchDest, tupleKey)
        trimDecisionCache()
    }

    fun rememberFlow(
        flowKey: Long,
        verdict: FirewallVerdict,
        matchDest: String? = null,
        tupleKey: Long? = null,
    ) {
        flowCache[flowKey] = verdict
        if (tupleKey != null && tupleKey != flowKey) {
            flowCache[tupleKey] = verdict
        }
        if (matchDest != null) {
            destFlowKeys.getOrPut(matchDest.lowercase()) { ConcurrentHashMap.newKeySet() }.add(flowKey)
            if (tupleKey != null) {
                destFlowKeys.getOrPut(matchDest.lowercase()) { ConcurrentHashMap.newKeySet() }.add(tupleKey)
            }
        }
        if (flowCache.size > MAX_FLOW_CACHE) {
            trimFlowCache()
        }
    }

    private fun trimFlowCache() {
            // Prefer trimming ALLOW over DENY (DENY miss used to open the mid-flow gate).
            var n = 0
            val it = flowCache.entries.iterator()
            while (it.hasNext() && n < FLOW_TRIM_BUDGET) {
                val e = it.next()
                if (e.value == FirewallVerdict.ALLOW) {
                    removeFlowKey(e.key)
                    it.remove()
                    n++
                }
            }
            if (flowCache.size > MAX_FLOW_CACHE) {
                val it2 = flowCache.keys.iterator()
                while (it2.hasNext() && n < FLOW_TRIM_BUDGET * 2) {
                    val k = it2.next()
                    removeFlowKey(k)
                    it2.remove()
                    n++
                }
            }
    }

    private fun removeFlowKey(key: Long) {
        destFlowKeys.values.forEach { it.remove(key) }
    }

    private fun removeDecisionKey(key: Long) {
        decisionCache.remove(key)
        destDecisionKeys.values.forEach { it.remove(key) }
    }

    private fun trimDecisionCache() {
        if (decisionCache.size <= MAX_DECISION_CACHE) return
        var n = 0
        val it = decisionCache.entries.iterator()
        while (it.hasNext() && n < DECISION_TRIM_BUDGET) {
            val e = it.next()
            if (e.value == FirewallVerdict.ALLOW) {
                removeDecisionKey(e.key)
                it.remove()
                n++
            }
        }
        if (decisionCache.size > MAX_DECISION_CACHE) {
            val it2 = decisionCache.keys.iterator()
            while (it2.hasNext() && n < DECISION_TRIM_BUDGET * 2) {
                val k = it2.next()
                removeDecisionKey(k)
                it2.remove()
                n++
            }
        }
    }

    companion object {
        private const val MAX_FLOW_CACHE = 8_000
        private const val MAX_DECISION_CACHE = 4_000
        private const val FLOW_TRIM_BUDGET = 128
        private const val DECISION_TRIM_BUDGET = 64
    }
}
