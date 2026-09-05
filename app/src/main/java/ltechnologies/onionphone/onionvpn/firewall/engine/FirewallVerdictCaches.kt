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

    /** Drop one flow sticky (and optional SYN tuple alias) without wiping sibling ports. */
    fun forgetFlow(flowKey: Long, tupleKey: Long? = null) {
        flowCache.remove(flowKey)
        if (tupleKey != null) flowCache.remove(tupleKey)
        destFlowKeys.values.forEach { set ->
            set.remove(flowKey)
            if (tupleKey != null) set.remove(tupleKey)
        }
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
            // Prefer trimming Tor ALLOW; keep DENY + ALLOW_OVPN sticky (OVPN demotion / fail-closed).
            var n = 0
            val it = flowCache.entries.iterator()
            while (it.hasNext() && n < FLOW_TRIM_BUDGET) {
                val e = it.next()
                if (e.value == FirewallVerdict.ALLOW_TOR) {
                    removeFlowKey(e.key)
                    it.remove()
                    n++
                }
            }
            if (flowCache.size > MAX_FLOW_CACHE) {
                val it2 = flowCache.entries.iterator()
                while (it2.hasNext() && n < FLOW_TRIM_BUDGET * 2) {
                    val e = it2.next()
                    if (e.value != FirewallVerdict.ALLOW_OVPN && e.value != FirewallVerdict.DENY) {
                        removeFlowKey(e.key)
                        it2.remove()
                        n++
                    }
                }
            }
            if (flowCache.size > MAX_FLOW_CACHE) {
                val it3 = flowCache.keys.iterator()
                while (it3.hasNext() && n < FLOW_TRIM_BUDGET * 3) {
                    val k = it3.next()
                    removeFlowKey(k)
                    it3.remove()
                    n++
                }
            }
    }

    private fun removeFlowKey(key: Long) {
        destFlowKeys.values.forEach { it.remove(key) }
    }

    private fun removeDecisionKey(key: Long) {
        // Reverse-index only — caller owns decisionCache iterator remove.
        destDecisionKeys.values.forEach { it.remove(key) }
    }

    private fun trimDecisionCache() {
        if (decisionCache.size <= MAX_DECISION_CACHE) return
        var n = 0
        val it = decisionCache.entries.iterator()
        while (it.hasNext() && n < DECISION_TRIM_BUDGET) {
            val e = it.next()
            // Trim Tor ALLOW first; keep ALLOW_OVPN + DENY sticky.
            if (e.value == FirewallVerdict.ALLOW_TOR) {
                removeDecisionKey(e.key)
                it.remove()
                n++
            }
        }
        if (decisionCache.size > MAX_DECISION_CACHE) {
            val it2 = decisionCache.entries.iterator()
            while (it2.hasNext() && n < DECISION_TRIM_BUDGET * 2) {
                val e = it2.next()
                if (e.value != FirewallVerdict.ALLOW_OVPN && e.value != FirewallVerdict.DENY) {
                    removeDecisionKey(e.key)
                    it2.remove()
                    n++
                }
            }
        }
        if (decisionCache.size > MAX_DECISION_CACHE) {
            val it3 = decisionCache.keys.iterator()
            while (it3.hasNext() && n < DECISION_TRIM_BUDGET * 3) {
                val k = it3.next()
                removeDecisionKey(k)
                it3.remove()
                n++
            }
        }
    }

    companion object {
        private const val MAX_FLOW_CACHE = 16_000
        private const val MAX_DECISION_CACHE = 8_000
        private const val FLOW_TRIM_BUDGET = 128
        private const val DECISION_TRIM_BUDGET = 64
    }
}
