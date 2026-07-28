package ltechnologies.onionphone.onionvpn.firewall

import android.content.Context
import android.os.Handler
import android.os.Looper
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import ltechnologies.onionphone.onionvpn.core.model.FirewallDefaultAction
import ltechnologies.onionphone.onionvpn.core.model.FirewallJournalEntry
import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.PacketFirewall
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.threat.DomainReputationRepository
import timber.log.Timber

/**
 * Interactive OpenSnitch-style firewall (app layer).
 *
 * Prompt model:
 * - FIFO queue, one visible prompt at a time
 * - No timeouts — wait until the user answers (or session clears)
 * - Packets for a queued/active key are dropped until a verdict exists
 *
 * Decision pipeline: flow cache → rules → decision cache → ASK/DENY/ALLOW.
 */
@Singleton
class InteractiveFirewallEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val rulesStore: FirewallRulesStore,
    private val preferencesStore: TunnelPreferencesStore,
    private val domainReputation: DomainReputationRepository,
) : PacketFirewall {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ownerResolver = ConnectionOwnerResolver(context)
    private val appUidResolver = AppUidResolver(context)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val ownUid = android.os.Process.myUid()
    private val promptNotifier = FirewallPromptNotifier(context)

    private val preferences = AtomicReference(TunnelPreferences())
    private val rules = AtomicReference<List<FirewallRule>>(emptyList())

    private val flowCache = ConcurrentHashMap<Long, FirewallVerdict>()
    private val decisionCache = ConcurrentHashMap<Long, FirewallVerdict>()

    /** ruleKey → queued or active prompt (dedupe). */
    private val pendingByKey = ConcurrentHashMap<String, QueuedPrompt>()

    /** FIFO of ruleKeys waiting to be shown (active is NOT in this deque). */
    private val waitQueue = ArrayDeque<String>()
    private val queueLock = Any()

    @Volatile private var active: QueuedPrompt? = null

    private val _journal = MutableStateFlow<List<FirewallJournalEntry>>(emptyList())
    val journal: StateFlow<List<FirewallJournalEntry>> = _journal.asStateFlow()

    private val _pendingPrompt = MutableStateFlow<FirewallConnectionInfo?>(null)
    val pendingPrompt: StateFlow<FirewallConnectionInfo?> = _pendingPrompt.asStateFlow()

    private val _queueDepth = MutableStateFlow(0)
    val queueDepth: StateFlow<Int> = _queueDepth.asStateFlow()

    /** Off-hot-path journal writer — never blocks TUN; drops under flood. */
    private val journalChannel = Channel<FirewallJournalEntry>(
        capacity = JOURNAL_CHANNEL_CAP,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )

    fun start() {
        promptNotifier.ensureChannel()
        appUidResolver.start()
        scope.launch {
            for (entry in journalChannel) {
                _journal.updateAndGet { list -> (listOf(entry) + list).take(MAX_JOURNAL) }
                runCatching { rulesStore.appendJournal(entry) }
            }
        }
        scope.launch {
            rulesStore.load()
            _journal.value = rulesStore.persistedJournal.value
            // Seed prefs before first packet so firewallEnabled isn't stuck on default false.
            runCatching { preferences.set(preferencesStore.preferences.first()) }
            preferencesStore.preferences.collect { preferences.set(it) }
        }
        scope.launch {
            rulesStore.rules.collect { list ->
                rules.set(list.filterNot { it.isExpired() })
            }
        }
    }

    fun clearSessionRules() {
        scope.launch {
            rulesStore.removeWhere { it.scope == FirewallRuleScope.SESSION }
        }
        flowCache.clear()
        decisionCache.clear()
        synchronized(queueLock) {
            waitQueue.clear()
            pendingByKey.clear()
            active = null
            _pendingPrompt.value = null
            publishQueueDepthLocked()
        }
        promptNotifier.cancel()
    }

    override fun allowOutbound(packet: ByteArray, length: Int): Boolean {
        val prefs = preferences.get()
        if (!prefs.firewallEnabled) return true

        val info = IpPacketParser.parse(packet, length) ?: return true
        val flowKey = flowKey(info)
        flowCache[flowKey]?.let { return it == FirewallVerdict.ALLOW }

        // Mid-flow TCP (ACK/data) never gated — only SYN opens a decision.
        if (info.isTcp && !info.isTcpSyn) {
            return true
        }

        val uid = ownerResolver.resolveUid(info)
        if (uid == ownUid) {
            return true
        }
        // Do not blanket-allow SYSTEM_UID: many OEM services share 1000 and still need a rule
        // when the user wants least privilege. Unknown uid still goes through ASK/DENY/ALLOW.

        val effectiveUid = if (ConnectionOwnerResolver.isValidUid(uid)) uid else UNKNOWN_UID
        val matching = findRule(effectiveUid, info)
        if (matching != null) {
            rememberFlow(flowKey, matching.verdict)
            return matching.verdict == FirewallVerdict.ALLOW
        }

        val rk = decisionKey(effectiveUid, info)
        decisionCache[rk]?.let { v ->
            rememberFlow(flowKey, v)
            return v == FirewallVerdict.ALLOW
        }

        val pendingKey = ruleKey(effectiveUid, info.dstIp, info.dstPort, info.protocol)
        // Already waiting on this key — keep dropping until answered.
        if (pendingByKey.containsKey(pendingKey)) {
            return false
        }

        // Resolve app label only on cold ASK/DENY paths (never on cache hits).
        val app = resolveApp(effectiveUid)
        return when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.ALLOW -> {
                rememberDecision(rk, flowKey, FirewallVerdict.ALLOW)
                true
            }
            FirewallDefaultAction.DENY -> {
                rememberDecision(rk, flowKey, FirewallVerdict.DENY)
                appendJournal(
                    uid = effectiveUid,
                    app = app,
                    info = info,
                    verdict = FirewallVerdict.DENY,
                    scope = FirewallRuleScope.SESSION,
                    note = "default deny",
                )
                false
            }
            FirewallDefaultAction.ASK -> enqueuePrompt(effectiveUid, app, info, flowKey, pendingKey, rk)
        }
    }

    /**
     * Enqueue a prompt (FIFO). No timeout — stays until [answerPrompt] or [clearSessionRules].
     * Returns false (drop packet) always for ASK until a later SYN hits a cached ALLOW.
     */
    private fun enqueuePrompt(
        uid: Int,
        app: AppIdentity,
        info: IpPacketInfo,
        flowKey: Long,
        ruleKey: String,
        decisionKey: Long,
    ): Boolean {
        val destHost = DnsHostnameCache.lookup(info.dstIp)
        val threat = domainReputation.classify(destHost)
        val request = FirewallConnectionInfo(
            requestId = UUID.randomUUID().toString(),
            uid = uid,
            packageName = app.packageName,
            appLabel = app.label,
            destIp = info.dstIp,
            destPort = info.dstPort,
            protocol = info.protocol,
            protocolLabel = IpPacketParser.protocolLabel(info.protocol),
            destHost = destHost,
            threatCategory = threat,
        )
        val queued = QueuedPrompt(request, flowKey, app, ruleKey, decisionKey)
        synchronized(queueLock) {
            if (pendingByKey.putIfAbsent(ruleKey, queued) != null) {
                return false
            }
            if (waitQueue.size >= MAX_QUEUE) {
                pendingByKey.remove(ruleKey, queued)
                Timber.w("Firewall prompt queue full (%d) — dropping %s", MAX_QUEUE, ruleKey)
                appendJournal(
                    uid = uid,
                    app = app,
                    info = info,
                    verdict = FirewallVerdict.DENY,
                    scope = FirewallRuleScope.SESSION,
                    note = "queue full — drop (no sticky rule)",
                )
                return false
            }
            waitQueue.addLast(ruleKey)
            publishQueueDepthLocked()
            promoteLocked()
        }
        return false
    }

    /** Must hold [queueLock]. */
    private fun promoteLocked() {
        if (active != null) return
        while (waitQueue.isNotEmpty()) {
            val key = waitQueue.removeFirst()
            val next = pendingByKey[key] ?: continue
            active = next
            _pendingPrompt.value = next.request
            publishQueueDepthLocked()
            val shown = next.request
            mainHandler.post { promptNotifier.show(shown) }
            return
        }
        publishQueueDepthLocked()
    }

    fun answerPrompt(
        requestId: String,
        verdict: FirewallVerdict,
        ruleScope: FirewallRuleScope,
    ) {
        val prefs = preferences.get()
        val answered: QueuedPrompt
        synchronized(queueLock) {
            val current = active
            if (current == null || current.request.requestId != requestId) {
                Timber.w("Stale firewall prompt answer id=$requestId")
                return
            }
            answered = current
            pendingByKey.remove(answered.ruleKey, answered)
            active = null
            _pendingPrompt.value = null
            publishQueueDepthLocked()
        }
        // Cancel current notification before promoting the next head of queue.
        promptNotifier.cancel()
        synchronized(queueLock) {
            promoteLocked()
        }

        val expires = if (ruleScope == FirewallRuleScope.TEMPORARY) {
            System.currentTimeMillis() + prefs.firewallTempMinutes.coerceIn(1, 1440) * 60_000L
        } else {
            null
        }
        val rule = FirewallRule(
            id = UUID.randomUUID().toString(),
            uid = answered.request.uid,
            packageName = answered.request.packageName,
            appLabel = answered.request.appLabel,
            destHost = answered.request.destIp,
            destPort = answered.request.destPort,
            protocol = answered.request.protocol,
            verdict = verdict,
            scope = ruleScope,
            expiresAtEpochMs = expires,
        )
        scope.launch { rulesStore.upsert(rule) }
        rules.updateAndGet { list ->
            list.filterNot {
                it.uid == rule.uid &&
                    it.destHost == rule.destHost &&
                    it.destPort == rule.destPort &&
                    it.protocol == rule.protocol
            } + rule
        }
        rememberDecision(answered.decisionKey, answered.flowKey, verdict)
        val note = when (ruleScope) {
            FirewallRuleScope.TEMPORARY -> "temporary ${prefs.firewallTempMinutes}m"
            FirewallRuleScope.SESSION -> "until VPN stops"
            FirewallRuleScope.PERMANENT -> "permanent"
        }
        appendJournal(
            uid = answered.request.uid,
            app = answered.app,
            destIp = answered.request.destIp,
            destHost = answered.request.destHost,
            threatCategory = answered.request.threatCategory,
            destPort = answered.request.destPort,
            protocolLabel = answered.request.protocolLabel,
            verdict = verdict,
            ruleScope = ruleScope,
            note = note,
        )
    }

    fun deleteRule(id: String) {
        scope.launch { rulesStore.remove(id) }
        rules.updateAndGet { it.filterNot { r -> r.id == id } }
        // Only wipe caches for the deleted rule's identity if we can; otherwise clear all.
        flowCache.clear()
        decisionCache.clear()
    }

    fun rulesFlow(): StateFlow<List<FirewallRule>> = rulesStore.rules

    private fun findRule(uid: Int, info: IpPacketInfo): FirewallRule? {
        val now = System.currentTimeMillis()
        val dstIp = info.dstIp
        var best: FirewallRule? = null
        var bestScore = -1
        var bestCreated = Long.MIN_VALUE
        for (rule in rules.get()) {
            if (rule.isExpired(now)) continue
            if (!rule.matches(uid, dstIp, info.dstPort, info.protocol)) continue
            val score =
                (if (rule.destHost.isNotEmpty()) 4 else 0) +
                    (if (rule.destPort >= 0) 2 else 0) +
                    (if (rule.protocol >= 0) 1 else 0)
            if (score > bestScore ||
                (score == bestScore && rule.createdAtEpochMs > bestCreated)
            ) {
                best = rule
                bestScore = score
                bestCreated = rule.createdAtEpochMs
            }
        }
        return best
    }

    private fun rememberDecision(decisionKey: Long, flowKey: Long, verdict: FirewallVerdict) {
        decisionCache[decisionKey] = verdict
        rememberFlow(flowKey, verdict)
        trimDecisionCache()
    }

    private fun rememberFlow(flowKey: Long, verdict: FirewallVerdict) {
        flowCache[flowKey] = verdict
        if (flowCache.size > MAX_FLOW_CACHE) {
            // Budgeted trim — avoid walking half the map on the TUN thread.
            var n = 0
            val it = flowCache.keys.iterator()
            while (it.hasNext() && n < FLOW_TRIM_BUDGET) {
                it.next()
                it.remove()
                n++
            }
        }
    }

    private fun trimDecisionCache() {
        if (decisionCache.size <= MAX_DECISION_CACHE) return
        var n = 0
        val it = decisionCache.entries.iterator()
        while (it.hasNext() && n < DECISION_TRIM_BUDGET) {
            it.next()
            it.remove()
            n++
        }
    }

    private fun publishQueueDepthLocked() {
        val depth = waitQueue.size + if (active != null) 1 else 0
        _queueDepth.value = depth
    }

    private fun resolveApp(uid: Int): AppIdentity {
        val id = appUidResolver.resolve(uid)
        return AppIdentity(
            packageName = id.packageName,
            label = id.label,
            confident = id.confident,
        )
    }

    private fun appendJournal(
        uid: Int,
        app: AppIdentity,
        info: IpPacketInfo,
        verdict: FirewallVerdict,
        scope: FirewallRuleScope,
        note: String,
    ) {
        val destHost = DnsHostnameCache.lookup(info.dstIp)
        appendJournal(
            uid = uid,
            app = app,
            destIp = info.dstIp,
            destHost = destHost,
            threatCategory = domainReputation.classify(destHost),
            destPort = info.dstPort,
            protocolLabel = IpPacketParser.protocolLabel(info.protocol),
            verdict = verdict,
            ruleScope = scope,
            note = note,
        )
    }

    private fun appendJournal(
        uid: Int,
        app: AppIdentity,
        destIp: String,
        destHost: String?,
        threatCategory: DomainThreatCategory,
        destPort: Int,
        protocolLabel: String,
        verdict: FirewallVerdict,
        ruleScope: FirewallRuleScope,
        note: String,
    ) {
        val entry = FirewallJournalEntry(
            id = UUID.randomUUID().toString(),
            timestampEpochMs = System.currentTimeMillis(),
            uid = uid,
            packageName = app.packageName,
            appLabel = app.label,
            destIp = destIp,
            destPort = destPort,
            protocolLabel = protocolLabel,
            verdict = verdict,
            scope = ruleScope,
            note = note,
            destHost = destHost,
            threatCategory = threatCategory,
        )
        // Non-blocking: DROP_OLDEST if journal writer is behind (TUN must never wait).
        journalChannel.trySend(entry)
    }

    /** Packed 5-tuple hash for flow cache (hot path — no String alloc). */
    private fun flowKey(info: IpPacketInfo): Long {
        var h = info.srcIpInt.toLong() and 0xffffffffL
        h = h * MIX + (info.dstIpInt.toLong() and 0xffffffffL)
        h = h * MIX + info.srcPort
        h = h * MIX + info.dstPort
        h = h * MIX + info.protocol
        return h
    }

    private fun decisionKey(uid: Int, info: IpPacketInfo): Long {
        var h = uid.toLong()
        h = h * MIX + (info.dstIpInt.toLong() and 0xffffffffL)
        h = h * MIX + info.dstPort
        h = h * MIX + info.protocol
        return h
    }

    private fun ruleKey(uid: Int, destIp: String, destPort: Int, protocol: Int): String =
        "$uid|$destIp|$destPort|$protocol"

    private data class AppIdentity(
        val packageName: String,
        val label: String,
        val confident: Boolean = true,
    )

    private class QueuedPrompt(
        val request: FirewallConnectionInfo,
        val flowKey: Long,
        val app: AppIdentity,
        val ruleKey: String,
        val decisionKey: Long,
    )

    companion object {
        private const val UNKNOWN_UID = -1
        private const val MAX_JOURNAL = 200
        private const val JOURNAL_CHANNEL_CAP = 64
        private const val MAX_QUEUE = 64
        private const val MAX_FLOW_CACHE = 8_000
        private const val MAX_DECISION_CACHE = 4_000
        private const val FLOW_TRIM_BUDGET = 128
        private const val DECISION_TRIM_BUDGET = 64
        /** Golden-ratio mix (signed Long form of 0x9E3779B97F4A7C15). */
        private const val MIX = -7046029254386353131L
    }
}

private fun <T> AtomicReference<List<T>>.updateAndGet(transform: (List<T>) -> List<T>): List<T> {
    while (true) {
        val cur = get()
        val next = transform(cur)
        if (compareAndSet(cur, next)) return next
    }
}

private fun <T> MutableStateFlow<List<T>>.updateAndGet(transform: (List<T>) -> List<T>): List<T> {
    while (true) {
        val cur = value
        val next = transform(cur)
        if (compareAndSet(cur, next)) return next
    }
}
