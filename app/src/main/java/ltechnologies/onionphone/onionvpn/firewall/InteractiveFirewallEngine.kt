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
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ApplicationLayerDetector
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.PacketFirewall
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import ltechnologies.onionphone.onionvpn.firewall.engine.FirewallCacheKeys
import ltechnologies.onionphone.onionvpn.firewall.engine.FirewallRuleMatcher
import ltechnologies.onionphone.onionvpn.firewall.engine.FirewallVerdictCaches
import ltechnologies.onionphone.onionvpn.threat.repo.DomainReputationRepository
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

    private val caches = FirewallVerdictCaches()

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
        FirewallBridge.resolveSocksClientUid = { sock -> ownerResolver.resolveAcceptedClientUid(sock) }
        FirewallBridge.onAutomapRemap = { ip, oldHost, newHost ->
            // Scoped only — never wipe every ALLOWED flow (CDN remaps used to blackhole mid-TCP).
            caches.invalidateDestination(ip)
            caches.invalidateDestination(oldHost)
            caches.invalidateDestination(newHost)
        }
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
        caches.clearAll()
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

        // Resolve UID before any cache — 5-tuple-only keys poisoned UNKNOWN→real UID races.
        val uid = ownerResolver.resolveUid(info)
        if (uid == ownUid) return true

        // SYN without owner: drop and wait for retransmit (never open uunknown / sticky collapse).
        if (info.isTcpSyn && !ConnectionOwnerResolver.isValidUid(uid)) {
            return false
        }
        // Mid-flow often loses owner UID on Android — do NOT fail-closed here (that blackholed
        // every ACK/TLS after STREAM SUCCEEDED). Fall through with best-effort UID for caches.
        if (!ConnectionOwnerResolver.isValidUid(uid) && info.isTcp && !info.isTcpSyn) {
            // Try flow cache with the unresolved uid first; if empty, fail-open mid-flow.
            // SYN already required a valid owner + ALLOW/ASK verdict.
            return true
        }
        if (!ConnectionOwnerResolver.isValidUid(uid)) {
            return false
        }

        val matchDest = matchDestination(info) ?: return false // Automap without hostname
        val flowKey = FirewallCacheKeys.flowKey(uid, info)
        caches.flowCache[flowKey]?.let { return it == FirewallVerdict.ALLOW }

        // Mid-flow: never open ASK/DENY prompts. Prefer sticky decision / rules when the
        // flow-cache entry was trimmed or wiped by a remap — hard-drop only if never allowed.
        if (info.isTcp && !info.isTcpSyn) {
            val matching = findRule(uid, matchDest, info)
            if (matching != null) {
                caches.rememberFlow(flowKey, matching.verdict, matchDest)
                return matching.verdict == FirewallVerdict.ALLOW
            }
            val rk = FirewallCacheKeys.decisionKey(uid, matchDest, info)
            caches.decisionCache[rk]?.let { v ->
                caches.rememberFlow(flowKey, v, matchDest)
                return v == FirewallVerdict.ALLOW
            }
            return false
        }

        val matching = findRule(uid, matchDest, info)
        if (matching != null) {
            caches.rememberFlow(flowKey, matching.verdict, matchDest)
            return matching.verdict == FirewallVerdict.ALLOW
        }

        val rk = FirewallCacheKeys.decisionKey(uid, matchDest, info)
        caches.decisionCache[rk]?.let { v ->
            caches.rememberFlow(flowKey, v, matchDest)
            return v == FirewallVerdict.ALLOW
        }

        val pendingKey = FirewallCacheKeys.ruleKey(uid, matchDest, info.dstPort, info.protocol)
        if (pendingByKey.containsKey(pendingKey)) {
            return false
        }

        val app = resolveApp(uid)
        val dpi = ApplicationLayerDetector.classify(packet, length, info)
        return when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.ALLOW -> {
                caches.rememberDecision(rk, flowKey, FirewallVerdict.ALLOW, matchDest)
                true
            }
            FirewallDefaultAction.DENY -> {
                caches.rememberDecision(rk, flowKey, FirewallVerdict.DENY, matchDest)
                appendJournal(
                    uid = uid,
                    app = app,
                    info = info,
                    verdict = FirewallVerdict.DENY,
                    scope = FirewallRuleScope.SESSION,
                    note = dpiJournalNote("default deny", dpi),
                    protocolLabel = dpi.label,
                )
                false
            }
            FirewallDefaultAction.ASK ->
                enqueuePrompt(uid, app, info, flowKey, pendingKey, rk, dpi, matchDest)
        }
    }

    /**
     * PAC / loopback SOCKS CONNECT gate — same rules as TUN SYN, keyed by dest host/IP.
     */
    override fun allowSocksConnect(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
    ): Boolean {
        val prefs = preferences.get()
        if (!prefs.firewallEnabled) return true
        if (uid == ownUid) return true
        if (!ConnectionOwnerResolver.isValidUid(uid)) return false

        val host = destHost.trim()
        val ip = destIp.trim()
        val matchDest = when {
            TunnelEndpoints.isOnionLikeHostname(host) -> host
            ip.isNotBlank() -> ip
            host.isNotBlank() -> host
            else -> return false
        }
        val displayHost = host.ifBlank { null }
        val protocol = IpPacketParser.PROTO_TCP
        val flowKey = FirewallCacheKeys.socksFlowKey(uid, matchDest, destPort)
        caches.flowCache[flowKey]?.let { return it == FirewallVerdict.ALLOW }

        val matching = findRule(uid, matchDest, destPort, protocol)
        if (matching != null) {
            caches.rememberFlow(flowKey, matching.verdict, matchDest)
            return matching.verdict == FirewallVerdict.ALLOW
        }

        val rk = FirewallCacheKeys.socksDecisionKey(uid, matchDest, destPort, protocol)
        caches.decisionCache[rk]?.let { v ->
            caches.rememberFlow(flowKey, v, matchDest)
            return v == FirewallVerdict.ALLOW
        }

        val pendingKey = FirewallCacheKeys.ruleKey(uid, matchDest, destPort, protocol)
        if (pendingByKey.containsKey(pendingKey)) {
            return false
        }

        val app = resolveApp(uid)
        val dpi = ApplicationLayerDetector.Result(
            label = "SOCKS/PAC",
            detail = "via PAC bridge",
        )
        return when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.ALLOW -> {
                caches.rememberDecision(rk, flowKey, FirewallVerdict.ALLOW, matchDest)
                true
            }
            FirewallDefaultAction.DENY -> {
                caches.rememberDecision(rk, flowKey, FirewallVerdict.DENY, matchDest)
                appendJournal(
                    uid = uid,
                    app = app,
                    destIp = ip.ifBlank { matchDest },
                    destHost = displayHost,
                    threatCategory = domainReputation.classify(displayHost),
                    destPort = destPort,
                    protocolLabel = dpi.label,
                    verdict = FirewallVerdict.DENY,
                    ruleScope = FirewallRuleScope.SESSION,
                    note = dpiJournalNote("default deny", dpi),
                )
                false
            }
            FirewallDefaultAction.ASK ->
                enqueueSocksPrompt(
                    uid = uid,
                    app = app,
                    matchDest = matchDest,
                    destIp = ip.ifBlank { matchDest },
                    destHost = displayHost,
                    destPort = destPort,
                    flowKey = flowKey,
                    ruleKey = pendingKey,
                    decisionKey = rk,
                    dpi = dpi,
                )
        }
    }

    private fun enqueueSocksPrompt(
        uid: Int,
        app: AppIdentity,
        matchDest: String,
        destIp: String,
        destHost: String?,
        destPort: Int,
        flowKey: Long,
        ruleKey: String,
        decisionKey: Long,
        dpi: ApplicationLayerDetector.Result,
    ): Boolean {
        val threat = domainReputation.classify(destHost)
        val request = FirewallConnectionInfo(
            requestId = UUID.randomUUID().toString(),
            uid = uid,
            packageName = app.packageName,
            appLabel = app.label,
            destIp = destIp,
            destPort = destPort,
            protocol = IpPacketParser.PROTO_TCP,
            protocolLabel = dpi.label,
            destHost = destHost,
            threatCategory = threat,
            dpiDetail = dpi.detail,
        )
        val queued = QueuedPrompt(request, flowKey, app, ruleKey, decisionKey, matchDest)
        synchronized(queueLock) {
            if (pendingByKey.putIfAbsent(ruleKey, queued) != null) {
                return false
            }
            if (waitQueue.size >= MAX_QUEUE) {
                pendingByKey.remove(ruleKey, queued)
                Timber.w("Firewall prompt queue full (%d) — dropping PAC %s", MAX_QUEUE, ruleKey)
                appendJournal(
                    uid = uid,
                    app = app,
                    destIp = destIp,
                    destHost = destHost,
                    threatCategory = threat,
                    destPort = destPort,
                    protocolLabel = dpi.label,
                    verdict = FirewallVerdict.DENY,
                    ruleScope = FirewallRuleScope.SESSION,
                    note = dpiJournalNote("queue full — drop (no sticky rule)", dpi),
                )
                return false
            }
            waitQueue.addLast(ruleKey)
            publishQueueDepthLocked()
            promoteLocked()
        }
        return false
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
        dpi: ApplicationLayerDetector.Result,
        matchDest: String,
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
            protocolLabel = dpi.label,
            destHost = destHost,
            threatCategory = threat,
            dpiDetail = dpi.detail,
        )
        val queued = QueuedPrompt(request, flowKey, app, ruleKey, decisionKey, matchDest)
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
                    note = dpiJournalNote("queue full — drop (no sticky rule)", dpi),
                    protocolLabel = dpi.label,
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
            // Automap: match .onion hostname; clearnet: match packet IP.
            destHost = answered.matchDest,
            destPort = answered.request.destPort,
            protocol = answered.request.protocol,
            verdict = verdict,
            scope = ruleScope,
            expiresAtEpochMs = expires,
            displayHost = answered.request.destHost.orEmpty(),
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
        caches.rememberDecision(answered.decisionKey, answered.flowKey, verdict, answered.matchDest)
        val note = when (ruleScope) {
            FirewallRuleScope.TEMPORARY -> "temporary ${prefs.firewallTempMinutes}m"
            FirewallRuleScope.SESSION -> "until VPN stops"
            FirewallRuleScope.PERMANENT -> "permanent"
        }
        val dpiNote = answered.request.dpiDetail?.takeIf { it.isNotBlank() }
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
            note = if (dpiNote != null) "$note · $dpiNote" else note,
        )
    }

    fun deleteRule(id: String) {
        scope.launch { rulesStore.remove(id) }
        rules.updateAndGet { it.filterNot { r -> r.id == id } }
        // Rule identity is not keyed the same as flow hashes — clear sticky caches.
        caches.clearAll()
    }

    fun rulesFlow(): StateFlow<List<FirewallRule>> = rulesStore.rules

    private fun findRule(uid: Int, matchDest: String, info: IpPacketInfo): FirewallRule? =
        FirewallRuleMatcher.find(rules.get(), uid, matchDest, info)

    private fun findRule(uid: Int, matchDest: String, destPort: Int, protocol: Int): FirewallRule? =
        FirewallRuleMatcher.find(rules.get(), uid, matchDest, destPort, protocol)

    /**
     * Clearnet → packet IP. Automap → `.onion`/`.exit` hostname (IP reuse must not reuse rules).
     * @return null when Automap IP has no hostname yet (fail-closed).
     */
    private fun matchDestination(info: IpPacketInfo): String? {
        val ip = info.dstIp
        if (!TunnelEndpoints.isAutomapVirtualIpv4(ip)) return ip
        val host = DnsHostnameCache.lookup(ip) ?: return null
        return if (TunnelEndpoints.isOnionLikeHostname(host)) host else null
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
        protocolLabel: String = IpPacketParser.protocolLabel(info.protocol),
    ) {
        val destHost = DnsHostnameCache.lookup(info.dstIp)
        appendJournal(
            uid = uid,
            app = app,
            destIp = info.dstIp,
            destHost = destHost,
            threatCategory = domainReputation.classify(destHost),
            destPort = info.dstPort,
            protocolLabel = protocolLabel,
            verdict = verdict,
            ruleScope = scope,
            note = note,
        )
    }

    private fun dpiJournalNote(base: String, dpi: ApplicationLayerDetector.Result): String {
        val detail = dpi.detail?.takeIf { it.isNotBlank() }
        return if (detail != null) "$base · ${dpi.label}: $detail" else "$base · ${dpi.label}"
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
        journalChannel.trySend(entry)
    }

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
        val matchDest: String,
    )

    companion object {
        private const val MAX_JOURNAL = 200
        private const val JOURNAL_CHANNEL_CAP = 64
        private const val MAX_QUEUE = 64
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
