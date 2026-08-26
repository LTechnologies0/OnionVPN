package ltechnologies.onionphone.onionvpn.firewall

import android.content.Context
import android.os.Handler
import android.os.Looper
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
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
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.SocksConnectPlane
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
    /** Collectors are process-lifetime; only wire hot-path hooks per tunnel session. */
    private val collectorsStarted = AtomicBoolean(false)
    private val sessionActive = AtomicBoolean(false)

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

    fun stop() {
        if (!sessionActive.compareAndSet(true, false)) {
            appUidResolver.stop()
            return
        }
        appUidResolver.stop()
        FirewallBridge.resolveSocksClientUid = null
        FirewallBridge.onAutomapRemap = null
    }

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
        // Drop sticky ALLOW_OVPN/Tor decisions from the previous tunnel session.
        caches.clearAll()
        synchronized(queueLock) {
            waitQueue.clear()
            pendingByKey.clear()
            active = null
            _pendingPrompt.value = null
            publishQueueDepthLocked()
        }
        sessionActive.set(true)
        // Singleton: tunnel stop/start must not stack DataStore/journal collectors.
        if (!collectorsStarted.compareAndSet(false, true)) return
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
            runCatching { preferences.set(coerceFirewallPrefs(preferencesStore.preferences.first())) }
            var lastDefault = preferences.get().firewallDefaultAction
            preferencesStore.preferences.collect { raw ->
                val next = coerceFirewallPrefs(raw)
                val prevDefault = lastDefault
                preferences.set(next)
                // Sticky ALLOW_OVPN flow cache survives Settings default flips and keeps
                // SoftEther RST pollution on Tor-path browsers until tunnel restart.
                if (next.firewallDefaultAction != prevDefault) {
                    lastDefault = next.firewallDefaultAction
                    caches.clearAll()
                    Timber.i(
                        "Firewall default %s → %s — cleared sticky verdict caches",
                        prevDefault,
                        next.firewallDefaultAction,
                    )
                    if (prevDefault == FirewallDefaultAction.ALLOW_OVPN &&
                        next.firewallDefaultAction != FirewallDefaultAction.ALLOW_OVPN
                    ) {
                        clearPermanentOvpnRules()
                    }
                }
            }
        }
        scope.launch {
            rulesStore.rules.collect { list ->
                rules.set(list.filterNot { it.isExpired() })
            }
        }
    }

    /**
     * Apply prefs from [TunnelForegroundService] start path (DataStore + Intent merge).
     * Ensures OpenVPN-over-Tor never runs with firewall silently off.
     */
    fun applySessionPreferences(prefs: TunnelPreferences) {
        val coerced = coerceFirewallPrefs(prefs)
        preferences.set(coerced)
        if (coerced.firewallEnabled != prefs.firewallEnabled) {
            Timber.i(
                "Firewall coerced ON for OpenVPN-over-Tor (was firewallEnabled=%s)",
                prefs.firewallEnabled,
            )
        }
    }

    private fun coerceFirewallPrefs(prefs: TunnelPreferences): TunnelPreferences =
        if (prefs.openVpnOverTorEnabled && !prefs.firewallEnabled) {
            prefs.copy(firewallEnabled = true)
        } else {
            prefs
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

    override fun outboundRoute(packet: ByteArray, length: Int): FirewallVerdict {
        val prefs = preferences.get()
        // OpenVPN-over-Tor requires interactive routing (Via OVPN); never silent-ALLOW_TOR.
        if (!prefs.firewallEnabled && !prefs.openVpnOverTorEnabled) {
            return FirewallVerdict.ALLOW_TOR
        }
        if (!prefs.firewallEnabled && prefs.openVpnOverTorEnabled) {
            // Prefs toggle off but OVPN mode on — enforce firewall (Via OVPN otherwise unreachable).
            Timber.v("firewall coerced on (openVpnOverTorEnabled)")
        }

        // Unparseable → fail-closed (never treat garbage as ALLOW).
        val info = IpPacketParser.parse(packet, length) ?: return FirewallVerdict.DENY

        // UDP/53 → TunDnsMux → DNSCrypt/Tor DNSPort (any resolver IP pinned into TUN).
        // Honor DENY rules only — never ASK (prompts would blackhole working DNS while Tor is fine).
        if (info.protocol == IpPacketParser.PROTO_UDP && info.dstPort == 53) {
            val uid = ownerResolver.resolveUid(info)
            if (uid == ownUid) return FirewallVerdict.ALLOW_TOR
            if (ConnectionOwnerResolver.isValidUid(uid)) {
                val deny = findRule(uid, info.dstIp, info)
                if (deny?.verdict == FirewallVerdict.DENY) return FirewallVerdict.DENY
            }
            return FirewallVerdict.ALLOW_TOR
        }

        val tupleKey = FirewallCacheKeys.tupleFlowKey(info)
        if (info.isTcp && !info.isTcpSyn) {
            caches.flowCache[tupleKey]?.let { return it }
        }

        // Resolve UID before uid-scoped caches — 5-tuple-only keys poisoned UNKNOWN→real UID races.
        val uid = if (info.isTcpSyn) {
            ownerResolver.resolveUidWithRetry(info)
        } else {
            ownerResolver.resolveUid(info)
        }
        if (uid == ownUid) return FirewallVerdict.ALLOW_TOR

        // SYN without owner: Waydroid/WebView often miss getConnectionOwnerUid on first
        // packets. Fail-open to the configured default (never invent OVPN when down) so
        // hev can dial; SocksUidBridge uses uunknown IsolateSOCKSAuth when stamp missing.
        if (info.isTcpSyn && !ConnectionOwnerResolver.isValidUid(uid)) {
            return when (prefs.firewallDefaultAction) {
                FirewallDefaultAction.DENY -> FirewallVerdict.DENY
                FirewallDefaultAction.ALLOW_OVPN -> defaultOvpnOrTor(prefs)
                FirewallDefaultAction.ALLOW,
                FirewallDefaultAction.ASK,
                -> FirewallVerdict.ALLOW_TOR
            }
        }
        // Mid-flow often loses owner UID on Android. Prefer sticky tuple cache (checked
        // above). Without it: never invent ALLOW_TOR when OVPN-over-Tor is enabled —
        // that would flip an OVPN flow onto a Tor exit after cache trim.
        if (!ConnectionOwnerResolver.isValidUid(uid) && info.isTcp && !info.isTcpSyn) {
            return midFlowFallback(prefs)
        }
        if (!ConnectionOwnerResolver.isValidUid(uid)) {
            return FirewallVerdict.DENY
        }

        val flowKey = FirewallCacheKeys.flowKey(uid, info)
        caches.flowCache[flowKey]?.let { return it }

        val matchDest = matchDestination(info)
        if (matchDest == null) {
            // Automap IP without hostname yet (DNS still in flight / dropped).
            // SYN: fail-closed. Mid-flow: sticky path only — no invented Tor route.
            return if (info.isTcp && !info.isTcpSyn) midFlowFallback(prefs) else FirewallVerdict.DENY
        }

        // Mid-flow: never open ASK/DENY prompts. Prefer sticky decision / rules when the
        // flow-cache entry was trimmed. Fall back via midFlowFallback (default-aware).
        if (info.isTcp && !info.isTcpSyn) {
            val matching = findRule(uid, matchDest, info)
            if (matching != null) {
                rememberPacketFlow(flowKey, matching.verdict, matchDest, info)
                return matching.verdict
            }
            val rk = FirewallCacheKeys.decisionKey(uid, matchDest, info)
            caches.decisionCache[rk]?.let { v ->
                rememberPacketFlow(flowKey, v, matchDest, info)
                return v
            }
            return when (prefs.firewallDefaultAction) {
                FirewallDefaultAction.ALLOW,
                FirewallDefaultAction.ASK,
                -> midFlowFallback(prefs)
                FirewallDefaultAction.ALLOW_OVPN -> defaultOvpnOrTor(prefs)
                FirewallDefaultAction.DENY -> FirewallVerdict.DENY
            }
        }

        val matching = findRule(uid, matchDest, info)
        if (matching != null) {
            rememberPacketFlow(flowKey, matching.verdict, matchDest, info)
            return matching.verdict
        }

        val rk = FirewallCacheKeys.decisionKey(uid, matchDest, info)
        caches.decisionCache[rk]?.let { v ->
            rememberPacketFlow(flowKey, v, matchDest, info)
            return v
        }

        val pendingKey = FirewallCacheKeys.ruleKey(uid, matchDest, info.dstPort, info.protocol)
        if (pendingByKey.containsKey(pendingKey)) {
            return FirewallVerdict.DENY
        }

        val app = resolveApp(uid)
        val dpi = ApplicationLayerDetector.classify(packet, length, info)
        return when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.ALLOW -> {
                caches.rememberDecision(
                    rk,
                    flowKey,
                    FirewallVerdict.ALLOW_TOR,
                    matchDest,
                    FirewallCacheKeys.tupleFlowKey(info),
                )
                FirewallVerdict.ALLOW_TOR
            }
            FirewallDefaultAction.ALLOW_OVPN -> {
                val v = defaultOvpnOrTor(prefs)
                caches.rememberDecision(
                    rk,
                    flowKey,
                    v,
                    matchDest,
                    FirewallCacheKeys.tupleFlowKey(info),
                )
                v
            }
            FirewallDefaultAction.DENY -> {
                caches.rememberDecision(
                    rk,
                    flowKey,
                    FirewallVerdict.DENY,
                    matchDest,
                    FirewallCacheKeys.tupleFlowKey(info),
                )
                appendJournal(
                    uid = uid,
                    app = app,
                    info = info,
                    verdict = FirewallVerdict.DENY,
                    scope = FirewallRuleScope.SESSION,
                    note = dpiJournalNote("default deny", dpi),
                    protocolLabel = dpi.label,
                )
                FirewallVerdict.DENY
            }
            FirewallDefaultAction.ASK ->
                enqueuePrompt(uid, app, info, flowKey, pendingKey, rk, dpi, matchDest)
        }
    }

    /**
     * PAC / hev UID-bridge SOCKS CONNECT — same rules as TUN SYN, keyed by dest host/IP.
     * [SocksConnectPlane.PAC_DNSCRYPT_BRIDGE] never saw a TUN SYN; it is the sole gate.
     * [SocksConnectPlane.HEV_UID_BRIDGE] re-checks after TunDnsMux (stamp theft / rule flip).
     */
    override fun socksConnectRoute(
        uid: Int,
        destHost: String,
        destIp: String,
        destPort: Int,
        plane: SocksConnectPlane,
    ): FirewallVerdict {
        val prefs = preferences.get()
        if (!prefs.firewallEnabled && !prefs.openVpnOverTorEnabled) {
            return FirewallVerdict.ALLOW_TOR
        }
        if (uid == ownUid) return FirewallVerdict.ALLOW_TOR
        // Unknown UID: PAC stays fail-closed on ASK/DENY (sole gate). HEV already passed TUN
        // SYN — Waydroid/WebView often loses owner UID before CONNECT; refuse → RST mid-TLS.
        if (!ConnectionOwnerResolver.isValidUid(uid)) {
            return when (plane) {
                SocksConnectPlane.HEV_UID_BRIDGE ->
                    if (prefs.firewallDefaultAction == FirewallDefaultAction.DENY) {
                        FirewallVerdict.DENY
                    } else {
                        FirewallVerdict.ALLOW_TOR
                    }
                SocksConnectPlane.PAC_DNSCRYPT_BRIDGE ->
                    if (prefs.firewallDefaultAction == FirewallDefaultAction.ALLOW ||
                        prefs.firewallDefaultAction == FirewallDefaultAction.ALLOW_OVPN
                    ) {
                        FirewallVerdict.ALLOW_TOR
                    } else {
                        FirewallVerdict.DENY
                    }
            }
        }

        val host = destHost.trim()
        val ip = destIp.trim()
        val matchDest = when {
            TunnelEndpoints.isOnionLikeHostname(host) -> host
            ip.isNotBlank() -> ip
            host.isNotBlank() -> host
            else -> return FirewallVerdict.DENY
        }
        val displayHost = host.ifBlank { null }
        val protocol = IpPacketParser.PROTO_TCP
        val flowKey = FirewallCacheKeys.socksFlowKey(uid, matchDest, destPort)
        caches.flowCache[flowKey]?.let { return it }

        val matching = findRule(uid, matchDest, destPort, protocol)
        if (matching != null) {
            val v = coerceSocksVerdict(matching.verdict)
            caches.rememberFlow(flowKey, v, matchDest)
            return v
        }

        val rk = FirewallCacheKeys.socksDecisionKey(uid, matchDest, destPort, protocol)
        caches.decisionCache[rk]?.let { v ->
            val coerced = coerceSocksVerdict(v)
            caches.rememberFlow(flowKey, coerced, matchDest)
            return coerced
        }

        val pendingKey = FirewallCacheKeys.ruleKey(uid, matchDest, destPort, protocol)
        if (pendingByKey.containsKey(pendingKey)) {
            return FirewallVerdict.DENY
        }

        val app = resolveApp(uid)
        val dpi = ApplicationLayerDetector.Result(
            label = when (plane) {
                SocksConnectPlane.PAC_DNSCRYPT_BRIDGE -> "SOCKS/PAC"
                SocksConnectPlane.HEV_UID_BRIDGE -> "SOCKS/hev"
            },
            detail = when (plane) {
                SocksConnectPlane.PAC_DNSCRYPT_BRIDGE -> "via PAC DNSCrypt→Tor bridge"
                SocksConnectPlane.HEV_UID_BRIDGE -> "via hev UID SOCKS bridge"
            },
        )
        return when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.ALLOW -> {
                caches.rememberDecision(rk, flowKey, FirewallVerdict.ALLOW_TOR, matchDest)
                FirewallVerdict.ALLOW_TOR
            }
            FirewallDefaultAction.ALLOW_OVPN -> {
                // PAC/hev SOCKS cannot encapsulate OVPN — Tor only on this plane.
                caches.rememberDecision(rk, flowKey, FirewallVerdict.ALLOW_TOR, matchDest)
                FirewallVerdict.ALLOW_TOR
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
                FirewallVerdict.DENY
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
    ): FirewallVerdict {
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
                return FirewallVerdict.DENY
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
                return FirewallVerdict.DENY
            }
            waitQueue.addLast(ruleKey)
            publishQueueDepthLocked()
            promoteLocked()
        }
        return FirewallVerdict.DENY
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
    ): FirewallVerdict {
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
                return FirewallVerdict.DENY
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
                return FirewallVerdict.DENY
            }
            waitQueue.addLast(ruleKey)
            Timber.d(
                "Firewall ASK enqueue app=%s dest=%s:%d dpi=%s queue=%d",
                app.label,
                matchDest,
                info.dstPort,
                dpi.label,
                waitQueue.size,
            )
            publishQueueDepthLocked()
            promoteLocked()
        }
        return FirewallVerdict.DENY
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
        val effective = when {
            verdict == FirewallVerdict.ALLOW_OVPN && !ovpnRouteAvailable(prefs) -> {
                Timber.w("ALLOW_OVPN rejected — OpenVPN-over-Tor not available; storing DENY")
                FirewallVerdict.DENY
            }
            else -> verdict
        }
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
            verdict = effective,
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
        caches.rememberDecision(answered.decisionKey, answered.flowKey, effective, answered.matchDest)
        val note = when (ruleScope) {
            FirewallRuleScope.TEMPORARY -> "temporary ${prefs.firewallTempMinutes}m"
            FirewallRuleScope.SESSION -> "until VPN stops"
            FirewallRuleScope.PERMANENT -> "permanent"
        }
        Timber.i(
            "Firewall answer %s → %s:%d verdict=%s scope=%s",
            answered.request.appLabel,
            answered.matchDest,
            answered.request.destPort,
            effective,
            note,
        )
        val dpiNote = answered.request.dpiDetail?.takeIf { it.isNotBlank() }
        appendJournal(
            uid = answered.request.uid,
            app = answered.app,
            destIp = answered.request.destIp,
            destHost = answered.request.destHost,
            threatCategory = answered.request.threatCategory,
            destPort = answered.request.destPort,
            protocolLabel = answered.request.protocolLabel,
            verdict = effective,
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

    /**
     * Drop permanent Via OVPN rules (and sticky caches) when leaving default Allow-via-OVPN
     * or when SoftEther is known-bad. Persistent SoftEther destinations otherwise keep
     * forcing OPENTUN even after default → Tor.
     */
    fun clearPermanentOvpnRules() {
        clearOvpnRules(scopes = setOf(FirewallRuleScope.PERMANENT))
    }

    /** UI / SoftEther blackhole: drop every stored Via OVPN rule and sticky caches. */
    fun clearAllOvpnRules() {
        clearOvpnRules(
            scopes = setOf(
                FirewallRuleScope.PERMANENT,
                FirewallRuleScope.SESSION,
                FirewallRuleScope.TEMPORARY,
            ),
        )
    }

    fun hasOvpnRules(): Boolean =
        rules.get().any { it.verdict == FirewallVerdict.ALLOW_OVPN }

    private fun clearOvpnRules(scopes: Set<FirewallRuleScope>) {
        scope.launch {
            rulesStore.removeWhere {
                it.verdict == FirewallVerdict.ALLOW_OVPN && it.scope in scopes
            }
        }
        rules.updateAndGet {
            it.filterNot { r ->
                r.verdict == FirewallVerdict.ALLOW_OVPN && r.scope in scopes
            }
        }
        caches.clearAll()
        Timber.i("Cleared Via OVPN rules scopes=%s + sticky caches", scopes)
    }

    fun rulesFlow(): StateFlow<List<FirewallRule>> = rulesStore.rules

    private fun rememberPacketFlow(
        flowKey: Long,
        verdict: FirewallVerdict,
        matchDest: String,
        info: IpPacketInfo,
    ) {
        caches.rememberFlow(
            flowKey,
            verdict,
            matchDest,
            FirewallCacheKeys.tupleFlowKey(info),
        )
    }

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
        if (!TunnelEndpoints.isAutomapVirtual(ip)) return ip
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


    /**
     * PAC / hev SOCKS cannot encapsulate OVPN-over-Tor.
     * Demote ALLOW_OVPN → Tor on this plane (never DENY): otherwise SoftEther-down /
     * TunDnsMux demote / default-Allow-via-OVPN SYN→hev still hits SOCKS re-check and
     * clients see net::ERR_CONNECTION_RESET.
     */
    private fun coerceSocksVerdict(v: FirewallVerdict): FirewallVerdict =
        if (v == FirewallVerdict.ALLOW_OVPN) FirewallVerdict.ALLOW_TOR else v

    /** Default ALLOW_OVPN when data plane is up; otherwise Tor (never a silent invent). */
    private fun defaultOvpnOrTor(prefs: TunnelPreferences): FirewallVerdict =
        if (ovpnRouteAvailable(prefs)) FirewallVerdict.ALLOW_OVPN else FirewallVerdict.ALLOW_TOR

    /**
     * Mid-flow cache miss (UID lost / trim). Prefer the configured default over a blanket DENY.
     *
     * Historical Tor-only builds fail-open to Tor. With OpenVPN-over-Tor, a blanket DENY here
     * (old behaviour) RST'd every Tor-routed TCP after [FirewallVerdictCaches] trimmed ALLOW
     * entries — browser saw net::ERR_CONNECTION_RESET for even example.com.
     *
     * OVPN permanent/session rules and decisionCache still win above this fallback; we only
     * avoid inventing Tor when the user explicitly defaulted to DENY.
     */
    private fun midFlowFallback(prefs: TunnelPreferences): FirewallVerdict =
        when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.DENY -> FirewallVerdict.DENY
            FirewallDefaultAction.ALLOW_OVPN -> defaultOvpnOrTor(prefs)
            FirewallDefaultAction.ALLOW,
            FirewallDefaultAction.ASK,
            -> FirewallVerdict.ALLOW_TOR
        }

    /** OVPN prompt option when feature enabled, profile present, and runtime up. */
    fun ovpnRouteAvailable(prefs: TunnelPreferences = preferences.get()): Boolean =
        prefs.openVpnOverTorEnabled &&
            prefs.openVpnProfileConfigured &&
            FirewallBridge.openVpnOverTorUp

    /**
     * Rebuild the heads-up notification once OpenVPN-over-Tor becomes UP so
     * "Via OVPN" appears on an already-visible prompt (race with async CONNECTED).
     */
    fun refreshActivePromptForOvpn() {
        if (!ovpnRouteAvailable()) return
        val shown = synchronized(queueLock) { active?.request } ?: return
        mainHandler.post { promptNotifier.show(shown) }
        Timber.i("Firewall prompt refreshed — Via OVPN now available")
    }

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
