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
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.model.observability.DiagnosticsGate
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ApplicationLayerDetector
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.PacketFirewall
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.SocksConnectPlane
import ltechnologies.onionphone.onionvpn.core.vpn.forwarder.TcpFlowUidIndex
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
 * - ASK TTL ([ASK_TTL_MS]) → fail-closed DENY if unanswered (Always-On headless)
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

    /** TEMPORARY expiry runnables — cancelled on stop/session clear (B07). */
    private val tempExpiryRunnables = ConcurrentHashMap.newKeySet<Runnable>()

    /** Active ASK TTL — fail-closed DENY if the user never answers (W4-10 #7). */
    private val askTtlRunnables = ConcurrentHashMap<String, Runnable>()

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
        FirewallBridge.deferRfc1918LanToFirewall = false
        cancelTempExpiryCallbacks()
    }

    private fun cancelTempExpiryCallbacks() {
        for (r in tempExpiryRunnables) {
            mainHandler.removeCallbacks(r)
        }
        tempExpiryRunnables.clear()
        for ((_, r) in askTtlRunnables) {
            mainHandler.removeCallbacks(r)
        }
        askTtlRunnables.clear()
    }

    private fun cancelAskTtl(requestId: String) {
        askTtlRunnables.remove(requestId)?.let { mainHandler.removeCallbacks(it) }
    }

    private fun armAskTtl(requestId: String) {
        cancelAskTtl(requestId)
        val expiry = Runnable {
            askTtlRunnables.remove(requestId)
            Timber.w("Firewall ASK TTL expired id=%s — fail-closed DENY", requestId)
            answerPrompt(requestId, FirewallVerdict.DENY, FirewallRuleScope.SESSION)
        }
        askTtlRunnables[requestId] = expiry
        mainHandler.postDelayed(expiry, ASK_TTL_MS)
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
            // Drop ASK prompts keyed to the old/new Automap identity (IP reuse).
            cancelAutomapPrompts(ip, oldHost, newHost)
        }
        // Drop sticky ALLOW_OVPN/Tor decisions from the previous tunnel session.
        caches.clearAll()
        scope.launch { rulesStore.removeWhere { it.scope == FirewallRuleScope.SESSION } }
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
            // Seed prefs before first packet so firewallEnabled isn't stuck on default false.
            val initial = runCatching {
                coerceFirewallPrefs(preferencesStore.preferences.first())
            }.getOrElse { TunnelPreferences() }
            preferences.set(initial)
            syncLanDeferFlag(initial)
            // Boot with noLogs must not resurrect Timeline IPs/hosts (W4-04).
            if (initial.noLogsEnabled) {
                _journal.value = emptyList()
                runCatching { rulesStore.clearJournal() }
            } else {
                _journal.value = rulesStore.persistedJournal.value
            }
            var lastDefault = preferences.get().firewallDefaultAction
            var lastNoLogs = preferences.get().noLogsEnabled
            var lastFirewallEnabled = preferences.get().firewallEnabled
            preferencesStore.preferences.collect { raw ->
                val next = coerceFirewallPrefs(raw)
                val prevDefault = lastDefault
                val prevNoLogs = lastNoLogs
                val prevFw = lastFirewallEnabled
                preferences.set(next)
                syncLanDeferFlag(next)
                if (next.noLogsEnabled && !prevNoLogs) {
                    lastNoLogs = true
                    _journal.value = emptyList()
                    runCatching { rulesStore.clearJournal() }
                } else {
                    lastNoLogs = next.noLogsEnabled
                }
                // OFF→ON (or reverse) must not reuse ALLOW_LAN stickies from the prior mode.
                if (next.firewallEnabled != prevFw) {
                    lastFirewallEnabled = next.firewallEnabled
                    caches.clearAll()
                    Timber.i(
                        "Firewall enabled %s → %s — cleared sticky verdict caches",
                        prevFw,
                        next.firewallEnabled,
                    )
                }
                // Sticky ALLOW_OVPN flow cache survives Settings default flips and keeps
                // peer RST pollution on Tor-path browsers until tunnel restart.
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
            var previousActive = emptyList<FirewallRule>()
            rulesStore.rules.collect { list ->
                val fromStore = list.filterNot {
                    it.isExpired() || it.isPoisonLanAllow() || it.isPoisonEmptyDest()
                }
                // Merge: keep in-memory rules whose upsert has not yet appeared in DataStore
                // (answerPrompt installs host-wide before async upsert — blind set clobbered
                // Via LAN mid-answer, B01 H2).
                val merged = rules.updateAndGet { mem ->
                    val storeIds = fromStore.map { it.id }.toHashSet()
                    val inFlight = mem.filter {
                        it.id !in storeIds &&
                            !it.isExpired() &&
                            !it.isPoisonLanAllow() &&
                            !it.isPoisonEmptyDest()
                    }
                    fromStore + inFlight
                }
                for (old in previousActive) {
                    if (merged.none { it.id == old.id } &&
                        old.scope != FirewallRuleScope.TEMPORARY
                    ) {
                        // Only invalidate when merged list no longer covers this dest at all.
                        val stillCovered = merged.any {
                            it.destHost.equals(old.destHost, ignoreCase = true)
                        }
                        if (!stillCovered) {
                            caches.invalidateDestination(old.destHost)
                        }
                    }
                }
                previousActive = merged
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
        syncLanDeferFlag(coerced)
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

    /** Arm LeakPacketFilter RFC1918 TCP defer when interactive routing is possible. */
    private fun syncLanDeferFlag(prefs: TunnelPreferences) {
        // Never re-arm after stop() while prefs collectors keep emitting (B06).
        FirewallBridge.deferRfc1918LanToFirewall =
            sessionActive.get() && (prefs.firewallEnabled || prefs.openVpnOverTorEnabled)
    }

    private fun isLanMatchDest(dest: String): Boolean =
        TorNetPolicy.isLanRoutableIpv4Literal(dest)

    /** Stamp UID only for ALLOW_LAN SYNs — never on ASK/DENY (stamp-theft window). */
    private fun stampLanAllowUid(
        info: IpPacketInfo,
        uid: Int,
        verdict: FirewallVerdict,
        lanPacket: Boolean,
    ) {
        if (verdict == FirewallVerdict.ALLOW_LAN && info.isTcpSyn && lanPacket) {
            TcpFlowUidIndex.note(info, uid)
        }
    }

    /**
     * Tor exits and SoftEther cannot reach the user's LAN — only Via LAN / Deny.
     * Non-LAN destinations must never keep ALLOW_LAN (poison rule / sticky).
     */
    private fun lanCoerce(v: FirewallVerdict, lanDest: Boolean): FirewallVerdict {
        if (!lanDest) {
            return if (v == FirewallVerdict.ALLOW_LAN) FirewallVerdict.DENY else v
        }
        return when (v) {
            FirewallVerdict.ALLOW_LAN, FirewallVerdict.DENY -> v
            FirewallVerdict.ALLOW_TOR, FirewallVerdict.ALLOW_OVPN -> FirewallVerdict.DENY
        }
    }

    /** Tor/OVPN rules on RFC1918 must not sticky-DENY — fall through to Via LAN ASK. */
    private fun lanIgnoresTorOvpnRule(verdict: FirewallVerdict, lanDest: Boolean): Boolean =
        lanDest &&
            (verdict == FirewallVerdict.ALLOW_TOR || verdict == FirewallVerdict.ALLOW_OVPN)

    fun clearSessionRules() {
        // Sync memory immediately — async store alone left SESSION ALLOW sticky (W5-03 H2).
        rules.updateAndGet { list -> list.filterNot { it.scope == FirewallRuleScope.SESSION } }
        scope.launch {
            rulesStore.removeWhere { it.scope == FirewallRuleScope.SESSION }
        }
        cancelTempExpiryCallbacks()
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
        // Unparseable → fail-closed (never treat garbage as ALLOW).
        val info = IpPacketParser.parse(packet, length) ?: return FirewallVerdict.DENY
        val lanPacket = TorNetPolicy.isLanRoutableIpv4Literal(info.dstIp)

        // OpenVPN-over-Tor requires interactive routing (Via OVPN); never silent-ALLOW_TOR.
        // RFC1918 never silent-ALLOW_TOR either (exits cannot reach LAN).
        if (!prefs.firewallEnabled && !prefs.openVpnOverTorEnabled) {
            return if (lanPacket) FirewallVerdict.DENY else FirewallVerdict.ALLOW_TOR
        }
        if (!prefs.firewallEnabled && prefs.openVpnOverTorEnabled) {
            // Prefs toggle off but OVPN mode on — enforce firewall (Via OVPN otherwise unreachable).
            Timber.v("firewall coerced on (openVpnOverTorEnabled)")
        }

        // UDP/53 → TunDnsMux → DNSCrypt/Tor DNSPort (any resolver IP pinned into TUN).
        // Honor DENY rules only — never ASK (prompts would blackhole working DNS while Tor is fine).
        // RFC1918 DNS must not ALLOW_TOR (mux silent-drops TOR+LAN — FIXES M4).
        if (info.protocol == IpPacketParser.PROTO_UDP && info.dstPort == 53) {
            if (lanPacket) return FirewallVerdict.DENY
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
            // Live plane was stamped at SYN — never re-coerce Tor↔OVPN mid-TCP.
            // LAN stickies still lanCoerce so stale ALLOW_OVPN/TOR cannot silent-drop.
            caches.flowCache[tupleKey]?.let { cached ->
                // Mid-flow must still demote ALLOW_OVPN when SoftEther SNAT is down (W4-03).
                return when {
                    lanPacket -> lanCoerce(cached, lanDest = true)
                    else -> coerceLiveOvpn(cached, prefs)
                }
            }
        }

        // Hot path = TunDnsMux sole TUN reader — NEVER park (LAN used to wait ~120ms/SYN
        // and stall the whole VPN plane). Single-shot only; SocksUidBridge / mux stamp
        // retry off-thread recover the SYN→UID race.
        val uid = ownerResolver.resolveUid(info)
        // Own UID is VpnService-disallowed; rare TUN hits must never ALLOW_TOR RFC1918
        // (TunDnsMux drops that → silent blackhole). Align with socksConnectRoute.
        if (uid == ownUid) {
            return if (lanPacket) FirewallVerdict.DENY else FirewallVerdict.ALLOW_TOR
        }

        // SYN without owner: fail-closed. HEV CONNECT also refuses without a UID stamp
        // (parity with PAC — no uunknown merge / shared IsolateSOCKSAuth token).
        if (info.isTcpSyn && !ConnectionOwnerResolver.isValidUid(uid)) {
            return FirewallVerdict.DENY
        }
        // Mid-flow often loses owner UID on Android. Prefer sticky tuple cache (checked
        // above). Without it: DENY — inventing Tor would flip a SoftEther flow onto a
        // Tor exit after an unlikely stamp miss.
        if (!ConnectionOwnerResolver.isValidUid(uid) && info.isTcp && !info.isTcpSyn) {
            return FirewallVerdict.DENY
        }
        if (!ConnectionOwnerResolver.isValidUid(uid)) {
            return FirewallVerdict.DENY
        }

        // Do NOT stamp UID on ASK/DENY SYNs — dest-only peek would let another app
        // ride a Via LAN rule (A03/A10). Stamp only when returning ALLOW_LAN below.

        val flowKey = FirewallCacheKeys.flowKey(uid, info)
        caches.flowCache[flowKey]?.let { v ->
            val live = when {
                lanPacket -> lanCoerce(v, lanDest = true)
                else -> coerceLiveOvpn(v, prefs)
            }
            stampLanAllowUid(info, uid, live, lanPacket)
            return live
        }

        val matchDest = matchDestination(info)
        if (matchDest == null) {
            // Automap IP without hostname yet — fail-closed (SYN and mid-flow).
            // Never invent Tor via midFlowFallback; SocksUidBridge also refuses CONNECT.
            return FirewallVerdict.DENY
        }

        // Mid-flow: never open ASK prompts. Prefer sticky decision / rules when the
        // flow-cache entry was trimmed. Never Tor↔OVPN flip: OVPN sticky stays OVPN while
        // SNAT is up (conntrack survives trim); OVPN-down → DENY (not Tor exit swap).
        val lanDest = lanPacket || isLanMatchDest(matchDest)

        if (info.isTcp && !info.isTcpSyn) {
            val matching = findRule(uid, matchDest, info)
            if (matching != null) {
                val live = midFlowStickyLive(
                    stickyIntent(lanCoerce(matching.verdict, lanDest), matchDest, info),
                    prefs,
                )
                rememberPacketFlow(flowKey, live, matchDest, info)
                return live
            }
            val rk = FirewallCacheKeys.decisionKey(uid, matchDest, info)
            caches.decisionCache[rk]?.let { cached ->
                val live = midFlowStickyLive(
                    stickyIntent(lanCoerce(cached, lanDest), matchDest, info),
                    prefs,
                )
                rememberPacketFlow(flowKey, live, matchDest, info)
                return live
            }
            if (lanDest) return FirewallVerdict.DENY
            return when (prefs.firewallDefaultAction) {
                FirewallDefaultAction.ALLOW,
                FirewallDefaultAction.ASK,
                -> midFlowFallback(prefs)
                // Never invent SoftEther or swap to Tor after OVPN-default cache trim.
                FirewallDefaultAction.ALLOW_OVPN,
                FirewallDefaultAction.DENY,
                -> FirewallVerdict.DENY
            }
        }

        val matching = findRule(uid, matchDest, info)
        if (matching != null && !lanIgnoresTorOvpnRule(matching.verdict, lanDest)) {
            val intent = stickyIntent(lanCoerce(matching.verdict, lanDest), matchDest, info)
            val live = coerceLiveOvpn(intent, prefs)
            rememberPacketFlow(flowKey, live, matchDest, info)
            stampLanAllowUid(info, uid, live, lanPacket)
            return live
        }

        val rk = FirewallCacheKeys.decisionKey(uid, matchDest, info)
        caches.decisionCache[rk]?.let { cached ->
            if (!lanIgnoresTorOvpnRule(cached, lanDest)) {
                val intent = stickyIntent(lanCoerce(cached, lanDest), matchDest, info)
                val live = coerceLiveOvpn(intent, prefs)
                rememberPacketFlow(flowKey, live, matchDest, info)
                stampLanAllowUid(info, uid, live, lanPacket)
                return live
            }
        }

        val pendingKey = FirewallCacheKeys.ruleKey(uid, matchDest, info.dstPort, info.protocol)
        if (pendingByKey.containsKey(pendingKey)) {
            return FirewallVerdict.DENY
        }

        val app = resolveApp(uid)
        val dpi = ApplicationLayerDetector.classify(packet, length, info)
        // RFC1918: never auto Via Tor / Via OVPN / silent default-DENY.
        // Even firewallDefaultAction=DENY must ASK for LAN — otherwise Cake→node is
        // unreachable without a way to pick Via LAN (kill-switch stays for clearnet).
        if (lanDest) {
            return enqueuePrompt(uid, app, info, flowKey, pendingKey, rk, dpi, matchDest)
        }
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
                // decisionCache keeps OVPN intent; flowCache stores live plane only.
                val intent = stickyIntent(FirewallVerdict.ALLOW_OVPN, matchDest, info)
                val live = coerceLiveOvpn(intent, prefs)
                val tuple = FirewallCacheKeys.tupleFlowKey(info)
                caches.rememberDecision(rk, flowKey, intent, matchDest, tuple)
                caches.rememberFlow(flowKey, live, matchDest, tuple)
                live
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
        val host = destHost.trim()
        val ip = destIp.trim()
        val matchDest = when {
            TunnelEndpoints.isOnionLikeHostname(host) -> host
            ip.isNotBlank() -> ip
            host.isNotBlank() -> host
            else -> return FirewallVerdict.DENY
        }
        val lanDest = isLanMatchDest(matchDest) || isLanMatchDest(ip)
        // PAC never dials protect()'d LAN — only hev UID bridge after TunDnsMux ALLOW_LAN.
        if (lanDest && plane == SocksConnectPlane.PAC_DNSCRYPT_BRIDGE) {
            return FirewallVerdict.DENY
        }
        if (!prefs.firewallEnabled && !prefs.openVpnOverTorEnabled) {
            return if (lanDest) FirewallVerdict.DENY else FirewallVerdict.ALLOW_TOR
        }
        if (uid == ownUid) {
            return if (lanDest) FirewallVerdict.DENY else FirewallVerdict.ALLOW_TOR
        }
        // Unknown UID: never merge apps onto a shared IsolateSOCKSAuth token (PAC + HEV).
        // Bridges refuse CONNECT before dial; this is defense-in-depth if they call through.
        if (!ConnectionOwnerResolver.isValidUid(uid)) {
            return FirewallVerdict.DENY
        }

        val displayHost = host.ifBlank { null }
        val protocol = IpPacketParser.PROTO_TCP
        val flowKey = FirewallCacheKeys.socksFlowKey(uid, matchDest, destPort)
        caches.flowCache[flowKey]?.let { return lanCoerce(coerceSocksVerdict(it), lanDest) }

        val matching = findRule(uid, matchDest, destPort, protocol)
        if (matching != null && !lanIgnoresTorOvpnRule(matching.verdict, lanDest)) {
            val v = lanCoerce(coerceSocksVerdict(matching.verdict), lanDest)
            caches.rememberFlow(flowKey, v, matchDest)
            return v
        }

        val rk = FirewallCacheKeys.socksDecisionKey(uid, matchDest, destPort, protocol)
        caches.decisionCache[rk]?.let { v ->
            if (!lanIgnoresTorOvpnRule(v, lanDest)) {
                val coerced = lanCoerce(coerceSocksVerdict(v), lanDest)
                caches.rememberFlow(flowKey, coerced, matchDest)
                return coerced
            }
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
        // Same as TUN: unruled LAN always ASK (never inherit clearnet default DENY).
        if (lanDest) {
            return enqueueSocksPrompt(
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
                lanDestination = true,
            )
        }
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
        lanDestination: Boolean = false,
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
            socksPlane = true,
            lanDestination = lanDestination || isLanMatchDest(destIp) || isLanMatchDest(matchDest),
        )
        val queued = QueuedPrompt(request, flowKey, app, ruleKey, decisionKey, matchDest)
        synchronized(queueLock) {
            if (pendingByKey.putIfAbsent(ruleKey, queued) != null) {
                return FirewallVerdict.DENY
            }
            if (waitQueue.size >= MAX_QUEUE) {
                pendingByKey.remove(ruleKey, queued)
                Timber.w("Firewall prompt queue full (%d) — dropping PAC", MAX_QUEUE)
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
     * Enqueue a prompt (FIFO). Unanswered prompts expire after [ASK_TTL_MS] → DENY.
     * Returns DENY for ASK until a later SYN hits a cached ALLOW.
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
            lanDestination = TorNetPolicy.isLanRoutableIpv4Literal(info.dstIp) ||
                isLanMatchDest(matchDest),
        )
        val queued = QueuedPrompt(
            request,
            flowKey,
            app,
            ruleKey,
            decisionKey,
            matchDest,
            tupleKey = FirewallCacheKeys.tupleFlowKey(info),
        )
        synchronized(queueLock) {
            if (pendingByKey.putIfAbsent(ruleKey, queued) != null) {
                return FirewallVerdict.DENY
            }
            if (waitQueue.size >= MAX_QUEUE) {
                pendingByKey.remove(ruleKey, queued)
                Timber.w("Firewall prompt queue full (%d) — dropping", MAX_QUEUE)
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
                "Firewall ASK enqueue app=%s dest_len=%d port=%d dpi=%s queue=%d",
                app.label,
                matchDest.length,
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
            mainHandler.post {
                promptNotifier.show(shown)
                armAskTtl(shown.requestId)
            }
            return
        }
        publishQueueDepthLocked()
    }

    fun answerPrompt(
        requestId: String,
        verdict: FirewallVerdict,
        ruleScope: FirewallRuleScope,
    ) {
        cancelAskTtl(requestId)
        val prefs = preferences.get()
        val answered: QueuedPrompt
        // Keep pending until rule+sticky are installed so LAN RST re-SYNs hit findRule
        // (or still-pending DENY) instead of a second ASK (B01).
        synchronized(queueLock) {
            val current = active
            if (current == null || current.request.requestId != requestId) {
                Timber.w("Stale firewall prompt answer id=$requestId")
                return
            }
            answered = current
        }
        // Persist user intent after requestId match. SoftEther down → live coerce only.
        // SOCKS/PAC and Automap/.onion never store ALLOW_OVPN.
        // LAN destinations only accept Via LAN / Deny.
        val lanDest = answered.request.lanDestination ||
            isLanMatchDest(answered.matchDest) ||
            isLanMatchDest(answered.request.destIp)
        val effective = when {
            lanDest -> lanCoerce(verdict, lanDest = true).also {
                if (it != verdict) {
                    Timber.w("LAN prompt answer %s coerced → %s", verdict, it)
                }
            }
            verdict == FirewallVerdict.ALLOW_OVPN && answered.request.socksPlane -> {
                Timber.w("ALLOW_OVPN→Tor for SOCKS-plane answer (cannot encapsulate SoftEther)")
                FirewallVerdict.ALLOW_TOR
            }
            verdict == FirewallVerdict.ALLOW_OVPN &&
                (
                    TunnelEndpoints.isOnionLikeHostname(answered.matchDest) ||
                        TunnelEndpoints.isAutomapVirtual(answered.request.destIp)
                    ) -> {
                Timber.w("ALLOW_OVPN→Tor for Automap/.onion answer (SoftEther cannot SOCKS5A)")
                FirewallVerdict.ALLOW_TOR
            }
            verdict == FirewallVerdict.ALLOW_LAN -> {
                // Non-LAN clearnet must never leave via protect()'d LAN path.
                Timber.w("ALLOW_LAN refused for non-LAN dest — DENY")
                FirewallVerdict.DENY
            }
            else -> verdict
        }
        // Exact port by default (LAN SSRF). Cake/monerod multi-port: install sibling
        // exact-port rules (18080/18081/18089) — never destPort=-1 wildcards (W5-10 R3).
        val answeredPort = answered.request.destPort
        val cakeSiblingPorts = if (
            lanDest &&
            (effective == FirewallVerdict.ALLOW_LAN || effective == FirewallVerdict.DENY) &&
            answeredPort in LAN_CAKE_PORTS
        ) {
            LAN_CAKE_PORTS
        } else {
            null
        }
        if (cakeSiblingPorts != null) {
            cancelLanHostPrompts(
                uid = answered.request.uid,
                lanHost = answered.matchDest,
                exceptRequestId = answered.request.requestId,
            )
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
        if (rule.isPoisonLanAllow() || rule.isPoisonEmptyDest()) {
            Timber.e("Refusing to persist poison rule dest_len=%d", rule.destHost.length)
            synchronized(queueLock) {
                if (active === answered) {
                    pendingByKey.remove(answered.ruleKey, answered)
                    active = null
                    _pendingPrompt.value = null
                    publishQueueDepthLocked()
                    promoteLocked()
                }
            }
            promptNotifier.cancel()
            return
        }
        val siblingRules = cakeSiblingPorts?.mapNotNull { port ->
            if (port == rule.destPort) return@mapNotNull null
            rule.copy(
                id = UUID.randomUUID().toString(),
                destPort = port,
                protocol = IpPacketParser.PROTO_TCP,
            )
        }.orEmpty()
        scope.launch {
            rulesStore.upsert(rule)
            for (sib in siblingRules) {
                rulesStore.upsert(sib)
            }
        }
        rules.updateAndGet { list ->
            val siblingPorts = siblingRules.map { it.destPort }.toSet() + rule.destPort
            list.filterNot { existing ->
                existing.uid == rule.uid &&
                    existing.destHost.equals(rule.destHost, ignoreCase = true) &&
                    existing.destPort in siblingPorts &&
                    existing.protocol == rule.protocol
            } + rule + siblingRules
        }
        // TEMPORARY must not sticky decisionCache: rules StateFlow only emits on upsert/remove,
        // so wall-clock expiry never hits the collect invalidate — answers would outlive the rule.
        // findRule still honors the TEMPORARY until expiresAt; flowCache covers this TCP only.
        val live = coerceLiveOvpn(effective, prefs)
        if (ruleScope == FirewallRuleScope.TEMPORARY) {
            caches.rememberFlow(answered.flowKey, live, answered.matchDest, answered.tupleKey)
            val destToInvalidate = answered.matchDest
            val delayMs = ((expires ?: 0L) - System.currentTimeMillis()).coerceAtLeast(0L)
            lateinit var expiry: Runnable
            expiry = Runnable {
                tempExpiryRunnables.remove(expiry)
                // Always invalidate dest — sibling 5-tuples pin ALLOW_LAN across TEMP TTL (B07).
                caches.invalidateDestination(destToInvalidate)
                rules.updateAndGet { list -> list.filterNot { it.isExpired() } }
                scope.launch { rulesStore.removeWhere { it.isExpired() } }
            }
            tempExpiryRunnables.add(expiry)
            mainHandler.postDelayed(expiry, delayMs)
        } else {
            if (cakeSiblingPorts != null) {
                caches.invalidateDestination(answered.matchDest)
                caches.invalidateDestination(answered.request.destIp)
            }
            caches.rememberDecision(
                answered.decisionKey,
                answered.flowKey,
                effective,
                answered.matchDest,
                answered.tupleKey,
            )
            // SOCKS-plane stickies for answered + Cake sibling exact ports (findRule covers TUN).
            val stickyPorts = cakeSiblingPorts ?: setOf(answered.request.destPort)
            for (port in stickyPorts) {
                val socksRk = FirewallCacheKeys.socksDecisionKey(
                    answered.request.uid,
                    answered.matchDest,
                    port,
                    IpPacketParser.PROTO_TCP,
                )
                val socksFk = FirewallCacheKeys.socksFlowKey(
                    answered.request.uid,
                    answered.matchDest,
                    port,
                )
                caches.rememberDecision(socksRk, socksFk, effective, answered.matchDest)
            }
            // flowCache must hold live plane so a Tor SYN while OVPN was down does not
            // mid-TCP flip to SoftEther after SNAT recovers (decisionCache keeps intent).
            if (live != effective) {
                caches.rememberFlow(
                    answered.flowKey,
                    live,
                    answered.matchDest,
                    answered.tupleKey,
                )
            }
        }
        val note = when (ruleScope) {
            FirewallRuleScope.TEMPORARY -> "temporary ${prefs.firewallTempMinutes}m"
            FirewallRuleScope.SESSION -> "until VPN stops"
            FirewallRuleScope.PERMANENT -> "permanent"
        }
        Timber.i(
            "Firewall answer %s dest_len=%d port=%d verdict=%s scope=%s",
            answered.request.appLabel,
            answered.matchDest.length,
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
        // Rule+sticky live — now drop pending so re-SYN hits findRule / decisionCache.
        promptNotifier.cancel()
        synchronized(queueLock) {
            if (active === answered || active?.request?.requestId == requestId) {
                pendingByKey.remove(answered.ruleKey, answered)
                active = null
                _pendingPrompt.value = null
                publishQueueDepthLocked()
                promoteLocked()
            }
        }
    }

    fun deleteRule(id: String) {
        scope.launch { rulesStore.remove(id) }
        rules.updateAndGet { it.filterNot { r -> r.id == id } }
        // Rule identity is not keyed the same as flow hashes — clear sticky caches.
        caches.clearAll()
    }

    /**
     * Drop permanent Via OVPN rules (and sticky caches) when leaving default Allow-via-OVPN
     * or when the OpenVPN data plane is known-bad. Persistent Via OVPN destinations
     * otherwise keep forcing OPENTUN even after default → Tor.
     */
    fun clearPermanentOvpnRules() {
        clearOvpnRules(scopes = setOf(FirewallRuleScope.PERMANENT))
    }

    /** UI / Via OVPN blackhole: drop every stored Via OVPN rule and sticky caches. */
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
        // Only scrub OVPN stickies — clearAll() used to kill Via LAN mid-flows (B04).
        caches.clearVerdict(FirewallVerdict.ALLOW_OVPN)
        Timber.i("Cleared Via OVPN rules scopes=%s + OVPN sticky caches", scopes)
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
     * Brief retry mirrors [SocksUidBridge] Automap wait so DNS→cache races do not silent-DENY SYN.
     * @return null when Automap IP has no hostname yet (fail-closed).
     */
    private fun matchDestination(info: IpPacketInfo): String? {
        val ip = info.dstIp
        if (!TunnelEndpoints.isAutomapVirtual(ip)) return ip
        DnsHostnameCache.lookup(ip)?.let { host ->
            if (TunnelEndpoints.isOnionLikeHostname(host)) return host
        }
        // Never park the TUN reader waiting for Automap cache — miss → DENY this SYN;
        // next SYN after DNS fill succeeds (SocksUidBridge also retries Automap rewrite).
        return null
    }

    /** Drop ASK queue entries tied to an Automap IP or its old/new hostnames. */
    /**
     * After Via LAN / Deny for an RFC1918 host, drop other queued prompts for the same
     * app UID + IP (different dest ports). Active was already cleared by [answerPrompt].
     */
    private fun cancelLanHostPrompts(uid: Int, lanHost: String, exceptRequestId: String) {
        val host = lanHost.trim().lowercase()
        if (host.isEmpty()) return
        fun QueuedPrompt.tiedToLanHost(): Boolean {
            if (request.uid != uid) return false
            if (request.requestId == exceptRequestId) return false
            val dests = listOf(matchDest, request.destIp, request.destHost.orEmpty())
            return dests.any { it.trim().equals(host, ignoreCase = true) }
        }
        synchronized(queueLock) {
            val toDrop = pendingByKey.values.filter { it.tiedToLanHost() }.toList()
            for (q in toDrop) {
                pendingByKey.remove(q.ruleKey)
                waitQueue.remove(q.ruleKey)
            }
            if (toDrop.isNotEmpty()) {
                Timber.i(
                    "LAN host verdict — cancelled %d sibling ASK prompt(s) for %s",
                    toDrop.size,
                    host,
                )
                publishQueueDepthLocked()
            }
        }
    }

    private fun cancelAutomapPrompts(ip: String, oldHost: String, newHost: String) {
        val targets = setOf(ip, oldHost, newHost)
            .map { it.trim().lowercase() }
            .filter { it.isNotBlank() }
            .toSet()
        if (targets.isEmpty()) return
        fun matches(dest: String?): Boolean {
            val d = dest?.trim()?.lowercase() ?: return false
            return d in targets
        }
        fun QueuedPrompt.tiedToAutomap(): Boolean =
            matches(matchDest) || matches(request.destHost) || matches(request.destIp)

        synchronized(queueLock) {
            val toDrop = pendingByKey.values.filter { it.tiedToAutomap() }.toList()
            var clearedActive = false
            active?.let { cur ->
                if (cur.tiedToAutomap()) {
                    active = null
                    _pendingPrompt.value = null
                    mainHandler.post { promptNotifier.cancel() }
                    clearedActive = true
                }
            }
            for (q in toDrop) {
                pendingByKey.remove(q.ruleKey)
                waitQueue.remove(q.ruleKey)
            }
            if (toDrop.isNotEmpty() || clearedActive) {
                Timber.i(
                    "Automap remap — cancelled %d ASK prompt(s)",
                    toDrop.size,
                )
                promoteLocked()
                publishQueueDepthLocked()
            }
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
        if (DiagnosticsGate.isNoLogs() || preferences.get().noLogsEnabled) return
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
        /** TUN 5-tuple mid-flow sticky; null for PAC SOCKS. */
        val tupleKey: Long? = null,
    )


    /**
     * PAC / hev SOCKS cannot encapsulate SoftEther. Demoting ALLOW_OVPN → Tor
     * created dual egress (TUN SoftEther + SOCKS Tor exit). Fail-closed: DENY
     * on the SOCKS plane so Via OVPN stays SoftEther-only on TUN.
     */
    private fun coerceSocksVerdict(v: FirewallVerdict): FirewallVerdict {
        if (v != FirewallVerdict.ALLOW_OVPN) return v
        return FirewallVerdict.DENY
    }

    /**
     * Demote ALLOW_OVPN → Tor for Automap/.onion (SoftEther cannot SOCKS5A).
     * Clearnet OVPN intent is preserved for sticky cache/rules.
     */
    private fun stickyIntent(
        v: FirewallVerdict,
        matchDest: String,
        info: IpPacketInfo,
    ): FirewallVerdict =
        if (v == FirewallVerdict.ALLOW_OVPN &&
            (
                TunnelEndpoints.isAutomapVirtual(info.dstIp) ||
                    TunnelEndpoints.isOnionLikeHostname(matchDest)
                )
        ) {
            FirewallVerdict.ALLOW_TOR
        } else {
            v
        }

    /** Default ALLOW_OVPN when data plane is up; otherwise DENY (never Tor exit swap). */
    private fun defaultOvpnOrTor(prefs: TunnelPreferences): FirewallVerdict =
        if (ovpnRouteAvailable(prefs)) FirewallVerdict.ALLOW_OVPN else FirewallVerdict.DENY

    /**
     * Sticky ALLOW_OVPN rules/cache must still honor live SNAT health — align with
     * TunDnsMux drop when Via OVPN is down (never SoftEther→Tor exit on new SYN).
     * Does not rewrite stored intent — only the returned live verdict.
     */
    private fun coerceLiveOvpn(v: FirewallVerdict, prefs: TunnelPreferences): FirewallVerdict =
        if (v == FirewallVerdict.ALLOW_OVPN && !ovpnRouteAvailable(prefs)) {
            FirewallVerdict.DENY
        } else {
            v
        }

    /**
     * Mid-flow sticky after flow-cache/tuple miss. Never invent SoftEther — a Tor TCP
     * whose trim raced a permanent Via-OVPN rule would otherwise flip exits mid-stream.
     * Live OVPN planes must already be stamped on tupleKey/flowCache (checked above).
     * OVPN sticky without stamp → DENY (same as OVPN-down SYN).
     */
    private fun midFlowStickyLive(v: FirewallVerdict, @Suppress("UNUSED_PARAMETER") prefs: TunnelPreferences): FirewallVerdict =
        when (v) {
            FirewallVerdict.ALLOW_OVPN -> FirewallVerdict.DENY
            FirewallVerdict.ALLOW_LAN,
            FirewallVerdict.ALLOW_TOR,
            FirewallVerdict.DENY,
            -> v
        }

    /**
     * Mid-flow cache miss (UID lost / trim) with no sticky rule/decision.
     * Tor-default (ALLOW/ASK) fail-open to Tor so trim does not RST clearnet-via-Tor.
     * OVPN-default / DENY → DENY (never invent SoftEther or a Tor exit swap).
     */
    private fun midFlowFallback(prefs: TunnelPreferences): FirewallVerdict =
        when (prefs.firewallDefaultAction) {
            FirewallDefaultAction.ALLOW,
            FirewallDefaultAction.ASK,
            -> FirewallVerdict.ALLOW_TOR
            FirewallDefaultAction.ALLOW_OVPN,
            FirewallDefaultAction.DENY,
            -> FirewallVerdict.DENY
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
        val up = ovpnRouteAvailable()
        if (!up) {
            // SoftEther demote: drop live OVPN stickies so mux doesn't silent-drop mid-flow.
            caches.clearVerdict(FirewallVerdict.ALLOW_OVPN)
        }
        val shown = synchronized(queueLock) { active?.request } ?: return
        if (shown.socksPlane || shown.lanDestination) return
        mainHandler.post { promptNotifier.show(shown) }
        Timber.i("Firewall prompt refreshed — Via OVPN available=%s", up)
    }

    companion object {
        private const val MAX_JOURNAL = 200
        private const val JOURNAL_CHANNEL_CAP = 64
        private const val MAX_QUEUE = 64
        /** Unanswered ASK → DENY (Always-On / denied notifications). */
        private const val ASK_TTL_MS = 5 * 60_000L
        /** Cake Wallet / monerod multi-port LAN (RPC + ZMQ) — exact sibling ports, not -1. */
        private val LAN_CAKE_PORTS = setOf(18080, 18081, 18089)
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
