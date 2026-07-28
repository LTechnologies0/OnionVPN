package ltechnologies.onionphone.onionvpn.firewall

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import dagger.hilt.android.qualifiers.ApplicationContext
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.FirewallConnectionInfo
import ltechnologies.onionphone.onionvpn.core.model.FirewallDefaultAction
import ltechnologies.onionphone.onionvpn.core.model.FirewallJournalEntry
import ltechnologies.onionphone.onionvpn.core.model.FirewallRule
import ltechnologies.onionphone.onionvpn.core.model.FirewallRuleScope
import ltechnologies.onionphone.onionvpn.core.model.FirewallVerdict
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketInfo
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.PacketFirewall
import ltechnologies.onionphone.onionvpn.prefs.TunnelPreferencesStore
import timber.log.Timber

@Singleton
class InteractiveFirewallEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val rulesStore: FirewallRulesStore,
    private val preferencesStore: TunnelPreferencesStore,
) : PacketFirewall {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ownerResolver = ConnectionOwnerResolver(context)
    private val mainHandler = Handler(Looper.getMainLooper())
    private val ownUid = android.os.Process.myUid()

    private val preferences = AtomicReference(TunnelPreferences())
    private val rules = AtomicReference<List<FirewallRule>>(emptyList())

    /** Flow key → last known allow/deny for established flows (session cache). */
    private val flowCache = ConcurrentHashMap<String, FirewallVerdict>()
    /** uid|dst|port|proto → verdict (survives ephemeral local ports). */
    private val decisionCache = ConcurrentHashMap<String, FirewallVerdict>()
    /** Rule key (uid|host|port|proto) currently waiting for user. */
    private val pending = ConcurrentHashMap<String, PendingPrompt>()

    private val _journal = MutableStateFlow<List<FirewallJournalEntry>>(emptyList())
    val journal: StateFlow<List<FirewallJournalEntry>> = _journal.asStateFlow()

    private val _pendingPrompt = MutableStateFlow<FirewallConnectionInfo?>(null)
    val pendingPrompt: StateFlow<FirewallConnectionInfo?> = _pendingPrompt.asStateFlow()

    fun start() {
        scope.launch {
            rulesStore.load()
            _journal.value = rulesStore.persistedJournal.value
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
        pending.values.forEach { it.complete(FirewallVerdict.DENY, timedOut = true) }
        pending.clear()
        _pendingPrompt.value = null
    }

    override fun allowOutbound(packet: ByteArray, length: Int): Boolean {
        val prefs = preferences.get()
        if (!prefs.firewallEnabled) return true

        val info = IpPacketParser.parse(packet, length) ?: return true
        // Only gate new TCP SYNs and UDP datagrams; allow mid-flow TCP.
        val flowKey = flowKey(info)
        flowCache[flowKey]?.let { return it == FirewallVerdict.ALLOW }

        if (info.isTcp && !info.isTcpSyn) {
            return true
        }

        val uid = ownerResolver.resolveUid(info)
        if (uid == ownUid || uid == android.os.Process.SYSTEM_UID) {
            return true
        }
        // Unknown owner: still prompt/deny based on default — use uid=-1 bucket.
        val effectiveUid = if (uid < 0) UNKNOWN_UID else uid
        val app = resolveApp(effectiveUid)

        val matching = findRule(effectiveUid, info)
        if (matching != null) {
            rememberFlow(flowKey, matching.verdict)
            return matching.verdict == FirewallVerdict.ALLOW
        }

        // Collapse ephemeral-port spam (esp. UDP) onto uid|dst|port|proto.
        val rk = ruleKey(effectiveUid, info.dstIp, info.dstPort, info.protocol)
        decisionCache[rk]?.let { v ->
            rememberFlow(flowKey, v)
            return v == FirewallVerdict.ALLOW
        }

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
            FirewallDefaultAction.ASK -> askUserNonBlocking(effectiveUid, app, info, flowKey, prefs)
        }
    }

    /**
     * Never block the TUN thread. Drop until the user answers; TCP SYN retransmits
     * after an allow rule is stored.
     */
    private fun askUserNonBlocking(
        uid: Int,
        app: AppIdentity,
        info: IpPacketInfo,
        flowKey: String,
        prefs: TunnelPreferences,
    ): Boolean {
        val ruleKey = ruleKey(uid, info.dstIp, info.dstPort, info.protocol)
        if (pending.containsKey(ruleKey)) {
            return false
        }

        val request = FirewallConnectionInfo(
            requestId = UUID.randomUUID().toString(),
            uid = uid,
            packageName = app.packageName,
            appLabel = app.label,
            destIp = info.dstIp,
            destPort = info.dstPort,
            protocol = info.protocol,
            protocolLabel = IpPacketParser.protocolLabel(info.protocol),
        )
        val prompt = PendingPrompt(request)
        if (pending.putIfAbsent(ruleKey, prompt) != null) {
            return false
        }
        _pendingPrompt.value = request
        launchPromptActivity()

        val timeoutSec = prefs.firewallPromptTimeoutSec.coerceIn(5, 120)
        scope.launch {
            val verdict = prompt.await(timeoutSec)
            pending.remove(ruleKey, prompt)
            if (_pendingPrompt.value?.requestId == request.requestId) {
                _pendingPrompt.value = null
            }
            if (prompt.timedOut) {
                // Auto-deny on timeout so retransmits don't re-prompt forever.
                val denyRule = FirewallRule(
                    id = UUID.randomUUID().toString(),
                    uid = uid,
                    packageName = app.packageName,
                    appLabel = app.label,
                    destHost = info.dstIp,
                    destPort = info.dstPort,
                    protocol = info.protocol,
                    verdict = FirewallVerdict.DENY,
                    scope = FirewallRuleScope.TEMPORARY,
                    expiresAtEpochMs = System.currentTimeMillis() +
                        prefs.firewallTempMinutes.coerceIn(1, 1440) * 60_000L,
                )
                rules.updateAndGet { list ->
                    list.filterNot {
                        it.uid == denyRule.uid &&
                            it.destHost == denyRule.destHost &&
                            it.destPort == denyRule.destPort &&
                            it.protocol == denyRule.protocol
                    } + denyRule
                }
                rulesStore.upsert(denyRule)
                appendJournal(
                    uid = uid,
                    app = app,
                    info = info,
                    verdict = FirewallVerdict.DENY,
                    scope = FirewallRuleScope.TEMPORARY,
                    note = "prompt timeout → deny",
                )
            }
            rememberFlow(flowKey, verdict)
            decisionCache[ruleKey] = verdict
        }
        return false
    }

    fun answerPrompt(
        requestId: String,
        verdict: FirewallVerdict,
        temporary: Boolean,
    ) {
        val prefs = preferences.get()
        val current = _pendingPrompt.value
        if (current == null || current.requestId != requestId) {
            Timber.w("Stale firewall prompt answer id=$requestId")
            return
        }
        val ruleKey = ruleKey(current.uid, current.destIp, current.destPort, current.protocol)
        val pendingPrompt = pending.remove(ruleKey) ?: return

        val ruleScope = if (temporary) FirewallRuleScope.TEMPORARY else FirewallRuleScope.PERMANENT
        val expires = if (temporary) {
            System.currentTimeMillis() + prefs.firewallTempMinutes.coerceIn(1, 1440) * 60_000L
        } else {
            null
        }
        val rule = FirewallRule(
            id = UUID.randomUUID().toString(),
            uid = current.uid,
            packageName = current.packageName,
            appLabel = current.appLabel,
            destHost = current.destIp,
            destPort = current.destPort,
            protocol = current.protocol,
            verdict = verdict,
            scope = ruleScope,
            expiresAtEpochMs = expires,
        )
        this.scope.launch {
            rulesStore.upsert(rule)
        }
        // Also keep in-memory immediately for hot path.
        rules.updateAndGet { list ->
            list.filterNot {
                it.uid == rule.uid &&
                    it.destHost == rule.destHost &&
                    it.destPort == rule.destPort &&
                    it.protocol == rule.protocol
            } + rule
        }

        appendJournal(
            uid = current.uid,
            app = AppIdentity(current.packageName, current.appLabel),
            destIp = current.destIp,
            destPort = current.destPort,
            protocolLabel = current.protocolLabel,
            verdict = verdict,
            scope = ruleScope,
            note = if (temporary) "temporary ${prefs.firewallTempMinutes}m" else "permanent",
        )

        _pendingPrompt.value = null
        decisionCache[ruleKey] = verdict
        pendingPrompt.complete(verdict, timedOut = false)
    }

    fun deleteRule(id: String) {
        scope.launch { rulesStore.remove(id) }
        rules.updateAndGet { it.filterNot { r -> r.id == id } }
        flowCache.clear()
        decisionCache.clear()
    }

    fun rulesFlow(): StateFlow<List<FirewallRule>> = rulesStore.rules

    private fun findRule(uid: Int, info: IpPacketInfo): FirewallRule? {
        val now = System.currentTimeMillis()
        val list = rules.get()
        // Prefer most specific: exact host+port+proto, then host+any port, then uid-wide.
        return list
            .filter { !it.isExpired(now) && it.matches(uid, info.dstIp, info.dstPort, info.protocol) }
            .maxWithOrNull(
                compareBy(
                    { if (it.destHost.isNotEmpty()) 1 else 0 },
                    { if (it.destPort >= 0) 1 else 0 },
                    { if (it.protocol >= 0) 1 else 0 },
                    { it.createdAtEpochMs },
                ),
            )
    }

    private fun rememberDecision(ruleKey: String, flowKey: String, verdict: FirewallVerdict) {
        decisionCache[ruleKey] = verdict
        rememberFlow(flowKey, verdict)
        if (decisionCache.size > 4_000) {
            decisionCache.clear()
        }
    }

    private fun rememberFlow(flowKey: String, verdict: FirewallVerdict) {
        flowCache[flowKey] = verdict
        if (flowCache.size > 8_000) {
            flowCache.clear()
        }
    }

    private fun launchPromptActivity() {
        mainHandler.post {
            try {
                val intent = Intent(context, FirewallPromptActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                }
                context.startActivity(intent)
            } catch (error: Exception) {
                Timber.e(error, "Failed to launch firewall prompt")
            }
        }
    }

    private fun resolveApp(uid: Int): AppIdentity {
        if (uid == UNKNOWN_UID) {
            return AppIdentity("unknown", "Unknown app")
        }
        return try {
            val pm = context.packageManager
            val packages = pm.getPackagesForUid(uid)
            val pkg = packages?.firstOrNull() ?: "uid:$uid"
            val label = try {
                val ai = pm.getApplicationInfo(pkg, 0)
                pm.getApplicationLabel(ai).toString()
            } catch (_: PackageManager.NameNotFoundException) {
                pkg
            }
            AppIdentity(pkg, label)
        } catch (_: Exception) {
            AppIdentity("uid:$uid", "UID $uid")
        }
    }

    private fun appendJournal(
        uid: Int,
        app: AppIdentity,
        info: IpPacketInfo,
        verdict: FirewallVerdict,
        scope: FirewallRuleScope,
        note: String,
    ) {
        appendJournal(
            uid = uid,
            app = app,
            destIp = info.dstIp,
            destPort = info.dstPort,
            protocolLabel = IpPacketParser.protocolLabel(info.protocol),
            verdict = verdict,
            scope = scope,
            note = note,
        )
    }

    private fun appendJournal(
        uid: Int,
        app: AppIdentity,
        destIp: String,
        destPort: Int,
        protocolLabel: String,
        verdict: FirewallVerdict,
        scope: FirewallRuleScope,
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
            scope = scope,
            note = note,
        )
        _journal.updateAndGet { list ->
            (listOf(entry) + list).take(MAX_JOURNAL)
        }
        this.scope.launch { rulesStore.appendJournal(entry) }
    }

    private fun flowKey(info: IpPacketInfo): String =
        "${info.protocol}|${info.srcIp}:${info.srcPort}->${info.dstIp}:${info.dstPort}"

    private fun ruleKey(uid: Int, destIp: String, destPort: Int, protocol: Int): String =
        "$uid|$destIp|$destPort|$protocol"

    private data class AppIdentity(val packageName: String, val label: String)

    private class PendingPrompt(val request: FirewallConnectionInfo) {
        private val latch = CountDownLatch(1)
        @Volatile var verdict: FirewallVerdict = FirewallVerdict.DENY
        @Volatile var timedOut: Boolean = false

        fun await(timeoutSec: Int): FirewallVerdict {
            val ok = latch.await(timeoutSec.toLong(), TimeUnit.SECONDS)
            if (!ok) {
                timedOut = true
                verdict = FirewallVerdict.DENY
            }
            return verdict
        }

        fun complete(verdict: FirewallVerdict, timedOut: Boolean) {
            this.verdict = verdict
            this.timedOut = timedOut
            latch.countDown()
        }
    }

    companion object {
        private const val UNKNOWN_UID = -1
        private const val MAX_JOURNAL = 200
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
