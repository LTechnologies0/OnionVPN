package ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Process
import androidx.core.content.ContextCompat
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.geo.RelayCountryLookup
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityAction
import ltechnologies.onionphone.onionvpn.core.model.stability.StabilityClassifier
import timber.log.Timber

/**
 * Tracks CIRC/STREAM events for UI and **surgical** ControlPort cleanup.
 *
 * Stability policy (path-spec KeepAliveIsolateSOCKSAuth / prop. 368 CDT rethink /
 * Privacy Guides / Tor Browser):
 * - Per-UID `u{uid}` circuits are **sticky** — Tor manages dirtiness; we do **not**
 *   CLOSECIRCUIT on every short stream end (that fought KeepAlive + pooling).
 * - Auto-close only: FAILED circuits, or idle ephemeral (no SOCKS auth) after grace.
 * - App death: CLOSESTREAM + CLOSECIRCUIT IfUnused only on PACKAGE_REMOVED /
 *   PACKAGE_RESTARTED for that UID (never ActivityManager.runningAppProcesses polls).
 * - Poll slower while Tor is dormant (battery).
 */
class CircuitLifecycleManager(
    private val context: Context,
    private val control: TorControlClient,
) {
    data class LiveCircuit(
        val info: TorCircuitInfo,
        val streamIds: Set<String> = emptySet(),
        val socksUsername: String? = null,
        val firstSeenMs: Long = System.currentTimeMillis(),
        val lastActivityMs: Long = System.currentTimeMillis(),
        /** KeepAliveIsolateSOCKSAuth domain — never auto-torn for short streams. */
        val stickyAuth: Boolean = false,
        val longLived: Boolean = false,
        val hops: List<RelayCountryLookup.Hop> = emptyList(),
    )

    data class LiveStream(
        val info: TorStreamInfo,
        val succeededAtMs: Long? = null,
        val socksUsername: String? = null,
    )

    private var supervisor: Job = SupervisorJob()
    private var scope = CoroutineScope(supervisor + Dispatchers.IO)
    private var eventsJob: Job? = null
    private var pollJob: Job? = null
    private var packageReceiver: BroadcastReceiver? = null

    private val streams = ConcurrentHashMap<String, LiveStream>()
    private val circuits = ConcurrentHashMap<String, LiveCircuit>()
    /** Circuit ids waiting for idle grace before CLOSECIRCUIT IfUnused. */
    private val pendingIdleClose = ConcurrentHashMap<String, Long>()
    private val countryLookup = RelayCountryLookup(control)

    private val _circuits = MutableStateFlow<List<LiveCircuit>>(emptyList())
    val liveCircuits: StateFlow<List<LiveCircuit>> = _circuits.asStateFlow()

    private val _streams = MutableStateFlow<List<LiveStream>>(emptyList())
    val liveStreams: StateFlow<List<LiveStream>> = _streams.asStateFlow()

    @Volatile private var running = false

    fun start() {
        if (running) return
        if (!supervisor.isActive) {
            supervisor = SupervisorJob()
            scope = CoroutineScope(supervisor + Dispatchers.IO)
        }
        running = true
        eventsJob = scope.launch {
            control.events.collect { event ->
                when (event) {
                    is TorControlEvent.Stream -> onStreamEvent(event)
                    is TorControlEvent.Circuit -> onCircuitEvent(event)
                    else -> Unit
                }
            }
        }
        pollJob = scope.launch {
            while (isActive && running) {
                val dormant = control.status.value.dormant
                refreshFromGetInfo()
                // Do NOT poll ActivityManager.runningAppProcesses — on modern Android it only
                // returns a tiny subset of UIDs, so we were CLOSECIRCUIT'ing live app circuits
                // every tick (traffic "allowed" by firewall but Tor streams killed).
                flushIdleCloses()
                delay(if (dormant) DORMANT_POLL_MS else APP_POLL_MS)
            }
        }
        registerPackageReceiver()
        scope.launch { refreshFromGetInfo() }
        Timber.i("CircuitLifecycleManager started (sticky KeepAlive auth; soft idle close)")
    }

    fun stop() {
        running = false
        eventsJob?.cancel()
        eventsJob = null
        pollJob?.cancel()
        pollJob = null
        supervisor.cancel()
        unregisterPackageReceiver()
        streams.clear()
        circuits.clear()
        pendingIdleClose.clear()
        _circuits.value = emptyList()
        _streams.value = emptyList()
    }

    fun refreshFromGetInfo() {
        if (!control.isConnected) return
        runCatching {
            val circList = control.listCircuits()
            val streamList = control.listStreams()
            val now = System.currentTimeMillis()
            val streamByCirc = streamList.groupBy { it.circuitId }
            for (c in circList) {
                val existing = circuits[c.id]
                val sids = streamByCirc[c.id].orEmpty().map { it.id }.toSet()
                val socks = c.socksUsername
                    ?: streamByCirc[c.id]?.firstOrNull { !it.socksUsername.isNullOrBlank() }?.socksUsername
                    ?: existing?.socksUsername
                val sticky = isStickySocksAuth(socks) || existing?.stickyAuth == true
                val longLived = sticky || existing?.longLived == true ||
                    streamByCirc[c.id].orEmpty().any { streamLongLived(it.id, now) } ||
                    sids.size > 1
                if (sids.isNotEmpty()) pendingIdleClose.remove(c.id)
                val hops = hopsFor(c.path, existing)
                circuits[c.id] = LiveCircuit(
                    info = c,
                    streamIds = sids,
                    socksUsername = socks,
                    firstSeenMs = existing?.firstSeenMs ?: now,
                    lastActivityMs = if (sids.isNotEmpty()) now else (existing?.lastActivityMs ?: now),
                    stickyAuth = sticky,
                    longLived = longLived,
                    hops = hops,
                )
            }
            val liveIds = circList.map { it.id }.toSet()
            circuits.keys.retainAll(liveIds)
            pendingIdleClose.keys.retainAll(liveIds)

            for (s in streamList) {
                val prev = streams[s.id]
                streams[s.id] = LiveStream(
                    info = s,
                    succeededAtMs = when {
                        s.status == "SUCCEEDED" -> prev?.succeededAtMs ?: now
                        else -> prev?.succeededAtMs
                    },
                    socksUsername = s.socksUsername ?: prev?.socksUsername,
                )
            }
            val liveStreamIds = streamList.map { it.id }.toSet()
            streams.keys.retainAll(liveStreamIds)
            publish()
        }.onFailure { Timber.d(it, "CircuitLifecycleManager refresh failed") }
    }

    fun closeCircuit(id: String, ifUnused: Boolean = true): Result<Unit> =
        control.closeCircuit(id, ifUnused).also {
            pendingIdleClose.remove(id)
            refreshFromGetInfo()
        }

    fun extendNewCircuit(): Result<String> =
        control.extendNewCircuit().also { refreshFromGetInfo() }

    private fun onStreamEvent(event: TorControlEvent.Stream) {
        val now = System.currentTimeMillis()
        when (event.status) {
            "NEW", "NEWRESOLVE", "SENTCONNECT", "SENTRESOLVE", "SUCCEEDED",
            "REMAP", "CONTROLLER_WAIT", "XOFF_SENT", "XOFF_RECV", "XON_SENT", "XON_RECV",
            -> {
                val prev = streams[event.id]
                val succeededAt = when {
                    event.status == "SUCCEEDED" -> prev?.succeededAtMs ?: now
                    else -> prev?.succeededAtMs
                }
                streams[event.id] = LiveStream(
                    info = TorStreamInfo(
                        id = event.id,
                        status = event.status,
                        circuitId = event.circuitId,
                        target = event.target,
                        sourceAddr = event.sourceAddr,
                        purpose = event.purpose,
                        socksUsername = event.socksUsername,
                        socksPassword = event.socksPassword,
                        clientProtocol = event.clientProtocol,
                        reason = event.reason,
                    ),
                    succeededAtMs = succeededAt,
                    socksUsername = event.socksUsername ?: prev?.socksUsername,
                )
                updateCircuitFromStream(event.circuitId, event, now, add = true)
            }
            "FAILED", "CLOSED", "DETACHED" -> {
                val removed = streams.remove(event.id)
                val circId = event.circuitId.takeIf { it != "0" }
                    ?: removed?.info?.circuitId
                if (circId != null && circId != "0") {
                    maybeScheduleIdleClose(circId, removed, now, streamFailed = event.status == "FAILED")
                }
                if (event.status == "FAILED") {
                    val signal = StabilityClassifier.forStreamReason(event.reason)
                    when (signal.action) {
                        StabilityAction.SOFT_RECOVER, StabilityAction.HARD_RECOVER ->
                            Timber.d(
                                "STREAM FAILED id=%s reason=%s action=%s",
                                event.id,
                                signal.code,
                                signal.action,
                            )
                        else -> Unit
                    }
                }
            }
        }
        publish()
    }

    private fun onCircuitEvent(event: TorControlEvent.Circuit) {
        val now = System.currentTimeMillis()
        when (event.status) {
            "CLOSED" -> {
                circuits.remove(event.id)
                pendingIdleClose.remove(event.id)
            }
            "FAILED" -> {
                circuits.remove(event.id)
                pendingIdleClose.remove(event.id)
                // Failed builds: ensure Tor frees resources (control-spec CLOSECIRCUIT).
                runCatching { control.closeCircuit(event.id, ifUnused = false) }
            }
            else -> {
                val prev = circuits[event.id]
                val socks = event.socksUsername ?: prev?.socksUsername
                val sticky = isStickySocksAuth(socks) || prev?.stickyAuth == true
                circuits[event.id] = LiveCircuit(
                    info = TorCircuitInfo(
                        id = event.id,
                        status = event.status,
                        path = event.path,
                        purpose = event.purpose.orEmpty(),
                        socksUsername = socks,
                        socksPassword = event.socksPassword ?: prev?.info?.socksPassword,
                        reason = event.reason,
                    ),
                    streamIds = prev?.streamIds.orEmpty(),
                    socksUsername = socks,
                    firstSeenMs = prev?.firstSeenMs ?: now,
                    lastActivityMs = now,
                    stickyAuth = sticky,
                    longLived = sticky || prev?.longLived == true,
                    hops = hopsFor(event.path, prev),
                )
            }
        }
        publish()
    }

    private fun updateCircuitFromStream(
        circuitId: String,
        event: TorControlEvent.Stream,
        now: Long,
        add: Boolean,
    ) {
        if (circuitId == "0") return
        val prev = circuits[circuitId]
        val sids = (prev?.streamIds.orEmpty()).toMutableSet()
        if (add) {
            sids.add(event.id)
            pendingIdleClose.remove(circuitId)
        } else {
            sids.remove(event.id)
        }
        val socks = event.socksUsername ?: prev?.socksUsername
        val sticky = isStickySocksAuth(socks) || prev?.stickyAuth == true
        val longLived = sticky || prev?.longLived == true ||
            (event.status == "SUCCEEDED" && streamLongLived(event.id, now)) ||
            sids.size > 1
        circuits[circuitId] = LiveCircuit(
            info = prev?.info?.copy(
                status = prev.info.status,
                socksUsername = socks ?: prev.info.socksUsername,
            ) ?: TorCircuitInfo(
                id = circuitId,
                status = "BUILT",
                socksUsername = socks,
            ),
            streamIds = sids,
            socksUsername = socks,
            firstSeenMs = prev?.firstSeenMs ?: now,
            lastActivityMs = now,
            stickyAuth = sticky,
            longLived = longLived,
            hops = prev?.hops.orEmpty(),
        )
    }

    private fun hopsFor(path: String, prev: LiveCircuit?): List<RelayCountryLookup.Hop> {
        if (path.isBlank()) return prev?.hops.orEmpty()
        if (prev != null && prev.info.path == path && prev.hops.isNotEmpty()) return prev.hops
        return countryLookup.hopsForPath(path)
    }

    /**
     * Sticky per-UID circuits: leave to Tor MaxCircuitDirtiness + KeepAliveIsolateSOCKSAuth.
     * Non-sticky idle: schedule grace then CLOSECIRCUIT IfUnused.
     */
    private fun maybeScheduleIdleClose(
        circuitId: String,
        removed: LiveStream?,
        now: Long,
        streamFailed: Boolean,
    ) {
        val circ = circuits[circuitId] ?: return
        val remaining = circ.streamIds - (removed?.info?.id ?: "")
        val socks = circ.socksUsername ?: removed?.socksUsername
        val sticky = circ.stickyAuth || isStickySocksAuth(socks)
        val longLived = sticky || circ.longLived ||
            (removed?.succeededAtMs?.let { now - it >= LONG_LIVED_MS } == true) ||
            remaining.isNotEmpty()
        circuits[circuitId] = circ.copy(
            streamIds = remaining,
            lastActivityMs = now,
            stickyAuth = sticky,
            longLived = longLived,
            socksUsername = socks ?: circ.socksUsername,
        )
        if (remaining.isNotEmpty()) {
            pendingIdleClose.remove(circuitId)
            return
        }
        if (sticky || longLived) {
            pendingIdleClose.remove(circuitId)
            return
        }
        // Only non-auth / ephemeral circuits get soft teardown.
        if (streamFailed) {
            control.closeCircuit(circuitId, ifUnused = true)
                .onSuccess { Timber.d("CLOSECIRCUIT IfUnused $circuitId (stream FAILED)") }
            circuits.remove(circuitId)
            pendingIdleClose.remove(circuitId)
        } else {
            pendingIdleClose.putIfAbsent(circuitId, now + IDLE_GRACE_MS)
        }
    }

    private fun flushIdleCloses() {
        val now = System.currentTimeMillis()
        val due = pendingIdleClose.entries.filter { it.value <= now }.map { it.key }
        for (id in due) {
            pendingIdleClose.remove(id)
            val circ = circuits[id] ?: continue
            if (circ.streamIds.isNotEmpty() || circ.stickyAuth || circ.longLived) continue
            control.closeCircuit(id, ifUnused = true)
                .onSuccess { Timber.d("CLOSECIRCUIT IfUnused $id (idle grace)") }
                .onFailure { Timber.d(it, "CLOSECIRCUIT $id skipped") }
            circuits.remove(id)
        }
    }

    private fun streamLongLived(streamId: String, now: Long): Boolean {
        val s = streams[streamId] ?: return false
        val at = s.succeededAtMs ?: return false
        return now - at >= LONG_LIVED_MS
    }

    /**
     * Close circuits for a UID only when we have a reliable signal the app is gone
     * (package removed / force-stop restarted) — never from runningAppProcesses polls.
     */
    private fun reapUidIfKnown(uid: Int) {
        if (uid < 0 || uid == Process.myUid()) return
        val user = TunnelEndpoints.socksUserForUid(uid)
        closeAuthDomain(user)
    }

    private fun closeAuthDomain(socksUser: String) {
        Timber.i("App gone — closing circuits for socks auth $socksUser")
        streams.values.filter { it.socksUsername == socksUser || it.info.socksUsername == socksUser }
            .forEach { s ->
                control.closeStream(s.info.id, TorControlCatalog.StreamEndReason.DONE)
            }
        circuits.values.filter { it.socksUsername == socksUser }
            .forEach { c ->
                pendingIdleClose.remove(c.info.id)
                control.closeCircuit(c.info.id, ifUnused = true)
            }
        streams.entries.removeIf { (_, v) ->
            v.socksUsername == socksUser || v.info.socksUsername == socksUser
        }
        circuits.entries.removeIf { (_, v) -> v.socksUsername == socksUser }
        publish()
    }

    private fun registerPackageReceiver() {
        if (packageReceiver != null) return
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                val uid = intent?.getIntExtra(Intent.EXTRA_UID, -1) ?: -1
                scope.launch { reapUidIfKnown(uid) }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_RESTARTED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addAction(Intent.ACTION_PACKAGE_FULLY_REMOVED)
            addDataScheme("package")
        }
        ContextCompat.registerReceiver(
            context.applicationContext,
            receiver,
            filter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        packageReceiver = receiver
    }

    private fun unregisterPackageReceiver() {
        packageReceiver?.let {
            runCatching { context.applicationContext.unregisterReceiver(it) }
        }
        packageReceiver = null
    }

    private fun publish() {
        _circuits.value = circuits.values.sortedBy { it.info.id }
        _streams.value = streams.values.sortedBy { it.info.id }
    }

    companion object {
        /** Streams SUCCEEDED this long count as background / long-lived. */
        const val LONG_LIVED_MS = 60_000L
        /** Wait before CLOSECIRCUIT on non-sticky idle circuits (lets Tor reuse briefly). */
        const val IDLE_GRACE_MS = 45_000L
        private const val APP_POLL_MS = 60_000L
        private const val DORMANT_POLL_MS = 120_000L

        fun isStickySocksAuth(username: String?): Boolean {
            if (username.isNullOrBlank()) return false
            // Per-UID app tokens + dedicated DNSCrypt / hev static tokens.
            if (TunnelEndpoints.uidFromSocksUser(username) != null) return true
            if (username == TunnelEndpoints.SOCKS_DNSCRYPT_USER) return true
            if (username == TunnelEndpoints.SOCKS_ISOLATION_USER) return true
            if (username == TunnelEndpoints.SOCKS_PAC_USER) return true
            return false
        }
    }
}
