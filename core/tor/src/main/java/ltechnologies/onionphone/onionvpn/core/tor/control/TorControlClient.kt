package ltechnologies.onionphone.onionvpn.core.tor.control

import java.io.File
import java.io.IOException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorCircuitInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorStreamInfo
import ltechnologies.onionphone.onionvpn.core.tor.control.ops.TorControlOperations
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlEventParser
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlWire
import ltechnologies.onionphone.onionvpn.core.tor.control.transport.TorControlTransport
import timber.log.Timber

/**
 * Package `control` — public façade over transport + protocol + ops.
 *
 * Sequential connect pipeline (control-spec):
 * 1. Open ControlSocket (transport)
 * 2. AUTHENTICATE (cookie hex)
 * 3. TAKEOWNERSHIP + RESETCONF __OwningControllerProcess
 * 4. USEFEATURE VERBOSE_NAMES then EXTENDED_EVENTS (always-on no-ops on modern Tor)
 * 5. SETEVENTS core → optional → PT (incremental; PT only if bridges)
 * 6. refreshBootstrap (minimal GETINFO)
 *
 * @see <a href="https://spec.torproject.org/control-spec/">control-spec</a>
 */
class TorControlClient {
    private val _status = MutableStateFlow(TorControlStatus())
    /** Live aggregated control status for UI / validation. */
    val status: StateFlow<TorControlStatus> = _status.asStateFlow()

    private val _events = MutableSharedFlow<TorControlEvent>(
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    /** Async 650 events (skip BW in log sinks if noisy). */
    val events: SharedFlow<TorControlEvent> = _events.asSharedFlow()

    private val transport = TorControlTransport(
        onAsyncPayload = ::onAsyncPayload,
        onReaderEnded = {
            _status.update { it.copy(connected = false) }
        },
    )

    private val ops = TorControlOperations(
        transport = transport,
        refreshInfo = ::refreshInfo,
    )

    /** True while transport reader is open (post-[connect], pre-[disconnect]). */
    val isConnected: Boolean get() = transport.isOpen

    /**
     * Runs the sequential auth + subscription pipeline against [controlSocketPath] + cookie.
     *
     * @param bridgesConfigured when true, also try PT SETEVENTS (TRANSPORT_LAUNCHED / PT_*)
     * @throws IOException if socket/cookie missing or a required command fails
     */
    fun connect(
        controlSocketPath: File,
        cookieFile: File,
        bridgesConfigured: Boolean = false,
    ) {
        disconnect(sendShutdown = false)
        if (!cookieFile.exists() || cookieFile.length() == 0L) {
            throw IOException("Cookie file missing: ${cookieFile.absolutePath}")
        }
        val cookieHex = cookieFile.readBytes().joinToString("") { b ->
            "%02X".format(b.toInt() and 0xff)
        }
        transport.open(controlSocketPath)

        transport.command("AUTHENTICATE $cookieHex")
        runCatching { transport.command("TAKEOWNERSHIP") }
        runCatching { transport.command("RESETCONF __OwningControllerProcess") }
        // One feature per call — USEFEATURE is all-or-nothing on unknown names.
        runCatching { transport.command("USEFEATURE VERBOSE_NAMES") }
        runCatching { transport.command("USEFEATURE EXTENDED_EVENTS") }
        subscribeClientEvents(bridgesConfigured)
        refreshBootstrap()
        _status.update { it.copy(connected = true, lastError = null) }
        Timber.i(
            "Tor control connected (%s) bridges=%s",
            controlSocketPath.name,
            bridgesConfigured,
        )
    }

    /**
     * Incremental SETEVENTS: each successful tier becomes the new baseline.
     * If optional fails, PT is still attempted against core alone (not core+optional).
     */
    private fun subscribeClientEvents(bridgesConfigured: Boolean) {
        val core = TorControlCatalog.CLIENT_EVENTS
        transport.command("SETEVENTS $core")
        var active = core

        fun tryAdd(extra: String, label: String) {
            if (extra.isBlank()) return
            runCatching {
                transport.command("SETEVENTS $active $extra")
                active = "$active $extra"
            }.onFailure { err ->
                Timber.d(err, "SETEVENTS %s skipped (active=%s)", label, active)
            }
        }

        tryAdd(TorControlCatalog.CLIENT_EVENTS_OPTIONAL, "optional")
        if (bridgesConfigured) {
            tryAdd(TorControlCatalog.CLIENT_EVENTS_PT, "PT")
        }
    }

    /**
     * Closes the control channel.
     *
     * @param sendShutdown when true and connected, issues SIGNAL SHUTDOWN (TAKEOWNERSHIP exit)
     */
    fun disconnect(sendShutdown: Boolean = true) {
        if (sendShutdown && transport.isOpen) {
            runCatching { transport.command("SIGNAL SHUTDOWN") }
        }
        transport.closeQuietly()
        _status.value = TorControlStatus()
    }

    // --- ops passthrough (single surface for ProcessManager / future callers) ---

    fun signal(name: String): Result<Unit> = ops.signal(name)
    fun signal(signal: TorControlCatalog.Signal): Result<Unit> = ops.signal(signal)
    fun newNym(): Result<Unit> = ops.newNymRateLimited()
    fun clearDnsCache(): Result<Unit> = ops.clearDnsCache()
    fun setActive(): Result<Unit> = ops.setActive()
    fun setDormant(): Result<Unit> = ops.setDormant()
    fun reload(): Result<Unit> = ops.reload()
    fun heartbeat(): Result<Unit> = ops.heartbeat()
    fun dropGuards(): Result<Unit> = ops.dropGuards()
    fun dropTimeouts(): Result<Unit> = ops.dropTimeouts()
    fun setDisableNetwork(disabled: Boolean): Result<Unit> = ops.setDisableNetwork(disabled)
    fun setBridges(bridgeLines: List<String>): Result<Unit> = ops.setBridges(bridgeLines)
    fun setCircuitTiming(
        maxCircuitDirtinessSec: Int,
        newCircuitPeriodSec: Int,
    ): Result<Unit> = ops.setCircuitTiming(maxCircuitDirtinessSec, newCircuitPeriodSec)

    fun setGeoIpFiles(geoIpPath: String, geoIp6Path: String): Result<Unit> =
        ops.setGeoIpFiles(geoIpPath, geoIp6Path)

    suspend fun resolve(hostname: String, timeoutMs: Long = 15_000): Result<String> =
        runCatching { resolveViaAddrMap(hostname, timeoutMs) }

    /**
     * control-spec RESOLVE: answers arrive as ADDRMAP events (preferred), with
     * address-mappings/cache poll as fallback if the event was missed.
     */
    private suspend fun resolveViaAddrMap(hostname: String, timeoutMs: Long): String {
        val host = TorControlWire.requireHostname(hostname)
        return coroutineScope {
            val waiter = async(Dispatchers.Default) {
                events.first { ev ->
                    ev is TorControlEvent.AddrMap &&
                        ev.address.equals(host, ignoreCase = true)
                } as TorControlEvent.AddrMap
            }
            ops.sendResolve(host).getOrThrow()
            try {
                withTimeout(timeoutMs) {
                    val map = waiter.await()
                    if (map.newAddress.isBlank() || map.newAddress == "<error>") {
                        throw IOException("RESOLVE failed for $host")
                    }
                    map.newAddress
                }
            } catch (timeout: kotlinx.coroutines.TimeoutCancellationException) {
                waiter.cancel()
                ops.pollResolveMapping(host)
                    ?: throw IOException("RESOLVE timeout for $host")
            }
        }
    }

    fun extendNewCircuit(): Result<String> = ops.extendNewCircuit()
    fun closeCircuit(id: String, ifUnused: Boolean = true): Result<Unit> =
        ops.closeCircuit(id, ifUnused)
    fun closeStream(
        id: String,
        reason: String = TorControlCatalog.StreamEndReason.DONE,
    ): Result<Unit> =
        ops.closeStream(id, reason)
    fun listCircuits(): List<TorCircuitInfo> = ops.listCircuits()
    fun listStreams(): List<TorStreamInfo> = ops.listStreams()
    fun closeBuiltCircuits(): Result<Int> = ops.closeBuiltCircuits()
    fun getConf(vararg keys: String): Map<String, String> = ops.getConf(*keys)
    fun getInfo(key: String): String = ops.getInfo(key)
    fun getInfoMany(vararg keys: String): Map<String, String> = ops.getInfoMany(*keys)
    fun rawCommand(cmd: String): Result<List<String>> = ops.rawCommand(cmd)
    fun setNodePrefs(entry: String, exit: String, exclude: String): Result<Unit> =
        ops.setNodePrefs(entry, exit, exclude)

    /**
     * Bootstrap-only GETINFO (no dormant / network-liveness — those 552 on some builds
     * and used to abort every poll).
     */
    fun refreshBootstrap() {
        if (!transport.isOpen) return
        runCatching {
            val info = ops.getInfoMany(*TorControlCatalog.HEALTH_GETINFO_CORE.filter {
                it.startsWith("status/")
            }.toTypedArray())
            TorControlEventParser.parseBootstrapPhase(info["status/bootstrap-phase"].orEmpty())
                ?.let { b ->
                    _status.update {
                        it.copy(
                            bootstrapProgress = b.progress,
                            bootstrapTag = b.tag,
                            bootstrapSummary = b.summary,
                        )
                    }
                }
            _status.update {
                it.copy(
                    circuitEstablished = info["status/circuit-established"] == "1",
                    enoughDirInfo = info["status/enough-dir-info"] == "1",
                )
            }
        }.onFailure { err ->
            // Fall back to single-key probes so one bad key cannot stall bootstrap.
            runCatching {
                TorControlEventParser.parseBootstrapPhase(ops.getInfo("status/bootstrap-phase"))
                    ?.let { b ->
                        _status.update {
                            it.copy(
                                bootstrapProgress = b.progress,
                                bootstrapTag = b.tag,
                                bootstrapSummary = b.summary,
                            )
                        }
                    }
                _status.update {
                    it.copy(
                        circuitEstablished =
                            runCatching { ops.getInfo("status/circuit-established") }.getOrNull() == "1",
                        enoughDirInfo =
                            runCatching { ops.getInfo("status/enough-dir-info") }.getOrNull() == "1",
                    )
                }
            }.onFailure {
                Timber.w(err, "Tor bootstrap GETINFO failed")
                _status.update { it.copy(lastError = err.message) }
            }
        }
    }

    /**
     * Cheap bootstrap / health poll — one batched GETINFO, no circuit/stream dumps.
     */
    fun refreshInfo() {
        refreshHealth(includeTraffic = true, includeCircuits = false)
    }

    /**
     * Traffic counters only (`traffic/read` + `traffic/written`) — process-wide totals
     * across **all** circuits. Used by the aggregate bandwidth indicator.
     */
    fun refreshTraffic() {
        if (!transport.isOpen) return
        runCatching {
            val traffic = ops.getInfoMany(*TorControlCatalog.HEALTH_GETINFO_TRAFFIC.toTypedArray())
            val read = traffic["traffic/read"]?.toLongOrNull() ?: return
            val write = traffic["traffic/written"]?.toLongOrNull() ?: return
            _status.update {
                it.copy(readBytes = read, writeBytes = write)
            }
        }.onFailure { err ->
            Timber.d(err, "Tor traffic GETINFO failed")
        }
    }

    /**
     * Cheap health poll for network recovery / periodic keep-alive.
     */
    fun refreshHealthLite() {
        refreshHealth(includeTraffic = false, includeCircuits = false)
    }

    /**
     * Full status including circuit/stream counts (UI / rare ticks only).
     */
    fun refreshCircuits() {
        refreshHealth(includeTraffic = true, includeCircuits = true)
    }

    private fun refreshHealth(includeTraffic: Boolean, includeCircuits: Boolean) {
        if (!transport.isOpen) return
        runCatching {
            val info = ops.getInfoMany(*TorControlCatalog.HEALTH_GETINFO_CORE.toTypedArray())
            // Per-key optional — one 552 must not drop the other.
            val optional = buildMap {
                for (key in TorControlCatalog.HEALTH_GETINFO_OPTIONAL) {
                    runCatching { ops.getInfo(key) }.getOrNull()?.let { put(key, it) }
                }
            }
            val traffic = if (includeTraffic) {
                runCatching {
                    ops.getInfoMany(*TorControlCatalog.HEALTH_GETINFO_TRAFFIC.toTypedArray())
                }.getOrDefault(emptyMap())
            } else {
                emptyMap()
            }
            TorControlEventParser.parseBootstrapPhase(info["status/bootstrap-phase"].orEmpty())
                ?.let { b ->
                    _status.update {
                        it.copy(
                            bootstrapProgress = b.progress,
                            bootstrapTag = b.tag,
                            bootstrapSummary = b.summary,
                        )
                    }
                }
            val circEst = info["status/circuit-established"] == "1"
            val dirOk = info["status/enough-dir-info"] == "1"
            val dormant = (optional["dormant"]?.toIntOrNull() ?: 0) != 0
            val live = optional["network-liveness"].orEmpty().equals("up", ignoreCase = true)
            val read = if (includeTraffic) {
                traffic["traffic/read"]?.toLongOrNull() ?: _status.value.readBytes
            } else {
                _status.value.readBytes
            }
            val write = if (includeTraffic) {
                traffic["traffic/written"]?.toLongOrNull() ?: _status.value.writeBytes
            } else {
                _status.value.writeBytes
            }
            var built = _status.value.builtCircuits
            var streamCount = _status.value.streamCount
            var guards = _status.value.entryGuardsSummary
            if (includeCircuits) {
                for (key in TorControlCatalog.HEALTH_GETINFO_HEAVY) {
                    val body = runCatching { ops.getInfo(key) }.getOrDefault("")
                    when (key) {
                        "circuit-status" ->
                            built = body.lineSequence().count {
                                it.trim().split(' ').getOrNull(1) == "BUILT"
                            }
                        "stream-status" ->
                            streamCount = body.lineSequence().count { it.isNotBlank() }
                        "entry-guards" ->
                            guards = body.lineSequence()
                                .take(3)
                                .joinToString(" | ") { it.trim().take(48) }
                    }
                }
            }
            _status.update {
                it.copy(
                    torVersion = info["version"].orEmpty().take(40),
                    circuitEstablished = circEst,
                    enoughDirInfo = dirOk,
                    networkLive = live || circEst,
                    dormant = dormant,
                    readBytes = read,
                    writeBytes = write,
                    builtCircuits = built,
                    streamCount = streamCount,
                    entryGuardsSummary = guards,
                )
            }
        }.onFailure { err ->
            Timber.w(err, "Tor GETINFO refresh failed")
            _status.update { it.copy(lastError = err.message) }
        }
    }

    private fun onAsyncPayload(payload: String) {
        val parsed = TorControlEventParser.parseAsyncPayload(payload)
        _status.update(parsed.statusPatch)
        parsed.event?.let { _events.tryEmit(it) }
    }
}
