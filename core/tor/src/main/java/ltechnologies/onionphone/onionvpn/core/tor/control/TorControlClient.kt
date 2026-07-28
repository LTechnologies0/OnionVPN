package ltechnologies.onionphone.onionvpn.core.tor.control

import java.io.File
import java.io.IOException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import ltechnologies.onionphone.onionvpn.core.tor.control.catalog.TorControlCatalog
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent
import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlStatus
import ltechnologies.onionphone.onionvpn.core.tor.control.ops.TorControlOperations
import ltechnologies.onionphone.onionvpn.core.tor.control.protocol.TorControlEventParser
import ltechnologies.onionphone.onionvpn.core.tor.control.transport.TorControlTransport
import timber.log.Timber

/**
 * Package `control` — public façade over transport + protocol + ops.
 *
 * Sequential connect pipeline (control-spec):
 * 1. Open ControlSocket (transport)
 * 2. AUTHENTICATE (cookie hex)
 * 3. TAKEOWNERSHIP + RESETCONF __OwningControllerProcess
 * 4. USEFEATURE VERBOSE_NAMES EXTENDED_EVENTS
 * 5. SETEVENTS client set (fallback if rejected)
 * 6. refreshInfo (GETINFO health keys)
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
     * @throws IOException if socket/cookie missing or a required command fails
     */
    fun connect(controlSocketPath: File, cookieFile: File) {
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
        runCatching { transport.command("USEFEATURE VERBOSE_NAMES EXTENDED_EVENTS") }
        subscribeClientEvents()
        refreshInfo()
        _status.update { it.copy(connected = true, lastError = null) }
        Timber.i("Tor control connected (%s)", controlSocketPath.name)
    }

    private fun subscribeClientEvents() {
        try {
            transport.command("SETEVENTS ${TorControlCatalog.CLIENT_EVENTS}")
        } catch (error: Exception) {
            Timber.w(error, "SETEVENTS full client set failed — falling back")
            transport.command(
                "SETEVENTS STATUS_CLIENT CIRC CIRC_MINOR STREAM ORCONN BW " +
                    "ADDRMAP NOTICE WARN ERR GUARD BUILDTIMEOUT_SET SIGNAL CONF_CHANGED",
            )
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
    fun newNym(): Result<Unit> = ops.newNym()
    fun clearDnsCache(): Result<Unit> = ops.clearDnsCache()
    fun setActive(): Result<Unit> = ops.setActive()
    fun setDormant(): Result<Unit> = ops.setDormant()
    fun reload(): Result<Unit> = ops.reload()
    fun heartbeat(): Result<Unit> = ops.heartbeat()
    fun dropGuards(): Result<Unit> = ops.dropGuards()
    fun dropTimeouts(): Result<Unit> = ops.dropTimeouts()
    fun setDisableNetwork(disabled: Boolean): Result<Unit> = ops.setDisableNetwork(disabled)
    fun setBridges(bridgeLines: List<String>): Result<Unit> = ops.setBridges(bridgeLines)
    fun resolve(hostname: String, timeoutMs: Long = 15_000): Result<String> =
        ops.resolve(hostname, timeoutMs)
    fun extendNewCircuit(): Result<String> = ops.extendNewCircuit()
    fun closeBuiltCircuits(): Result<Int> = ops.closeBuiltCircuits()
    fun getConf(vararg keys: String): Map<String, String> = ops.getConf(*keys)
    fun getInfo(key: String): String = ops.getInfo(key)
    fun getInfoMany(vararg keys: String): Map<String, String> = ops.getInfoMany(*keys)
    fun rawCommand(cmd: String): Result<List<String>> = ops.rawCommand(cmd)
    fun setNodePrefs(entry: String, exit: String, exclude: String): Result<Unit> =
        ops.setNodePrefs(entry, exit, exclude)

    /**
     * Cheap bootstrap / health poll — one batched GETINFO, no circuit/stream dumps.
     */
    fun refreshInfo() {
        refreshHealth(includeTraffic = true, includeCircuits = false)
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
            val keys = buildList {
                add("version")
                add("status/bootstrap-phase")
                add("status/circuit-established")
                add("status/enough-dir-info")
                add("dormant")
                add("network-liveness")
                if (includeTraffic) {
                    add("traffic/read")
                    add("traffic/written")
                }
            }
            val info = ops.getInfoMany(*keys.toTypedArray())
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
            val dormant = (info["dormant"]?.toIntOrNull() ?: 0) != 0
            val live = info["network-liveness"].orEmpty().equals("up", ignoreCase = true)
            val read = if (includeTraffic) {
                info["traffic/read"]?.toLongOrNull() ?: 0L
            } else {
                _status.value.readBytes
            }
            val write = if (includeTraffic) {
                info["traffic/written"]?.toLongOrNull() ?: 0L
            } else {
                _status.value.writeBytes
            }
            var built = _status.value.builtCircuits
            var streamCount = _status.value.streamCount
            var guards = _status.value.entryGuardsSummary
            if (includeCircuits) {
                val circBody = ops.getInfo("circuit-status")
                built = circBody.lineSequence().count {
                    it.trim().split(' ').getOrNull(1) == "BUILT"
                }
                val streams = runCatching { ops.getInfo("stream-status") }.getOrDefault("")
                streamCount = streams.lineSequence().count { it.isNotBlank() }
                guards = runCatching { ops.getInfo("entry-guards") }.getOrDefault("")
                    .lineSequence()
                    .take(3)
                    .joinToString(" | ") { it.trim().take(48) }
            }
            _status.update {
                it.copy(
                    torVersion = info["version"].orEmpty().take(40),
                    circuitEstablished = circEst,
                    enoughDirInfo = dirOk,
                    networkLive = live,
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
