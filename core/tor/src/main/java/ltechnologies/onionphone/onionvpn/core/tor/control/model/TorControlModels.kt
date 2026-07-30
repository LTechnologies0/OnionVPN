package ltechnologies.onionphone.onionvpn.core.tor.control.model

/**
 * Package `control.model` — immutable control-plane state and async event types.
 *
 * Imported by: TorControlClient, TorControlHealth, TorControlEventFormatter, TorProcessManager,
 * and app UI / log collectors. No I/O.
 */

/**
 * Aggregated live Tor control-plane snapshot (GETINFO polls + 650 event side-effects).
 *
 * Exposed as [kotlinx.coroutines.flow.StateFlow] from
 * [ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient.status]
 * and mirrored into tunnel UI snapshots.
 */
data class TorControlStatus(
    /** True after AUTHENTICATE + SETEVENTS succeed and the reader thread is alive. */
    val connected: Boolean = false,
    /** Tor binary version string (truncated), from GETINFO version. */
    val torVersion: String = "",
    /** Bootstrap 0–100 from STATUS_CLIENT BOOTSTRAP / status/bootstrap-phase. */
    val bootstrapProgress: Int = 0,
    /** Bootstrap TAG= value (e.g. `done`, `handshake_dir`). */
    val bootstrapTag: String = "",
    /** Human SUMMARY= from bootstrap phase. */
    val bootstrapSummary: String = "",
    /** GETINFO status/circuit-established == 1. */
    val circuitEstablished: Boolean = false,
    /** GETINFO status/enough-dir-info == 1. */
    val enoughDirInfo: Boolean = false,
    /** GETINFO network-liveness equals "up". */
    val networkLive: Boolean = false,
    /** GETINFO dormant != 0 (SIGNAL DORMANT / idle). */
    val dormant: Boolean = false,
    /** Count of BUILT rows in circuit-status. */
    val builtCircuits: Int = 0,
    /** Soft counter of FAILED/CLOSED CIRC events since connect. */
    val failedCircuitsRecent: Int = 0,
    /** Non-blank rows in stream-status. */
    val streamCount: Int = 0,
    /** Soft counter of FAILED/CLOSED STREAM events since connect. */
    val failedStreamsRecent: Int = 0,
    /** Soft counter of ORCONN CONNECTED events since connect. */
    val orConnCount: Int = 0,
    /** Short preview of GETINFO entry-guards (first guards). */
    val entryGuardsSummary: String = "",
    /** Last CIRC / CIRC_MINOR status line for UI debug. */
    val lastCircEvent: String = "",
    /** Last STREAM status line for UI debug. */
    val lastStreamEvent: String = "",
    /** GETINFO traffic/read — cumulative bytes read by Tor (**all circuits**). */
    val readBytes: Long = 0L,
    /** GETINFO traffic/written — cumulative bytes written by Tor (**all circuits**). */
    val writeBytes: Long = 0L,
    /**
     * Last control-spec `BW` event read bytes/sec.
     * Process-wide (sum of all OR/circuit traffic), not a single circuit.
     */
    val lastBwReadPerSec: Long = 0L,
    /**
     * Last control-spec `BW` event written bytes/sec.
     * Process-wide (sum of all OR/circuit traffic), not a single circuit.
     */
    val lastBwWritePerSec: Long = 0L,
    /** Last control-plane error message, if any. */
    val lastError: String? = null,
    /**
     * Latest recovery hint from STREAM/CIRC/ORCONN REASON= catalogs
     * ([ltechnologies.onionphone.onionvpn.core.model.stability.StabilityAction] name).
     */
    val lastStabilityAction: String = "",
    /** Wire code that produced [lastStabilityAction] (e.g. NOROUTE, SOCKS_3). */
    val lastStabilityCode: String = "",
)

/**
 * Parsed asynchronous control events (650 lines after SETEVENTS).
 *
 * Emitted on [ltechnologies.onionphone.onionvpn.core.tor.control.TorControlClient.events].
 *
 * @see <a href="https://spec.torproject.org/control-spec/replies.html">asynchronous events</a>
 */
sealed interface TorControlEvent {
    /**
     * STATUS_* BOOTSTRAP progress.
     *
     * @property progress 0–100
     * @property tag Tor TAG=
     * @property summary Tor SUMMARY=
     * @property warning optional WARNING=
     * @property reason optional REASON=
     */
    data class Bootstrap(
        val progress: Int,
        val tag: String,
        val summary: String,
        val warning: String? = null,
        val reason: String? = null,
    ) : TorControlEvent

    /**
     * CIRC / CIRC_MINOR circuit lifecycle.
     *
     * @property id circuit id
     * @property status LAUNCHED/BUILT/FAILED/CLOSED/…
     * @property path hop path when present
     * @property reason REASON= on failure/close
     * @property purpose PURPOSE= when present
     * @property socksUsername SOCKS_USERNAME= isolation token
     * @property socksPassword SOCKS_PASSWORD= isolation token
     */
    data class Circuit(
        val id: String,
        val status: String,
        val path: String,
        val reason: String? = null,
        val purpose: String? = null,
        val socksUsername: String? = null,
        val socksPassword: String? = null,
    ) : TorControlEvent

    /**
     * STREAM application stream attached to a circuit.
     *
     * @property id stream id
     * @property status NEW/SENTCONNECT/SUCCEEDED/FAILED/CLOSED/…
     * @property circuitId owning circuit or 0
     * @property target destination host:port
     * @property reason REASON= on failure
     * @property socksUsername SOCKS_USERNAME= (IsolateSOCKSAuth key)
     * @property socksPassword SOCKS_PASSWORD=
     * @property clientProtocol CLIENT_PROTOCOL=
     * @property purpose PURPOSE=
     * @property sourceAddr SOURCE_ADDR=
     */
    data class Stream(
        val id: String,
        val status: String,
        val circuitId: String,
        val target: String,
        val reason: String? = null,
        val socksUsername: String? = null,
        val socksPassword: String? = null,
        val clientProtocol: String? = null,
        val purpose: String? = null,
        val sourceAddr: String? = null,
    ) : TorControlEvent

    /**
     * ORCONN relay OR connection status.
     *
     * @property target relay endpoint
     * @property status CONNECTED/FAILED/CLOSED/…
     * @property reason optional REASON=
     */
    data class OrConn(
        val target: String,
        val status: String,
        val reason: String? = null,
    ) : TorControlEvent

    /**
     * ADDRMAP DNS mapping (from RESOLVE or Automap).
     *
     * @property address queried name
     * @property newAddress mapped address
     * @property expiry expiry token / NEVER
     */
    data class AddrMap(
        val address: String,
        val newAddress: String,
        val expiry: String,
    ) : TorControlEvent

    /** BW read/written deltas for the last second. */
    data class Bandwidth(val read: Long, val written: Long) : TorControlEvent

    /**
     * NOTICE / WARN / ERR log lines mirrored on the control channel.
     *
     * @property severity NOTICE|WARN|ERR
     * @property line full payload
     */
    data class Notice(val severity: String, val line: String) : TorControlEvent

    /** GUARD entry-guard events. */
    data class Guard(val line: String) : TorControlEvent

    /** CONF_CHANGED after SETCONF. */
    data class ConfChanged(val line: String) : TorControlEvent

    /** SIGNAL event acknowledging a handled signal name. */
    data class SignalReceived(val name: String) : TorControlEvent

    /** BUILDTIMEOUT_SET circuit build timeout learning. */
    data class BuildTimeoutSet(val line: String) : TorControlEvent

    /** TRANSPORT_LAUNCHED / PT_* pluggable-transport lines. */
    data class TransportLaunched(val line: String) : TorControlEvent
}
