package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.tor.control.model.TorControlEvent

/**
 * Formats [TorControlEvent] for log buffers / UI (no I/O).
 *
 * Imported by [ltechnologies.onionphone.onionvpn.OnionVpnApplication] when collecting
 * [TorControlClient.events]. Prefer skipping [TorControlEvent.Bandwidth] at the sink.
 */
object TorControlEventFormatter {
    /** One-line CTRL … representation of [event]. */
    fun format(event: TorControlEvent): String = when (event) {
        is TorControlEvent.Bootstrap ->
            "CTRL BOOTSTRAP ${event.progress}% ${event.tag} ${event.summary}"
        is TorControlEvent.Circuit ->
            "CTRL CIRC ${event.status} ${event.id} ${event.path} ${event.reason.orEmpty()}".trim()
        is TorControlEvent.Stream ->
            "CTRL STREAM ${event.status} ${event.target} circ=${event.circuitId}"
        is TorControlEvent.OrConn ->
            "CTRL ORCONN ${event.status} ${event.target}"
        is TorControlEvent.AddrMap ->
            "CTRL ADDRMAP ${event.address} → ${event.newAddress}"
        is TorControlEvent.Bandwidth ->
            "CTRL BW r=${event.read} w=${event.written}"
        is TorControlEvent.Notice ->
            "CTRL ${event.severity} ${event.line}"
        is TorControlEvent.Guard ->
            "CTRL ${event.line}"
        is TorControlEvent.ConfChanged ->
            "CTRL ${event.line}"
        is TorControlEvent.SignalReceived ->
            "CTRL SIGNAL ${event.name}"
        is TorControlEvent.BuildTimeoutSet ->
            "CTRL ${event.line}"
        is TorControlEvent.TransportLaunched ->
            "CTRL ${event.line}"
    }
}
