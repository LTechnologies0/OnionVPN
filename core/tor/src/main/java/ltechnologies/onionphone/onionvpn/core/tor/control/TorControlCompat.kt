package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.TorEngine

/**
 * Control-spec → engine compatibility matrix.
 *
 * Arti (arti-mobile) has **no classic ControlSocket**. Every SIGNAL / SETCONF / GETINFO /
 * CIRCUIT op must either map to an Arti equivalent or be a documented no-op / unsupported.
 *
 * Call sites must go through [ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager]
 * (never raw [TorControlClient] from the app) so Arti paths stay consistent.
 */
object TorControlCompat {

    enum class ArtiBehavior {
        /** Full equivalent exists (e.g. NEWNYM → runtime restart). */
        EQUIVALENT,
        /** Safe no-op that preserves VPN semantics (ACTIVE/DORMANT while listeners stay up). */
        NOOP_OK,
        /** Soft recovery that re-probes SOCKS/DNS (DROPTIMEOUTS / CLEARDNSCACHE family). */
        SOFT_RECOVER,
        /** Hard recovery that restarts Arti (DisableNetwork bounce family). */
        HARD_RECOVER,
        /** Requires tunnel restart with new prefs (live SETCONF bridges / nodes). */
        REQUIRES_RESTART,
        /** Not available — UI must be gated; returns failure if invoked. */
        UNSUPPORTED,
    }

    data class Op(
        val name: String,
        val wire: String,
        val arti: ArtiBehavior,
        val notes: String,
    )

    /** All control-plane ops OnionVPN uses (or may call via TorProcessManager). */
    val OPS: List<Op> = listOf(
        Op("NEWNYM", "SIGNAL NEWNYM", ArtiBehavior.EQUIVALENT, "Arti: restart runtime (new circuits)"),
        Op("CLEARDNSCACHE", "SIGNAL CLEARDNSCACHE", ArtiBehavior.SOFT_RECOVER, "Arti: re-probe listeners"),
        Op("ACTIVE", "SIGNAL ACTIVE", ArtiBehavior.NOOP_OK, "Arti has no dormant mode"),
        Op("DORMANT", "SIGNAL DORMANT", ArtiBehavior.NOOP_OK, "Arti stays running under Blocking TUN"),
        Op("RELOAD", "SIGNAL RELOAD", ArtiBehavior.REQUIRES_RESTART, "Restart tunnel / Arti"),
        Op("SHUTDOWN", "SIGNAL SHUTDOWN", ArtiBehavior.EQUIVALENT, "Arti: stop JNI runtime"),
        Op("HEARTBEAT", "SIGNAL HEARTBEAT", ArtiBehavior.NOOP_OK, "No control log channel"),
        Op("DROPTIMEOUTS", "DROPTIMEOUTS", ArtiBehavior.SOFT_RECOVER, "Arti: soft network recovery"),
        Op("DROPGUARDS", "DROPGUARDS", ArtiBehavior.HARD_RECOVER, "Arti: hard restart clears state"),
        Op("DisableNetwork", "SETCONF DisableNetwork", ArtiBehavior.HARD_RECOVER, "Arti: hard restart"),
        Op("SETCONF_circuit_timing", "SETCONF MaxCircuitDirtiness/NewCircuitPeriod", ArtiBehavior.NOOP_OK, "Prefs persisted; no live Arti knobs yet"),
        Op("SETCONF_bridges", "SETCONF UseBridges/Bridge", ArtiBehavior.REQUIRES_RESTART, "Restart tunnel with bridges"),
        Op("SETCONF_nodes", "SETCONF Entry/Exit/ExcludeNodes", ArtiBehavior.REQUIRES_RESTART, "Not wired into arti-mobile yet"),
        Op("SETCONF_geoip", "SETCONF GeoIPFile", ArtiBehavior.UNSUPPORTED, "No circuit country UI on Arti"),
        Op("GETINFO_bootstrap", "GETINFO status/bootstrap-phase", ArtiBehavior.EQUIVALENT, "Synthetic status from SOCKS/DNS ready"),
        Op("GETINFO_circuits", "GETINFO circuit-status", ArtiBehavior.UNSUPPORTED, "No CIRC events"),
        Op("GETINFO_streams", "GETINFO stream-status", ArtiBehavior.UNSUPPORTED, "No STREAM events"),
        Op("GETINFO_traffic", "GETINFO traffic/read|written", ArtiBehavior.UNSUPPORTED, "Use UID TrafficStats fallback"),
        Op("EXTENDCIRCUIT", "EXTENDCIRCUIT 0", ArtiBehavior.UNSUPPORTED, "Circuits UI gated"),
        Op("CLOSECIRCUIT", "CLOSECIRCUIT", ArtiBehavior.UNSUPPORTED, "Circuits UI gated"),
        Op("CLOSESTREAM", "CLOSESTREAM", ArtiBehavior.UNSUPPORTED, "Circuits UI gated"),
        Op("RESOLVE", "RESOLVE", ArtiBehavior.UNSUPPORTED, "Use SOCKS5A / DNSPort instead"),
        Op("SETEVENTS", "SETEVENTS", ArtiBehavior.UNSUPPORTED, "No async control events"),
        Op("AUTHENTICATE", "AUTHENTICATE", ArtiBehavior.UNSUPPORTED, "No ControlSocket"),
    )

    fun behavior(opName: String): ArtiBehavior =
        OPS.firstOrNull { it.name.equals(opName, ignoreCase = true) }?.arti
            ?: ArtiBehavior.UNSUPPORTED

    fun isSupported(engine: TorEngine, opName: String): Boolean {
        if (engine == TorEngine.LITTLE_T) return true
        return when (behavior(opName)) {
            ArtiBehavior.EQUIVALENT,
            ArtiBehavior.NOOP_OK,
            ArtiBehavior.SOFT_RECOVER,
            ArtiBehavior.HARD_RECOVER,
            ArtiBehavior.REQUIRES_RESTART,
            -> true
            ArtiBehavior.UNSUPPORTED -> false
        }
    }

    fun unsupportedMessage(opName: String): String =
        "ControlPort op '$opName' is not available on Arti — use C Tor or restart tunnel"
}
