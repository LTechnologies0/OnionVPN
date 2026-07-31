package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.TorEngine

/**
 * Doc-backed little-t Tor ↔ Arti parity matrix for every ControlPort / Tor op
 * OnionVPN uses.
 *
 * Sources compared:
 * - Tor control-spec SIGNAL / SETCONF / GETINFO / CIRCUIT / RESOLVE
 *   (https://spec.torproject.org/control-spec/commands.html)
 * - Tor Project: Arti RPC replaces ControlPort but only supports connect /
 *   bootstrap / open streams today (Arti 1.4.0 blog)
 * - Guardian Project `arti-mobile` 1.7.0.1 JNI surface:
 *   `startArtiProxyJNI(cache, state, obfs4, snowflake, ptPath, bridges, socks, dns)`
 *   + `stopArtiProxyJNI()` — no ControlSocket, no RPC port, no SETCONF
 * - Arti `TorClientConfig` has `circuit_timing.max_dirtiness` and bridges config
 *   in-process, but arti-mobile does not expose reconfigure / TOML knobs for
 *   ExitNodes / MaxCircuitDirtiness / CIRC events
 *
 * **1:1 policy:** every little-t op maps to the closest Arti-capable behaviour
 * that preserves VPN semantics. Ops that cannot be implemented with the
 * published arti-mobile API are [Parity.ENGINE_LIMITATION] and must be UI-gated
 * via [ltechnologies.onionphone.onionvpn.core.model.TorEngineCapabilities].
 */
object TorControlCompat {

    /**
     * How close the Arti path is to little-t for the same user-facing intent.
     */
    enum class Parity {
        /** Same user-visible outcome (e.g. NEWNYM → runtime restart). */
        SEMANTIC_1_1,
        /** Outcome achieved at the app layer (DNSPort resolve, Automap synth, UID TrafficStats). */
        APP_LAYER_1_1,
        /** Safe no-op that preserves VPN semantics under Blocking TUN / shared SOCKS. */
        NOOP_OK,
        /** Soft recovery (listener re-probe / app DNS cache clear). */
        SOFT_RECOVER,
        /** Hard recovery (full Arti restart). */
        HARD_RECOVER,
        /** Applied only by restarting the tunnel/runtime with new prefs. */
        REQUIRES_RESTART,
        /** Not available in arti-mobile / Arti RPC yet — must fail closed + UI gate. */
        ENGINE_LIMITATION,
    }

    /** Runtime behaviour bucket used by [TorProcessManager] wrappers. */
    enum class ArtiBehavior {
        EQUIVALENT,
        NOOP_OK,
        SOFT_RECOVER,
        HARD_RECOVER,
        REQUIRES_RESTART,
        UNSUPPORTED,
    }

    data class Op(
        val name: String,
        val wire: String,
        val littleT: String,
        val arti: ArtiBehavior,
        val parity: Parity,
        val artiImpl: String,
        val docs: String,
    )

    /**
     * Complete inventory of ControlPort / Tor ops OnionVPN exercises.
     * Keep in sync with [ltechnologies.onionphone.onionvpn.core.tor.control.ops.TorControlOperations]
     * and [ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager] public API.
     */
    val OPS: List<Op> = listOf(
        Op(
            name = "NEWNYM",
            wire = "SIGNAL NEWNYM",
            littleT = "Clean circuits; new streams get fresh paths; clears client DNS cache",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiRuntime.restartForNewIdentity() + clear app DNS/Automap caches",
            docs = "control-spec SIGNAL NEWNYM; Arti has no NEWNYM — isolated client / restart is the VPN equivalent",
        ),
        Op(
            name = "CLEARDNSCACHE",
            wire = "SIGNAL CLEARDNSCACHE",
            littleT = "Forget client-side cached IPs for hostnames",
            arti = ArtiBehavior.SOFT_RECOVER,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "Clear DnsHostnameCache + OnionAutomapAllocator; re-probe SOCKS/DNS",
            docs = "control-spec CLEARDNSCACHE; arti-mobile has no SIGNAL — app-layer cache is the Automap store",
        ),
        Op(
            name = "ACTIVE",
            wire = "SIGNAL ACTIVE",
            littleT = "Leave dormant mode; resume activity",
            arti = ArtiBehavior.NOOP_OK,
            parity = Parity.NOOP_OK,
            artiImpl = "No-op: arti-mobile has no dormant mode; listeners stay up under Blocking TUN",
            docs = "control-spec ACTIVE; Arti client stays running while process lives",
        ),
        Op(
            name = "DORMANT",
            wire = "SIGNAL DORMANT",
            littleT = "Become dormant (reduce background network use)",
            arti = ArtiBehavior.NOOP_OK,
            parity = Parity.NOOP_OK,
            artiImpl = "No-op: keep Arti running so kill-switch recovery can reattach without cold bootstrap",
            docs = "control-spec DORMANT; arti-mobile JNI has no dormant API",
        ),
        Op(
            name = "RELOAD",
            wire = "SIGNAL RELOAD / HUP",
            littleT = "Reload config files",
            arti = ArtiBehavior.HARD_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiRuntime.restartHard() with last ports/prefs (bridges re-applied via JNI)",
            docs = "control-spec RELOAD; Arti reload_cfg exists in-tree but arti-mobile exposes only stop/start",
        ),
        Op(
            name = "SHUTDOWN",
            wire = "SIGNAL SHUTDOWN",
            littleT = "Clean shutdown of Tor process",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiMobileNative.stop() / ArtiRuntime.stop()",
            docs = "control-spec SHUTDOWN; arti-mobile stopArtiProxyJNI",
        ),
        Op(
            name = "HEARTBEAT",
            wire = "SIGNAL HEARTBEAT",
            littleT = "Force a heartbeat log line",
            arti = ArtiBehavior.NOOP_OK,
            parity = Parity.NOOP_OK,
            artiImpl = "No-op success (no control log channel)",
            docs = "control-spec HEARTBEAT; informational only",
        ),
        Op(
            name = "DROPTIMEOUTS",
            wire = "DROPTIMEOUTS",
            littleT = "Drop circuits that timed out building; soft network recover",
            arti = ArtiBehavior.SOFT_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Re-probe SOCKS/DNS listeners (soft network recovery)",
            docs = "control-spec DROPTIMEOUTS; Arti has no circuit-timeout command — soft recover is VPN equivalent",
        ),
        Op(
            name = "DROPGUARDS",
            wire = "DROPGUARDS",
            littleT = "Forget entry guards; rebuild guard set",
            arti = ArtiBehavior.HARD_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Full Arti restart (clears in-memory client / circuit state)",
            docs = "control-spec DROPGUARDS; arti-mobile has no DROPGUARDS — hard restart is closest",
        ),
        Op(
            name = "DisableNetwork",
            wire = "SETCONF DisableNetwork",
            littleT = "Pause/resume Tor networking without process exit",
            arti = ArtiBehavior.HARD_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "disabled→stop(); enabled→restartHard()",
            docs = "torrc DisableNetwork; arti-mobile has no DisableNetwork — stop/start mirrors it",
        ),
        Op(
            name = "SETCONF_circuit_timing",
            wire = "SETCONF MaxCircuitDirtiness/NewCircuitPeriod",
            littleT = "Live circuit dirtiness / new-circuit period",
            arti = ArtiBehavior.NOOP_OK,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "Prefs persisted; arti-mobile JNI does not expose circuit_timing.max_dirtiness",
            docs = "Arti TorClientConfig.circuit_timing.max_dirtiness exists, but not via arti-mobile start API",
        ),
        Op(
            name = "SETCONF_bridges",
            wire = "SETCONF UseBridges/Bridge",
            littleT = "Live bridge lines without full process restart",
            arti = ArtiBehavior.REQUIRES_RESTART,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Restart Arti with new bridgeLines (+ managed Lyrebird path) via JNI",
            docs = "arti-mobile startArtiProxyJNI(bridgeLines); live SETCONF unsupported — restart is 1:1 apply",
        ),
        Op(
            name = "SETCONF_nodes",
            wire = "SETCONF Entry/Exit/ExcludeNodes",
            littleT = "Live path constraints (StrictNodes)",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "Not in arti-mobile API (StreamPrefs.exit_country is Rust-only / geoip feature)",
            docs = "Arti StreamPrefs.exit_country requires geoip + embedding API; JNI has no node prefs",
        ),
        Op(
            name = "SETCONF_geoip",
            wire = "SETCONF GeoIPFile",
            littleT = "Point Tor at GeoIP DBs for ip-to-country",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "No circuit country UI / GETINFO ip-to-country on Arti path",
            docs = "GeoIP circuit UI needs classic control plane",
        ),
        Op(
            name = "GETINFO_bootstrap",
            wire = "GETINFO status/bootstrap-phase",
            littleT = "Bootstrap progress / tags",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "Synthetic TorControlStatus from SOCKS+DNS listener readiness",
            docs = "Arti RPC get_client_status is the desktop equivalent; mobile uses listener probe",
        ),
        Op(
            name = "GETINFO_circuits",
            wire = "GETINFO circuit-status",
            littleT = "List circuits + CIRC events",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "Empty list / UI gated (circuitInspection=false)",
            docs = "Arti RPC does not yet expose circuit-status (Tor Project forum / RPC roadmap)",
        ),
        Op(
            name = "GETINFO_streams",
            wire = "GETINFO stream-status",
            littleT = "List streams + STREAM events",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "Empty list / UI gated",
            docs = "Same as circuits — not in Arti RPC mobile surface",
        ),
        Op(
            name = "GETINFO_traffic",
            wire = "GETINFO traffic/read|written",
            littleT = "Process-wide Tor byte counters",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "UID TrafficStats via TorBandwidthSampler (TunnelThroughputTracker)",
            docs = "No traffic GETINFO without control plane; Android TrafficStats is the VPN equivalent",
        ),
        Op(
            name = "EXTENDCIRCUIT",
            wire = "EXTENDCIRCUIT 0",
            littleT = "Build a new circuit on demand",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "UI gated; Arti builds circuits on demand for SOCKS streams",
            docs = "Arti intentionally avoids controller-driven circuit management (forum API sketch)",
        ),
        Op(
            name = "CLOSECIRCUIT",
            wire = "CLOSECIRCUIT",
            littleT = "Close a specific circuit",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "UI gated; use NEWNYM to drop all circuits",
            docs = "No circuit handles in arti-mobile",
        ),
        Op(
            name = "CLOSESTREAM",
            wire = "CLOSESTREAM",
            littleT = "Close a specific stream",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "UI gated",
            docs = "No stream handles in arti-mobile",
        ),
        Op(
            name = "RESOLVE",
            wire = "RESOLVE + ADDRMAP",
            littleT = "Ask Tor to resolve a hostname over the network",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "UDP DNS A query to Arti DNSPort (same network resolve path)",
            docs = "control-spec RESOLVE; Arti DNSPort performs resolve_with_prefs equivalent",
        ),
        Op(
            name = "SETEVENTS",
            wire = "SETEVENTS",
            littleT = "Async CIRC/STREAM/BW/STATUS events",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "No event channel",
            docs = "Arti RPC watch_client_status is desktop-only; not in arti-mobile",
        ),
        Op(
            name = "AUTHENTICATE",
            wire = "AUTHENTICATE",
            littleT = "Cookie / password control auth",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "No ControlSocket",
            docs = "In-process JNI; no control auth surface",
        ),
        Op(
            name = "CLOSE_BUILT_CIRCUITS",
            wire = "CLOSECIRCUIT (all BUILT)",
            littleT = "Tear down built circuits so next streams rebuild",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Same as NEWNYM — restartForNewIdentity()",
            docs = "Closing all built circuits ≈ clean circuit set; Arti restart is the available tool",
        ),
    )

    fun behavior(opName: String): ArtiBehavior =
        OPS.firstOrNull { it.name.equals(opName, ignoreCase = true) }?.arti
            ?: ArtiBehavior.UNSUPPORTED

    fun parity(opName: String): Parity =
        OPS.firstOrNull { it.name.equals(opName, ignoreCase = true) }?.parity
            ?: Parity.ENGINE_LIMITATION

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

    /** Ops that are semantic or app-layer 1:1 on Arti (including soft/hard recover). */
    fun isOneToOneOnArti(opName: String): Boolean =
        when (parity(opName)) {
            Parity.SEMANTIC_1_1,
            Parity.APP_LAYER_1_1,
            Parity.NOOP_OK,
            Parity.SOFT_RECOVER,
            Parity.HARD_RECOVER,
            Parity.REQUIRES_RESTART,
            -> true
            Parity.ENGINE_LIMITATION -> false
        }

    fun unsupportedMessage(opName: String): String =
        "ControlPort op '$opName' is not available on Arti (arti-mobile has no ControlSocket/RPC) — use C Tor or NEWNYM/restart"
}
