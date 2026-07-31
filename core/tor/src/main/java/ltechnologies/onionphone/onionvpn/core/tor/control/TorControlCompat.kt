package ltechnologies.onionphone.onionvpn.core.tor.control

import ltechnologies.onionphone.onionvpn.core.model.TorEngine

/**
 * Doc-backed little-t Tor ↔ Arti parity matrix for every ControlPort / Tor op
 * OnionVPN uses.
 *
 * ## Sources (read in full)
 * - Tor control-spec: https://spec.torproject.org/control-spec/commands.html
 * - **arti-client 0.36.0** (all 122 pages): https://docs.rs/arti-client/0.36.0/arti_client/
 *   — this is the crate version embedded in Guardian `arti-mobile` 1.7.0.1
 *   (`libarti_mobile_ex.so` strings: `arti-client-0.36.0` / `arti-1.7.0`)
 * - arti-mobile-ex JNI (`common/src/android.rs` + `lib.rs`): stock AAR only has
 *   `startArtiProxyJNI` + `stopArtiProxyJNI`. OnionVPN ships a patched
 *   `libarti_mobile_ex.so` (see `native/arti-mobile-ex/`) that also exports
 *   `ArtiControlNative` — `setDormant` / `applyMaxDirtiness` / `bootstrapFraction`.
 *   When the Ext API is absent, app-layer fallbacks remain.
 *
 * ## arti-client 0.36.0 APIs that map to little-t (Rust / RPC)
 * | little-t | arti-client 0.36.0 |
 * |---|---|
 * | SIGNAL NEWNYM (per-app isolation) | `TorClient::isolated_client` / `StreamPrefs::new_isolation_group` |
 * | SIGNAL NEWNYM (VPN-wide) | full runtime restart (stronger; invalidates all streams) |
 * | SIGNAL DORMANT / ACTIVE | `TorClient::set_dormant(DormantMode::Soft\|Normal)` |
 * | RESOLVE | `TorClient::resolve` / `resolve_with_prefs` |
 * | bootstrap GETINFO | `bootstrap_status()` → `as_frac` / `ready_for_traffic` / `blocked` |
 * | MaxCircuitDirtiness | `CircuitTimingBuilder::max_dirtiness` (live via `reconfigure`) |
 * | NewCircuitPeriod | `PreemptiveCircuitConfig::prediction_lifetime` (semantic analogue) |
 * | ExitNodes country | `StreamPrefs::exit_country` (geoip; SOCKS via OnionVPN patch) |
 * | Bridges / PT | `config::BridgesConfig` + `pt::TransportConfig` (incl. Conjure) |
 * | IsolateSOCKSAuth | SOCKS username → `StreamIsolation` / IsolationToken |
 *
 * ## JNI gap (stock AAR) vs OnionVPN patch
 * Stock Guardian AAR does not export set_dormant / reconfigure / bootstrap_status.
 * OnionVPN's patched `libarti_mobile_ex.so` (control-api≥2) closes dormant, max_dirtiness,
 * prediction_lifetime, exit_country, resolve, and bootstrap blockage. Remaining
 * ENGINE_LIMITATION: CIRC/STREAM UI, Entry/ExcludeNodes, AUTHENTICATE.
 */
object TorControlCompat {

    /** arti-client crate version embedded in our arti-mobile AAR. */
    const val ARTI_CLIENT_DOCS_VERSION = "0.36.0"
    const val ARTI_CLIENT_DOCS_URL = "https://docs.rs/arti-client/0.36.0/arti_client/"

    /**
     * How close the Arti path is to little-t for the same user-facing intent.
     */
    enum class Parity {
        /** Same user-visible outcome (e.g. NEWNYM → runtime restart). */
        SEMANTIC_1_1,
        /** Outcome achieved at the app layer (DNSPort resolve, Automap synth, UID TrafficStats). */
        APP_LAYER_1_1,
        /** Safe no-op / status-only that preserves VPN semantics under Blocking TUN. */
        NOOP_OK,
        /** Soft recovery (listener re-probe / app DNS cache clear). */
        SOFT_RECOVER,
        /** Hard recovery (full Arti restart). */
        HARD_RECOVER,
        /** Applied only by restarting the tunnel/runtime with new prefs. */
        REQUIRES_RESTART,
        /** Not available via arti-mobile JNI — fail closed + UI gate. */
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
            docs = "arti-client $ARTI_CLIENT_DOCS_VERSION TorClient::isolated_client is the per-handle " +
                "NEWNYM analogue; VPN-wide identity requires restart (stronger than isolated_client)",
        ),
        Op(
            name = "CLEARDNSCACHE",
            wire = "SIGNAL CLEARDNSCACHE",
            littleT = "Forget client-side cached IPs for hostnames",
            arti = ArtiBehavior.SOFT_RECOVER,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "Clear DnsHostnameCache + OnionAutomapAllocator; re-probe SOCKS/DNS",
            docs = "No TorClient::clear_dns_cache in 0.36.0; app Automap store is the client DNS cache on Arti",
        ),
        Op(
            name = "ACTIVE",
            wire = "SIGNAL ACTIVE",
            littleT = "Leave dormant mode; resume activity",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiControlNative.setDormant(false) → TorClient::set_dormant(Normal); " +
                "fallback: clear synthetic dormant flag",
            docs = "arti-client 0.36.0 DormantMode::Normal via OnionVPN Ext JNI (control-api≥1)",
        ),
        Op(
            name = "DORMANT",
            wire = "SIGNAL DORMANT",
            littleT = "Become dormant (reduce background network use)",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiControlNative.setDormant(true) → TorClient::set_dormant(Soft); " +
                "fallback: synthetic dormant=true; runtime kept under Blocking TUN",
            docs = "arti-client 0.36.0 set_dormant(DormantMode::Soft) via OnionVPN Ext JNI",
        ),
        Op(
            name = "RELOAD",
            wire = "SIGNAL RELOAD / HUP",
            littleT = "Reload config files",
            arti = ArtiBehavior.HARD_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiRuntime.restartHard() with last ports/prefs (bridges re-applied via JNI)",
            docs = "arti-client 0.36.0 TorClient::reconfigure + config::Reconfigure; " +
                "arti-mobile uses ConfigurationSources::default() (empty) so restart is the apply path",
        ),
        Op(
            name = "SHUTDOWN",
            wire = "SIGNAL SHUTDOWN",
            littleT = "Clean shutdown of Tor process",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiMobileNative.stop() / ArtiRuntime.stop() (TorClient::wait_for_stop analogue)",
            docs = "arti-client 0.36.0 wait_for_stop; arti-mobile stopArtiProxyJNI",
        ),
        Op(
            name = "HEARTBEAT",
            wire = "SIGNAL HEARTBEAT",
            littleT = "Force a heartbeat log line",
            arti = ArtiBehavior.NOOP_OK,
            parity = Parity.NOOP_OK,
            artiImpl = "No-op success (no control log channel / no TorClient heartbeat API)",
            docs = "control-spec HEARTBEAT; not present in arti-client 0.36.0 public API",
        ),
        Op(
            name = "DROPTIMEOUTS",
            wire = "DROPTIMEOUTS",
            littleT = "Drop circuits that timed out building; soft network recover",
            arti = ArtiBehavior.SOFT_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Re-probe SOCKS/DNS listeners (soft network recovery)",
            docs = "No DROPTIMEOUTS in arti-client 0.36.0; soft listener recover is VPN equivalent",
        ),
        Op(
            name = "DROPGUARDS",
            wire = "DROPGUARDS",
            littleT = "Forget entry guards; rebuild guard set",
            arti = ArtiBehavior.HARD_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Full Arti restart (clears in-memory client / circuit / guard state)",
            docs = "No DROPGUARDS in arti-client 0.36.0 public API; hard restart clears client state",
        ),
        Op(
            name = "DisableNetwork",
            wire = "SETCONF DisableNetwork",
            littleT = "Pause/resume Tor networking without process exit",
            arti = ArtiBehavior.HARD_RECOVER,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "disabled→stop(); enabled→restartHard()",
            docs = "No DisableNetwork in arti-client 0.36.0; stop/start mirrors network pause",
        ),
        Op(
            name = "SETCONF_circuit_timing",
            wire = "SETCONF MaxCircuitDirtiness/NewCircuitPeriod",
            littleT = "Live circuit dirtiness / new-circuit period",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiControlNative.applyCircuitTiming → CircuitTimingBuilder::max_dirtiness " +
                "+ PreemptiveCircuitConfig::prediction_lifetime via reconfigure; " +
                "also written to state_dir/onionvpn_circuit_timing for start-time apply",
            docs = "arti-client 0.36.0 max_dirtiness (= MaxCircuitDirtiness). " +
                "prediction_lifetime is NOT NewCircuitPeriod — OnionVPN floors it at 3600s " +
                "(Arti default) so short NewCircuitPeriod prefs do not thrash preemptive circuits. " +
                "Ext JNI control-api≥2",
        ),
        Op(
            name = "SETCONF_bridges",
            wire = "SETCONF UseBridges/Bridge",
            littleT = "Live bridge lines without full process restart",
            arti = ArtiBehavior.REQUIRES_RESTART,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Restart Arti with new bridgeLines (+ Lyrebird/Conjure TransportConfig) via JNI",
            docs = "arti-client 0.36.0 config::BridgesConfig + pt::TransportConfig; " +
                "arti-mobile passes bridge_lines + managed PT paths into TorClientConfigBuilder at start",
        ),
        Op(
            name = "SETCONF_nodes",
            wire = "SETCONF Entry/Exit/ExcludeNodes",
            littleT = "Live path constraints (StrictNodes)",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ExitNodes single {cc} → ArtiControlNative.applyExitCountry → " +
                "SOCKS StreamPrefs::exit_country (geoip). Entry/Exclude ignored with warning.",
            docs = "arti-client 0.36.0 StreamPrefs::exit_country (geoip); OnionVPN patched SOCKS " +
                "applies global exit country. EntryNodes/ExcludeNodes have no SOCKS mapping",
        ),
        Op(
            name = "SETCONF_geoip",
            wire = "SETCONF GeoIPFile",
            littleT = "Point Tor at GeoIP DBs for ip-to-country",
            arti = ArtiBehavior.NOOP_OK,
            parity = Parity.NOOP_OK,
            artiImpl = "Embedded GeoipDb via arti-client geoip feature (no external GeoIPFile)",
            docs = "arti-client 0.36.0 geoip uses tor_geoip::GeoipDb::new_embedded(); " +
                "no SETCONF GeoIPFile — exit_country works without C Tor GeoIP files",
        ),
        Op(
            name = "GETINFO_bootstrap",
            wire = "GETINFO status/bootstrap-phase",
            littleT = "Bootstrap progress / tags",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiControlNative.bootstrapFraction / readyForTraffic / bootstrapBlockage; " +
                "else synthetic TorControlStatus from SOCKS+DNS readiness",
            docs = "arti-client 0.36.0 BootstrapStatus::as_frac / ready_for_traffic / blocked — " +
                "OnionVPN Ext JNI; listener probe remains the stock-AAR stand-in",
        ),
        Op(
            name = "GETINFO_circuits",
            wire = "GETINFO circuit-status",
            littleT = "List circuits + CIRC events",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "Empty list / UI gated (circuitInspection=false)",
            docs = "circmgr() is experimental-api only; no circuit-status list API in 0.36.0",
        ),
        Op(
            name = "GETINFO_streams",
            wire = "GETINFO stream-status",
            littleT = "List streams + STREAM events",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "Empty list / UI gated",
            docs = "No stream-status API in arti-client 0.36.0 public surface",
        ),
        Op(
            name = "GETINFO_traffic",
            wire = "GETINFO traffic/read|written",
            littleT = "Process-wide Tor byte counters",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "UID TrafficStats via TorBandwidthSampler (TunnelThroughputTracker)",
            docs = "No traffic counters on TorClient in 0.36.0; Android TrafficStats is VPN equivalent",
        ),
        Op(
            name = "EXTENDCIRCUIT",
            wire = "EXTENDCIRCUIT 0",
            littleT = "Build a new circuit on demand",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "UI gated; Arti builds circuits on demand for SOCKS / connect()",
            docs = "Arti builds circuits internally; no controller EXTENDCIRCUIT in 0.36.0",
        ),
        Op(
            name = "CLOSECIRCUIT",
            wire = "CLOSECIRCUIT",
            littleT = "Close a specific circuit",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "UI gated; use NEWNYM to drop all circuits",
            docs = "No enumerable circuit handles in arti-client public API / arti-mobile JNI",
        ),
        Op(
            name = "CLOSESTREAM",
            wire = "CLOSESTREAM",
            littleT = "Close a specific stream",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "UI gated",
            docs = "No stream-id controller API in arti-client 0.36.0",
        ),
        Op(
            name = "RESOLVE",
            wire = "RESOLVE + ADDRMAP",
            littleT = "Ask Tor to resolve a hostname over the network",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "ArtiControlNative.resolveHostname → TorClient::resolve; " +
                "fallback: UDP DNS A query to Arti DNSPort",
            docs = "arti-client 0.36.0 TorClient::resolve / resolve_with_prefs — " +
                "OnionVPN Ext JNI control-api≥2; DNSPort remains stock-AAR fallback",
        ),
        Op(
            name = "SETEVENTS",
            wire = "SETEVENTS",
            littleT = "Async CIRC/STREAM/BW/STATUS events",
            arti = ArtiBehavior.SOFT_RECOVER,
            parity = Parity.APP_LAYER_1_1,
            artiImpl = "STATUS_CLIENT analogue via BootstrapStatus poll " +
                "(bootstrapFraction / bootstrapBlockage); no CIRC/STREAM events",
            docs = "bootstrap_events / BootstrapStatus::blocked in 0.36.0; " +
                "CIRC/STREAM event channel not exposed by arti-mobile JNI",
        ),
        Op(
            name = "AUTHENTICATE",
            wire = "AUTHENTICATE",
            littleT = "Cookie / password control auth",
            arti = ArtiBehavior.UNSUPPORTED,
            parity = Parity.ENGINE_LIMITATION,
            artiImpl = "No ControlSocket",
            docs = "In-process JNI; TorClient has no control-spec AUTHENTICATE",
        ),
        Op(
            name = "CLOSE_BUILT_CIRCUITS",
            wire = "CLOSECIRCUIT (all BUILT)",
            littleT = "Tear down built circuits so next streams rebuild",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "Same as NEWNYM — restartForNewIdentity()",
            docs = "Closing all built circuits ≈ clean circuit set; restart is the available tool",
        ),
        Op(
            name = "SOCKS_AUTH_ISOLATION",
            wire = "IsolateSOCKSAuth / SessionGroup",
            littleT = "Per-UID SOCKS username → separate circuits (KeepAliveIsolateSOCKSAuth)",
            arti = ArtiBehavior.EQUIVALENT,
            parity = Parity.SEMANTIC_1_1,
            artiImpl = "UidIsolatingTunForwarder sends u{uid} SOCKS auth on shared Arti SocksPort",
            docs = "arti-client 0.36.0 isolation::StreamIsolation / IsolationToken; " +
                "Arti SOCKS proxy maps username/password to stream isolation",
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
        "ControlPort op '$opName' is not available on Arti " +
            "(arti-client $ARTI_CLIENT_DOCS_VERSION API not exposed by arti-mobile JNI) — " +
            "use C Tor or NEWNYM/restart"
}
