package ltechnologies.onionphone.onionvpn.core.model

/**
 * Which Tor client implementation drives the tunnel.
 *
 * - [LITTLE_T]: classic C Tor (`libtor.so` + torrc + ControlSocket).
 * - [ARTI]: Rust Arti via Guardian Project / Tor Project `arti-mobile`
 *   (in-process SOCKS + DNS proxy; embeds arti-client 0.36.0; no classic control port).
 */
enum class TorEngine {
    LITTLE_T,
    ARTI,
    ;

    val displayName: String
        get() = when (this) {
            LITTLE_T -> "C Tor (libtor)"
            ARTI -> "Arti (Rust)"
        }

    /** Feature matrix used to gate UI, validation, and recovery paths. */
    val capabilities: TorEngineCapabilities
        get() = when (this) {
            LITTLE_T -> TorEngineCapabilities.LITTLE_T
            ARTI -> TorEngineCapabilities.ARTI
        }

    companion object {
        fun fromPreference(raw: String?): TorEngine =
            entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: LITTLE_T
    }
}

/**
 * What each Tor engine can do. Call sites must branch on these flags instead of
 * sniffing version strings or assuming ControlSocket semantics.
 *
 * Arti capability notes map to arti-client 0.36.0
 * (https://docs.rs/arti-client/0.36.0/arti_client/) vs what arti-mobile JNI exposes.
 */
data class TorEngineCapabilities(
    /** Classic Tor control-spec (ControlSocket + cookie + SIGNAL/SETCONF/GETINFO). */
    val classicControlPlane: Boolean,
    /** Distinct SocksPorts with SessionGroup isolation (apps / DNSCrypt / probe). */
    val multiSocksSessionGroups: Boolean,
    /**
     * Per-stream isolation via SOCKS username/password
     * (C Tor IsolateSOCKSAuth / Arti IsolationToken via SOCKS auth).
     */
    val socksAuthIsolation: Boolean,
    /** Native DNSPort AutomapHostsOnResolve → VirtualAddrNetwork. */
    val nativeAutomapDnsPort: Boolean,
    /**
     * App-side Automap for `.onion`/`.exit` when [nativeAutomapDnsPort] is false
     * (synthesize virtual A + DnsHostnameCache → SOCKS5A).
     */
    val synthesizeOnionAutomap: Boolean,
    /** New identity (C Tor SIGNAL NEWNYM, or Arti runtime restart). */
    val newIdentity: Boolean,
    /** Live CIRC/STREAM inspection and CLOSECIRCUIT / EXTENDCIRCUIT. */
    val circuitInspection: Boolean,
    /** Live SETCONF (circuit timing, bridges, GeoIP, nodes). */
    val liveSetConf: Boolean,
    /**
     * DORMANT / ACTIVE semantics.
     * C Tor: real SIGNAL. Arti: app-layer status flag
     * ([TorClient::set_dormant] exists in 0.36.0 but is not in arti-mobile JNI).
     */
    val dormantSignals: Boolean,
    /** Runtime torrc file is authoritative config. */
    val torrcConfig: Boolean,
    /** Conjure pluggable transport. */
    val conjureBridges: Boolean,
    /**
     * EntryNodes / ExitNodes / ExcludeNodes honored by the engine.
     * Arti: false — StreamPrefs.exit_country is Rust connect-only, not SOCKS/JNI.
     */
    val nodePrefs: Boolean,
    /**
     * Bridges applied at engine start (C Tor torrc / Arti JNI bridgeLines).
     * Live SETCONF still requires [liveSetConf]; otherwise restart applies them.
     */
    val bridgesAtStart: Boolean,
) {
    companion object {
        val LITTLE_T = TorEngineCapabilities(
            classicControlPlane = true,
            multiSocksSessionGroups = true,
            socksAuthIsolation = true,
            nativeAutomapDnsPort = true,
            synthesizeOnionAutomap = false,
            newIdentity = true,
            circuitInspection = true,
            liveSetConf = true,
            dormantSignals = true,
            torrcConfig = true,
            conjureBridges = true,
            nodePrefs = true,
            bridgesAtStart = true,
        )

        val ARTI = TorEngineCapabilities(
            classicControlPlane = false,
            multiSocksSessionGroups = false,
            socksAuthIsolation = true,
            nativeAutomapDnsPort = false,
            synthesizeOnionAutomap = true,
            newIdentity = true,
            circuitInspection = false,
            liveSetConf = false,
            // App-layer synthetic dormant flag (Rust set_dormant not in JNI).
            dormantSignals = true,
            torrcConfig = false,
            conjureBridges = false,
            nodePrefs = false,
            bridgesAtStart = true,
        )
    }
}
