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

    /**
     * Settings Tor section subtitle — derived only from [capabilities]
     * so copy cannot drift from the feature matrix.
     */
    fun settingsSubtitle(): String {
        val c = capabilities
        return buildString {
            when {
                c.classicControlPlane && c.liveSetConf ->
                    append(
                        "Circuit rotation via ControlPort SETCONF (path-spec). " +
                            "Live MaxCircuitDirtiness / NewCircuitPeriod when connected.",
                    )
                c.liveCircuitTiming && !c.liveSetConf ->
                    append(
                        "Circuit timing via Ext JNI: max_dirtiness + prediction_lifetime " +
                            "(floored ≥3600s; not a 1:1 NewCircuitPeriod map).",
                    )
                else -> append("Circuit timing applied at engine start.")
            }
            append(' ')
            when {
                c.nativeAutomapDnsPort -> append("Native DNSPort Automap. ")
                c.synthesizeOnionAutomap -> append("App-side Automap synth for .onion/.exit. ")
            }
            if (c.socksAuthIsolation) {
                append(
                    if (c.multiSocksSessionGroups) {
                        "Per-UID SOCKS-auth + distinct SessionGroup SocksPorts. "
                    } else {
                        "Per-UID SOCKS-auth on a shared SocksPort (no SessionGroups). "
                    },
                )
            }
            if (c.conjureBridges) {
                append("Lyrebird + Conjure PTs. ")
            } else {
                append("Lyrebird PTs (no Conjure). ")
            }
            when {
                c.nodePrefs -> append("Full Entry/Exit/ExcludeNodes. ")
                c.exitCountryPrefs -> append("Single-country ExitNodes only. ")
                else -> append("No node country prefs. ")
            }
            if (!c.circuitInspection) append("No circuits UI. ")
            when {
                c.liveSetConf -> append("Bridges/nodes can apply live when connected.")
                c.bridgesAtStart -> append("Bridges/NEWNYM/RELOAD need tunnel restart.")
            }
        }.trim()
    }

    /** Short blurb under the C Tor / Arti engine chips. */
    fun enginePickerHint(): String {
        val c = capabilities
        return buildString {
            append("Choose which Tor client the tunnel launches. ")
            append(displayName)
            append(": ")
            when {
                c.classicControlPlane && c.torrcConfig ->
                    append("full ControlPort + torrc feature set")
                else ->
                    append("SOCKS+DNS routing with capability-gated gaps")
            }
            if (!c.multiSocksSessionGroups) append("; shared SocksPort")
            if (!c.circuitInspection) append("; no circuits UI")
            if (c.conjureBridges) append("; Conjure supported")
            else append("; no Conjure")
            if (c.exitCountryPrefs && !c.nodePrefs) append("; Exit country only")
            append(". Changing engine restarts the tunnel.")
        }
    }

    companion object {
        fun fromPreference(raw: String?): TorEngine {
            if (raw.equals("KOTLIN_TOR", ignoreCase = true) ||
                raw.equals("kotlin_tor", ignoreCase = true)
            ) {
                // Former kotlin-tor prefs migrate to classic C Tor (same HEV_SOCKS plane).
                return LITTLE_T
            }
            return entries.firstOrNull { it.name.equals(raw, ignoreCase = true) } ?: LITTLE_T
        }
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
    /**
     * Live circuit timing SETCONF (MaxCircuitDirtiness / NewCircuitPeriod analogue).
     * Arti: Ext JNI reconfigure (max_dirtiness + prediction_lifetime).
     */
    val liveCircuitTiming: Boolean,
    /** Live SETCONF for bridges / GeoIP / full node prefs (C Tor ControlPort). */
    val liveSetConf: Boolean,
    /**
     * DORMANT / ACTIVE semantics.
     * C Tor: real SIGNAL. Arti: TorClient::set_dormant via OnionVPN Ext JNI when present;
     * otherwise app-layer status flag.
     */
    val dormantSignals: Boolean,
    /** Runtime torrc file is authoritative config. */
    val torrcConfig: Boolean,
    /** Conjure pluggable transport. */
    val conjureBridges: Boolean,
    /**
     * Full EntryNodes / ExitNodes / ExcludeNodes (C Tor StrictNodes).
     * Arti: false — use [exitCountryPrefs] for single-country ExitNodes only.
     */
    val nodePrefs: Boolean,
    /**
     * Single-country ExitNodes via StreamPrefs::exit_country (geoip) on SOCKS.
     * Multi-country / Entry / Exclude remain unsupported on Arti.
     */
    val exitCountryPrefs: Boolean,
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
            liveCircuitTiming = true,
            liveSetConf = true,
            dormantSignals = true,
            torrcConfig = true,
            conjureBridges = true,
            nodePrefs = true,
            exitCountryPrefs = true,
            bridgesAtStart = true,
        )

        val ARTI = TorEngineCapabilities(
            classicControlPlane = false,
            // App-layer role relays give distinct DNSCrypt/probe listen ports → Arti SOCKS
            // (IsolationToken via SOCKS auth). Not native SessionGroup, same product effect.
            multiSocksSessionGroups = true,
            socksAuthIsolation = true,
            nativeAutomapDnsPort = false,
            synthesizeOnionAutomap = true,
            newIdentity = true,
            circuitInspection = true, // onionmasq CircuitStore / hops UI when TUN plane is ONIONMASQ
            liveCircuitTiming = true,
            liveSetConf = false,
            // TorClient::set_dormant via Ext JNI when patched .so is loaded.
            dormantSignals = true,
            torrcConfig = false,
            conjureBridges = true,
            nodePrefs = false,
            exitCountryPrefs = true,
            bridgesAtStart = true,
        )
    }
}
