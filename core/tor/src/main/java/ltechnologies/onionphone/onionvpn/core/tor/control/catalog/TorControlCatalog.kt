package ltechnologies.onionphone.onionvpn.core.tor.control.catalog

/**
 * Package `control.catalog` — wire vocabulary for Tor control-spec v1.
 *
 * Imported by: control client (SETEVENTS / SIGNAL), ops, and catalog unit tests.
 * No I/O; pure constants.
 *
 * @see <a href="https://spec.torproject.org/control-spec/commands.html">control-spec commands</a>
 * @see <a href="https://spec.torproject.org/control-spec/replies.html">control-spec replies</a>
 */
object TorControlCatalog {

    /**
     * Tor controller commands.
     *
     * @property wire exact keyword sent on the control channel
     * @property vpnUse OnionVPN rationale (when / why this command matters on Android VPN)
     */
    enum class Command(val wire: String, val vpnUse: String) {
        SETCONF("SETCONF", "Live torrc keys (bridges, DisableNetwork, EntryNodes)"),
        RESETCONF("RESETCONF", "Clear keys / __OwningControllerProcess"),
        GETCONF("GETCONF", "Read live config"),
        SETEVENTS("SETEVENTS", "Subscribe async 650 events"),
        AUTHENTICATE("AUTHENTICATE", "Cookie / password auth"),
        SAVECONF("SAVECONF", "Persist SETCONF to torrc (optional)"),
        SIGNAL("SIGNAL", "NEWNYM/ACTIVE/DORMANT/RELOAD/…"),
        MAPADDRESS("MAPADDRESS", "Force address map (rare)"),
        GETINFO("GETINFO", "Bootstrap, circuits, traffic, guards"),
        EXTENDCIRCUIT("EXTENDCIRCUIT", "Build/extend circuits (0 = new)"),
        SETCIRCUITPURPOSE("SETCIRCUITPURPOSE", "Mark circuit purpose"),
        SETROUTERPURPOSE("SETROUTERPURPOSE", "Relay purpose (unused client)"),
        ATTACHSTREAM("ATTACHSTREAM", "Manual stream attach (TransPort)"),
        POSTDESCRIPTOR("POSTDESCRIPTOR", "Inject descriptor (unused)"),
        REDIRECTSTREAM("REDIRECTSTREAM", "Rewrite stream target"),
        CLOSESTREAM("CLOSESTREAM", "Kill one stream"),
        CLOSECIRCUIT("CLOSECIRCUIT", "Kill circuit(s)"),
        QUIT("QUIT", "Close control connection"),
        USEFEATURE("USEFEATURE", "VERBOSE_NAMES etc."),
        RESOLVE("RESOLVE", "DNS via Tor (async ADDRMAP)"),
        PROTOCOLINFO("PROTOCOLINFO", "Auth methods before AUTHENTICATE"),
        LOADCONF("LOADCONF", "Replace config blob"),
        TAKEOWNERSHIP("TAKEOWNERSHIP", "Tor dies if controller dies"),
        AUTHCHALLENGE("AUTHCHALLENGE", "SAFECOOKIE handshake"),
        DROPGUARDS("DROPGUARDS", "Forget entry guards"),
        HSFETCH("HSFETCH", "Onion descriptor fetch"),
        ADD_ONION("ADD_ONION", "Ephemeral onion service"),
        DEL_ONION("DEL_ONION", "Remove onion service"),
        HSPOST("HSPOST", "Upload HS descriptor"),
        ONION_CLIENT_AUTH_ADD("ONION_CLIENT_AUTH_ADD", "Client onion auth"),
        ONION_CLIENT_AUTH_REMOVE("ONION_CLIENT_AUTH_REMOVE", "Remove client auth"),
        ONION_CLIENT_AUTH_VIEW("ONION_CLIENT_AUTH_VIEW", "List client auth"),
        DROPOWNERSHIP("DROPOWNERSHIP", "Release TAKEOWNERSHIP"),
        DROPTIMEOUTS("DROPTIMEOUTS", "Reset circuit build timeouts (net change)"),
    }

    /**
     * SIGNAL names (control-spec §3.7).
     *
     * @property wire SIGNAL argument
     * @property vpnUse when OnionVPN issues this signal
     */
    enum class Signal(val wire: String, val vpnUse: String) {
        RELOAD("RELOAD", "Reload config"),
        SHUTDOWN("SHUTDOWN", "Clean exit"),
        DUMP("DUMP", "Log connection dump"),
        DEBUG("DEBUG", "Debug logging"),
        HALT("HALT", "Immediate exit"),
        HUP("HUP", "Unix HUP"),
        INT("INT", "Unix INT"),
        USR1("USR1", "Unix USR1"),
        USR2("USR2", "Unix USR2"),
        TERM("TERM", "Unix TERM"),
        NEWNYM("NEWNYM", "New circuits + clear client DNS"),
        CLEARDNSCACHE("CLEARDNSCACHE", "Forget client DNS cache"),
        HEARTBEAT("HEARTBEAT", "Force heartbeat log"),
        ACTIVE("ACTIVE", "Leave dormant (after net change)"),
        DORMANT("DORMANT", "Idle / battery when Blocking"),
    }

    /**
     * Async event codes for SETEVENTS.
     *
     * @property wire event keyword
     * @property tier subscription layer — Tor 552s the *entire* SETEVENTS if any keyword
     *   is unknown, so tiers are applied incrementally (core → optional → PT).
     */
    enum class EventTier {
        /** Always subscribed; must succeed or connect fails. */
        CORE,
        /** Best-effort after core (CIRC_MINOR, STATUS_GENERAL, …). */
        OPTIONAL,
        /** Only when bridges/PT may be configured. */
        PT,
        /** Catalog only — never auto-subscribed. */
        CATALOG,
    }

    enum class Event(val wire: String, val tier: EventTier) {
        CIRC("CIRC", EventTier.CORE),
        CIRC_MINOR("CIRC_MINOR", EventTier.OPTIONAL),
        // STREAM floods the control reader under browse storms; keep optional.
        STREAM("STREAM", EventTier.OPTIONAL),
        ORCONN("ORCONN", EventTier.CORE),
        BW("BW", EventTier.CORE),
        NOTICE("NOTICE", EventTier.CORE),
        WARN("WARN", EventTier.CORE),
        ERR("ERR", EventTier.CORE),
        NEWDESC("NEWDESC", EventTier.CATALOG),
        ADDRMAP("ADDRMAP", EventTier.CORE),
        AUTHDIR_NEWDESCS("AUTHDIR_NEWDESCS", EventTier.CATALOG),
        DESCCHANGED("DESCCHANGED", EventTier.CATALOG),
        STATUS_GENERAL("STATUS_GENERAL", EventTier.OPTIONAL),
        STATUS_CLIENT("STATUS_CLIENT", EventTier.CORE),
        STATUS_SERVER("STATUS_SERVER", EventTier.CATALOG),
        GUARD("GUARD", EventTier.CORE),
        NS("NS", EventTier.CATALOG),
        STREAM_BW("STREAM_BW", EventTier.CATALOG),
        CLIENTS_SEEN("CLIENTS_SEEN", EventTier.CATALOG),
        NEWCONSENSUS("NEWCONSENSUS", EventTier.CATALOG),
        BUILDTIMEOUT_SET("BUILDTIMEOUT_SET", EventTier.OPTIONAL),
        SIGNAL("SIGNAL", EventTier.OPTIONAL),
        CONF_CHANGED("CONF_CHANGED", EventTier.OPTIONAL),
        CIRC_BW("CIRC_BW", EventTier.CATALOG),
        CONN_BW("CONN_BW", EventTier.CATALOG),
        CELL_STATS("CELL_STATS", EventTier.CATALOG),
        TB_EMPTY("TB_EMPTY", EventTier.CATALOG),
        TRANSPORT_LAUNCHED("TRANSPORT_LAUNCHED", EventTier.PT),
        HS_DESC("HS_DESC", EventTier.CATALOG),
        HS_DESC_CONTENT("HS_DESC_CONTENT", EventTier.CATALOG),
        PT_LOG("PT_LOG", EventTier.PT),
        PT_STATUS("PT_STATUS", EventTier.PT),
    }

    private fun eventsOf(tier: EventTier): String =
        Event.entries.filter { it.tier == tier }.joinToString(" ") { it.wire }

    /** Core SETEVENTS — lean set (STREAM is optional to avoid control floods). */
    val CLIENT_EVENTS: String get() = eventsOf(EventTier.CORE)

    /** Optional extras tried after core succeeds (best-effort, incremental). */
    val CLIENT_EVENTS_OPTIONAL: String get() = eventsOf(EventTier.OPTIONAL)

    /** Pluggable-transport events (only when bridges configured). */
    val CLIENT_EVENTS_PT: String get() = eventsOf(EventTier.PT)

    /** Core GETINFO keys — safe to batch (always present on Tor ≥0.2.x). */
    val HEALTH_GETINFO_CORE = listOf(
        "version",
        "status/bootstrap-phase",
        "status/circuit-established",
        "status/enough-dir-info",
    )

    /** Optional GETINFO — probe per-key (one 552 must not drop the others). */
    val HEALTH_GETINFO_OPTIONAL = listOf(
        "dormant",
        "network-liveness",
    )

    val HEALTH_GETINFO_TRAFFIC = listOf(
        "traffic/read",
        "traffic/written",
    )

    val HEALTH_GETINFO_HEAVY = listOf(
        "circuit-status",
        "stream-status",
        "entry-guards",
    )

    /** Flat union for docs/tests — never join into one GETINFO batch. */
    val HEALTH_GETINFO_KEYS: List<String>
        get() = HEALTH_GETINFO_CORE + HEALTH_GETINFO_OPTIONAL +
            HEALTH_GETINFO_TRAFFIC + HEALTH_GETINFO_HEAVY
}
