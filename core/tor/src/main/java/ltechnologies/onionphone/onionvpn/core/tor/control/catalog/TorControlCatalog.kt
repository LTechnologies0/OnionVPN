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
     * @property client true when OnionVPN VPN client should subscribe by default
     */
    enum class Event(val wire: String, val client: Boolean) {
        CIRC("CIRC", true),
        CIRC_MINOR("CIRC_MINOR", true),
        STREAM("STREAM", true),
        ORCONN("ORCONN", true),
        BW("BW", true),
        NOTICE("NOTICE", true),
        WARN("WARN", true),
        ERR("ERR", true),
        NEWDESC("NEWDESC", false),
        ADDRMAP("ADDRMAP", true),
        AUTHDIR_NEWDESCS("AUTHDIR_NEWDESCS", false),
        DESCCHANGED("DESCCHANGED", false),
        STATUS_GENERAL("STATUS_GENERAL", true),
        STATUS_CLIENT("STATUS_CLIENT", true),
        STATUS_SERVER("STATUS_SERVER", false),
        GUARD("GUARD", true),
        NS("NS", false),
        STREAM_BW("STREAM_BW", false),
        CLIENTS_SEEN("CLIENTS_SEEN", false),
        NEWCONSENSUS("NEWCONSENSUS", false),
        BUILDTIMEOUT_SET("BUILDTIMEOUT_SET", true),
        SIGNAL("SIGNAL", true),
        CONF_CHANGED("CONF_CHANGED", true),
        CIRC_BW("CIRC_BW", false),
        CONN_BW("CONN_BW", false),
        CELL_STATS("CELL_STATS", false),
        TB_EMPTY("TB_EMPTY", false),
        TRANSPORT_LAUNCHED("TRANSPORT_LAUNCHED", true),
        HS_DESC("HS_DESC", false),
        HS_DESC_CONTENT("HS_DESC_CONTENT", false),
        PT_LOG("PT_LOG", true),
        PT_STATUS("PT_STATUS", true),
    }

    /** Space-separated SETEVENTS list for Orbot-like VPN clients. */
    val CLIENT_EVENTS: String =
        Event.entries.filter { it.client }.joinToString(" ") { it.wire }

    /** GETINFO keys polled for health / UI snapshots. */
    val HEALTH_GETINFO_KEYS = listOf(
        "version",
        "status/bootstrap-phase",
        "status/circuit-established",
        "status/enough-dir-info",
        "status/good-server-descriptor",
        "dormant",
        "traffic/read",
        "traffic/written",
        "circuit-status",
        "stream-status",
        "entry-guards",
        "network-liveness",
        "process/pid",
        "process/uid",
    )
}
