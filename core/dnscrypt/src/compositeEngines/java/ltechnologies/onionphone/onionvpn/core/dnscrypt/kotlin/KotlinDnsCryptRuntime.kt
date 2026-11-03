package ltechnologies.onionphone.onionvpn.core.dnscrypt.kotlin

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptConfigWriter
import ltechnologies.onionphone.onionvpn.core.dnscrypt.config.DnsCryptResolverPlan
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelPreferences
import org.kotlindnscrypt.api.DnsCryptClient
import org.kotlindnscrypt.api.DnsCryptSession
import org.kotlindnscrypt.api.ResolverPool
import org.kotlindnscrypt.api.SessionOptions
import org.kotlindnscrypt.sources.BundledResolvers
import org.kotlindnscrypt.sources.CatalogFilter
import org.kotlindnscrypt.transport.Socks5TcpDialer
import timber.log.Timber

/**
 * Loopback DNS stub (UDP+TCP/53) backed by org.kotlindnscrypt over Tor SOCKS.
 * Policy matches [DnsCryptConfigWriter] / native dnscrypt-proxy (resolver plan, cache, padding).
 */
internal class KotlinDnsCryptRuntime {
    private var scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var udpJob: Job? = null
    private var tcpJob: Job? = null
    private val running = AtomicBoolean(false)
    private val sessionMutex = Mutex()
    private var session: DnsCryptSession? = null
    private var blockedSuffixes: List<String> = emptyList()
    private val queryCache = KotlinDnsCryptQueryCache()
    private var lastParams: SessionParams? = null

    var onLogLine: ((String) -> Unit)? = null

    private data class SessionParams(
        val torSocksPort: Int,
        val socksUser: String,
        val serverName: String,
        val preferences: TunnelPreferences,
    )

    suspend fun start(
        listenPort: Int,
        torSocksPort: Int,
        socksUser: String,
        serverName: String,
        preferences: TunnelPreferences,
    ) {
        stopInternal()
        if (!scope.isActive) {
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        }
        blockedSuffixes = DnsCryptConfigWriter.blockedNamesFileContent()
            .lineSequence()
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toList()
        openSession(torSocksPort, socksUser, serverName, preferences)
        running.set(true)
        val loopback = InetAddress.getByName(TunnelEndpoints.LOOPBACK)
        udpJob = scope.launch {
            DatagramSocket(listenPort, loopback).use { socket ->
                socket.soTimeout = 0
                onLogLine?.invoke("[INFO] kotlin-DNSCrypt UDP listening on $listenPort")
                val buf = ByteArray(4096)
                while (isActive && running.get()) {
                    val packet = DatagramPacket(buf, buf.size)
                    runCatching { socket.receive(packet) }.onFailure { continue }
                    val query = packet.data.copyOf(packet.length)
                    val reply = runCatching { resolveRaw(query) }.getOrNull() ?: continue
                    socket.send(
                        DatagramPacket(
                            reply,
                            reply.size,
                            packet.address,
                            packet.port,
                        ),
                    )
                }
            }
        }
        tcpJob = scope.launch {
            ServerSocket(listenPort, 50, loopback).use { server ->
                onLogLine?.invoke("[INFO] kotlin-DNSCrypt TCP listening on $listenPort")
                while (isActive && running.get()) {
                    val client = runCatching { server.accept() }.getOrNull() ?: continue
                    launch { handleTcpClient(client) }
                }
            }
        }
    }

    suspend fun reconfigure(
        torSocksPort: Int,
        socksUser: String,
        serverName: String,
        preferences: TunnelPreferences,
    ) {
        queryCache.clear()
        sessionMutex.withLock {
            session?.close()
            session = null
            openSessionLocked(torSocksPort, socksUser, serverName, preferences)
        }
        onLogLine?.invoke("[INFO] kotlin-DNSCrypt session reconfigured ($serverName)")
    }

    suspend fun clearQueryCache() {
        queryCache.clear()
        val params = lastParams ?: return
        sessionMutex.withLock {
            session?.discardPqTicket()
            session?.close()
            session = null
            openSessionLocked(
                params.torSocksPort,
                params.socksUser,
                params.serverName,
                params.preferences,
            )
        }
        onLogLine?.invoke("[INFO] kotlin-DNSCrypt query cache cleared (session refreshed)")
    }

    fun isRunning(): Boolean = running.get()

    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        running.set(false)
        udpJob?.cancel()
        tcpJob?.cancel()
        udpJob = null
        tcpJob = null
        queryCache.clear()
        runCatching {
            kotlinx.coroutines.runBlocking {
                sessionMutex.withLock {
                    session?.close()
                    session = null
                }
            }
        }
        scope.cancel()
    }

    private suspend fun openSession(
        torSocksPort: Int,
        socksUser: String,
        serverName: String,
        preferences: TunnelPreferences,
    ) {
        sessionMutex.withLock {
            openSessionLocked(torSocksPort, socksUser, serverName, preferences)
        }
    }

    private suspend fun openSessionLocked(
        torSocksPort: Int,
        socksUser: String,
        serverName: String,
        preferences: TunnelPreferences,
    ) {
        lastParams = SessionParams(torSocksPort, socksUser, serverName, preferences)
        val dialer = Socks5TcpDialer(
            proxy = InetSocketAddress(TunnelEndpoints.LOOPBACK, torSocksPort),
            username = socksUser,
            password = TunnelEndpoints.socksDnsCryptPass(),
        )
        val client = DnsCryptClient(
            transport = org.kotlindnscrypt.transport.UdpTcpTransport(dialer),
            defaultOptions = sessionOptions(preferences),
        )
        val filter = catalogFilter(preferences)
        val relayAddress = anonymizedRelayAddress(preferences)
        val relayName = anonymizedRelayName(preferences)
        val names = DnsCryptResolverPlan.resolvedServerNames(serverName, preferences)
        session = when {
            DnsCryptResolverPlan.isAutoSelection(names) -> {
                client.openAuto(
                    filter = filter,
                    relayName = relayName,
                    options = sessionOptions(preferences),
                )
            }
            names.size == 1 -> {
                client.openNamed(
                    name = names.first(),
                    filter = filter,
                    relay = relayAddress,
                    options = sessionOptions(preferences),
                )
            }
            else -> {
                val endpoints = names.mapNotNull { n ->
                    runCatching { client.catalog().endpoint(n, filter, relayAddress) }.getOrNull()
                }
                check(endpoints.isNotEmpty()) { "No kotlin-DNSCrypt endpoints for $names" }
                ResolverPool(client, endpoints).open(sessionOptions(preferences))
            }
        }
        onLogLine?.invoke("[INFO] Server certificate loaded.")
    }

    private fun catalogFilter(preferences: TunnelPreferences) = CatalogFilter(
        requireNoLog = preferences.dnsCryptRequireNoLog,
        requireNoFilter = preferences.dnsCryptRequireNoFilter,
        requireDnssec = preferences.dnsCryptRequireDnssec,
        ipv4Only = true,
    )

    private fun sessionOptions(preferences: TunnelPreferences): SessionOptions =
        SessionOptions(
            forceTcp = true,
            ephemeralKeys = true,
            allowPqResumeWhenAnonymized = preferences.dnsCryptAnonymized,
        )

    /** One relay per session — same role as native `via=['*']` (any compatible relay). */
    private fun anonymizedRelayName(preferences: TunnelPreferences): String? {
        if (!preferences.dnsCryptAnonymized) return null
        return runCatching { BundledResolvers.relays().entries.randomOrNull()?.name }.getOrNull()
    }

    private fun anonymizedRelayAddress(preferences: TunnelPreferences): InetSocketAddress? =
        anonymizedRelayName(preferences)?.let { name ->
            runCatching { BundledResolvers.relays().require(name).toAddress() }.getOrNull()
        }

    private suspend fun resolveRaw(query: ByteArray): ByteArray {
        if (isBlocked(query)) {
            return buildRefusedResponse(query)
        }
        queryCache.get(query)?.let { return it }
        val active = sessionMutex.withLock { session }
            ?: error("kotlin-DNSCrypt session not open")
        val reply = active.exchange(query)
        queryCache.put(query, reply)
        return reply
    }

    private suspend fun handleTcpClient(client: Socket) {
        client.use { sock ->
            sock.soTimeout = 30_000
            val input = sock.getInputStream()
            val output = sock.getOutputStream()
            val lenBuf = ByteArray(2)
            while (running.get()) {
                if (input.read(lenBuf) != 2) break
                val len = ((lenBuf[0].toInt() and 0xff) shl 8) or (lenBuf[1].toInt() and 0xff)
                if (len <= 0 || len > 4096) break
                val query = ByteArray(len)
                var read = 0
                while (read < len) {
                    val n = input.read(query, read, len - read)
                    if (n <= 0) break
                    read += n
                }
                if (read != len) break
                val reply = runCatching { resolveRaw(query) }.getOrElse {
                    Timber.w(it, "kotlin-DNSCrypt TCP query failed")
                    break
                }
                output.write((reply.size shr 8) and 0xff)
                output.write(reply.size and 0xff)
                output.write(reply)
                output.flush()
            }
        }
    }

    private fun isBlocked(query: ByteArray): Boolean {
        val qname = extractQname(query)?.lowercase() ?: return false
        return blockedSuffixes.any { suffix ->
            when {
                suffix.startsWith("*.") -> qname.endsWith(suffix.removePrefix("*"))
                else -> qname == suffix || qname.endsWith(".$suffix")
            }
        }
    }

    private fun extractQname(query: ByteArray): String? {
        if (query.size < 13) return null
        var idx = 12
        val labels = mutableListOf<String>()
        while (idx < query.size) {
            val len = query[idx].toInt() and 0xff
            if (len == 0) break
            if (len > 63) return null
            idx++
            if (idx + len > query.size) return null
            labels += String(query, idx, len, Charsets.US_ASCII)
            idx += len
        }
        return labels.joinToString(".")
    }

    private fun buildRefusedResponse(query: ByteArray): ByteArray {
        if (query.size < 12) return query
        val out = query.copyOf()
        out[2] = (out[2].toInt() or 0x02).toByte()
        out[3] = (out[3].toInt() or 0x05).toByte()
        return out
    }
}
