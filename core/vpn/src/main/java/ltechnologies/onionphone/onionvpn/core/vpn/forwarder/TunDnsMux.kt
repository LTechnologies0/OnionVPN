package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.LockSupport
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.observability.MemoryHygiene
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsOnionAutomapReply
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.dns.OnionAutomapAllocator
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.FirewallBridge
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import timber.log.Timber

/**
 * Splits VPN TUN traffic:
 * - When [divertDnsToDnsCrypt]: UDP/53 clearnet → DNSCrypt; `.onion`/`.exit` → Tor DNSPort
 *   (AutomapHostsOnResolve → virtual IPs in [TunnelEndpoints.VIRTUAL_ADDR_NETWORK]/10),
 *   or app-side Automap when [synthesizeOnionAutomap] (Arti has no native Automap).
 * - Non-DNS UDP / ICMP / multicast → blackhole (force apps onto TCP; Tor has no UDP)
 * - IPv4+IPv6 TCP → hev → Tor SOCKS
 * - IPv4 TCP → firewall check → hev engine (UID stamped into [TcpFlowUidIndex] for SocksUidBridge)
 *
 * DoS / ARM notes:
 * - DNS work uses a **bounded** pool + queue (never unbounded LinkedBlockingQueue).
 * - Saturated pool: AbortPolicy + recycle (never block TUN; never silently drop
 *   queued DNS without recycling — DiscardOldest leaked buffers and starved apps).
 * - Per-worker reused DatagramSocket + reply buffers (ThreadLocal) — no open/close per query.
 * - Packet handoff uses a small free-list of MTU buffers.
 * - No per-packet [FileOutputStream.flush].
 */
class TunDnsMux(
    context: Context,
    private val tunFd: ParcelFileDescriptor,
    private val hevFd: ParcelFileDescriptor,
    private val dnsCryptHost: String,
    private val dnsCryptPort: Int,
    private val vpnDnsAddress: String,
    private val divertDnsToDnsCrypt: Boolean = true,
    /** Tor DNSPort for Automap; `<= 0` drops onion queries (fail-closed) unless synthesizing. */
    private val torDnsHost: String = TunnelEndpoints.LOOPBACK,
    private val torDnsPort: Int = 0,
    /**
     * When true (Arti), answer `.onion`/`.exit` locally with VirtualAddrNetwork IPs
     * instead of querying Tor DNSPort (Arti DNS proxy has no AutomapHostsOnResolve).
     */
    private val synthesizeOnionAutomap: Boolean = false,
    private val onFatal: ((Throwable) -> Unit)? = null,
) {
    private val ownerResolver = ConnectionOwnerResolver(context)
    private val running = AtomicBoolean(false)
    private val generation = AtomicLong(0)
    private var tunToHev: Thread? = null
    private var hevToTun: Thread? = null
    private val tunWriteLock = Any()
    private val hevWriteLock = Any()

    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private var hevIn: FileInputStream? = null
    private var hevOut: FileOutputStream? = null

    private val dnsCryptAddress: InetAddress = InetAddress.getByName(dnsCryptHost)
    private val torDnsAddress: InetAddress = InetAddress.getByName(torDnsHost)
    private val packetPool = ArrayBlockingQueue<ByteArray>(DNS_QUEUE_CAP)
    private val dnsRejectSample = AtomicLong(0)

    private val dnsExecutor = ThreadPoolExecutor(
        DNS_CORE_THREADS,
        DNS_MAX_THREADS,
        30L,
        TimeUnit.SECONDS,
        ArrayBlockingQueue(DNS_QUEUE_CAP),
        { r -> Thread(r, "onionvpn-dns").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    ).apply {
        allowCoreThreadTimeOut(true)
    }
    private var tunEmptyReadStreak = 0
    private var hevEmptyReadStreak = 0

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val gen = generation.incrementAndGet()
        LeakPacketFilter.resetStats()
        val vpnDns = InetAddress.getByName(vpnDnsAddress).address
        val localTunOut = FileOutputStream(tunFd.fileDescriptor)
        val localHevOut = FileOutputStream(hevFd.fileDescriptor)
        tunOut = localTunOut
        hevOut = localHevOut

        tunToHev = Thread({
            val localTunIn = FileInputStream(tunFd.fileDescriptor)
            tunIn = localTunIn
            val buf = ByteArray(MTU)
            try {
                while (running.get() && generation.get() == gen) {
                    val n = localTunIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            tunEmptyReadStreak = (tunEmptyReadStreak + 1).coerceAtMost(8)
                            LockSupport.parkNanos(EMPTY_READ_BASE_NS shl tunEmptyReadStreak)
                            continue
                        }
                        divertDnsToDnsCrypt && LeakPacketFilter.isDnsUdpPort53(buf, n) -> {
                            tunEmptyReadStreak = 0
                            // Clearnet UDP/53 → DNSCrypt; .onion/.exit → Tor DNSPort (in handleDnsQuery).
                            // Same OpenSnitch gate as TCP — drop if interactive firewall DENYs.
                            if (!FirewallBridge.engine.allowOutbound(buf, n)) {
                                // Drop
                            } else {
                                snoopDnsOutbound(buf, n)
                                val packet = borrowPacket(buf, n)
                                try {
                                    dnsExecutor.execute {
                                        try {
                                            if (generation.get() == gen) {
                                                handleDnsQuery(packet, n, localTunOut)
                                            }
                                        } finally {
                                            recyclePacket(packet)
                                        }
                                    }
                                } catch (_: RejectedExecutionException) {
                                    recyclePacket(packet)
                                    if ((dnsRejectSample.incrementAndGet() and 0x3F) == 0L) {
                                        Timber.w("TunDnsMux DNS pool saturated — dropping query")
                                    }
                                }
                            }
                        }
                        !divertDnsToDnsCrypt && isDnsQueryToVpnDns(buf, n, vpnDns) -> {
                            tunEmptyReadStreak = 0
                            // Legacy FakeDNS path — still learn QNAME before engine.
                            snoopDnsOutbound(buf, n)
                            writeHev(localHevOut, buf, n)
                        }
                        else -> {
                            tunEmptyReadStreak = 0
                            val blackhole = LeakPacketFilter.blackholeBeforeTorTcp(buf, n)
                            if (blackhole != null) {
                                LeakPacketFilter.noteBlackhole(blackhole)
                                // Silent UDP drops stall Chromium QUIC→TCP fallback; ICMP
                                // port-unreachable makes the stack fail over promptly.
                                IcmpUnreachable.buildForBlackholedUdp(buf, n)?.let { icmp ->
                                    synchronized(tunWriteLock) {
                                        if (running.get() && generation.get() == gen) {
                                            localTunOut.write(icmp, 0, icmp.size)
                                        }
                                    }
                                }
                            } else if (!FirewallBridge.engine.allowOutbound(buf, n)) {
                                // Drop
                            } else {
                                stampTcpUid(buf, n)
                                writeHev(localHevOut, buf, n)
                            }
                        }
                    }
                }
            } catch (error: Exception) {
                if (running.get() && generation.get() == gen) {
                    Timber.w(error, "TunDnsMux tun→hev stopped")
                    onFatal?.invoke(error)
                }
            }
        }, "onionvpn-tun-hev").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY
            start()
        }

        hevToTun = Thread({
            val localHevIn = FileInputStream(hevFd.fileDescriptor)
            hevIn = localHevIn
            val buf = ByteArray(MTU)
            try {
                while (running.get() && generation.get() == gen) {
                    val n = localHevIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            hevEmptyReadStreak = (hevEmptyReadStreak + 1).coerceAtMost(8)
                            LockSupport.parkNanos(EMPTY_READ_BASE_NS shl hevEmptyReadStreak)
                            continue
                        }
                        else -> {
                            hevEmptyReadStreak = 0
                            // FakeDNS / hev replies: attribute Fake-IP → hostname.
                            snoopDnsInbound(buf, n)
                            synchronized(tunWriteLock) {
                                if (!running.get() || generation.get() != gen) return@synchronized
                                localTunOut.write(buf, 0, n)
                            }
                        }
                    }
                }
            } catch (error: Exception) {
                if (running.get() && generation.get() == gen) {
                    Timber.w(error, "TunDnsMux hev→tun stopped")
                    onFatal?.invoke(error)
                }
            }
        }, "onionvpn-hev-tun").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY
            start()
        }

        Timber.i(
            "TunDnsMux started dns=$vpnDnsAddress divertDns=$divertDnsToDnsCrypt " +
                "clearnet→$dnsCryptHost:$dnsCryptPort " +
                "onion→${if (synthesizeOnionAutomap) "synth-automap" else "$torDnsHost:$torDnsPort"} " +
                "pool=$DNS_CORE_THREADS..$DNS_MAX_THREADS q=$DNS_QUEUE_CAP gen=$gen",
        )
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) {
            // Still bump generation so any late readers ignore fatals.
            generation.incrementAndGet()
            return
        }
        generation.incrementAndGet()
        dnsExecutor.shutdownNow()
        runCatching { tunIn?.close() }
        runCatching { hevIn?.close() }
        runCatching { tunOut?.close() }
        runCatching { hevOut?.close() }
        tunIn = null
        hevIn = null
        tunOut = null
        hevOut = null
        runCatching { tunFd.close() }
        runCatching { hevFd.close() }
        tunToHev?.let { t ->
            t.interrupt()
            runCatching { t.join(2_000L) }
        }
        hevToTun?.let { t ->
            t.interrupt()
            runCatching { t.join(2_000L) }
        }
        tunToHev = null
        hevToTun = null
        packetPool.clear()
        // FakeDNS IPs are reused across sessions — drop stale IP→host bindings.
        pendingQnames.clear()
        DnsHostnameCache.clear()
        TcpFlowUidIndex.clear()
        runCatching {
            if (!dnsExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                Timber.w("DNS executor did not terminate cleanly")
            }
        }
        MemoryHygiene.afterHeavyWork("tundnsmux_stop")
    }

    private fun borrowPacket(src: ByteArray, n: Int): ByteArray {
        val packet = packetPool.poll() ?: ByteArray(MTU)
        System.arraycopy(src, 0, packet, 0, n)
        return packet
    }

    private fun recyclePacket(packet: ByteArray) {
        if (packet.size == MTU) {
            packetPool.offer(packet)
        }
    }

    private fun writeHev(hevOut: FileOutputStream, buf: ByteArray, n: Int) {
        synchronized(hevWriteLock) {
            if (!running.get()) return
            hevOut.write(buf, 0, n)
        }
    }

    /** Stamp SYN (and first-seen dest) so SocksUidBridge can IsolateSOCKSAuth after hev CONNECT. */
    private fun stampTcpUid(buf: ByteArray, n: Int) {
        val info = IpPacketParser.parse(buf, n) ?: return
        if (!info.isTcp) return
        val recent = if (info.isIpv6) {
            TcpFlowUidIndex.hasRecentHost(info.dstIp, info.dstPort)
        } else {
            TcpFlowUidIndex.hasRecent(info.dstIpInt, info.dstPort)
        }
        // Always re-stamp SYNs (owner UID may have been missed on the first race).
        if (!info.isTcpSyn && recent) return
        val uid = ownerResolver.resolveUid(info)
        if (ConnectionOwnerResolver.isValidUid(uid)) {
            TcpFlowUidIndex.note(info, uid)
            return
        }
        // Kernel often lacks the socket on the first TUN SYN — retry off the reader thread.
        if (!info.isTcpSyn || !running.get()) return
        try {
            dnsExecutor.execute {
                if (!running.get()) return@execute
                val retried = ownerResolver.resolveUidWithRetry(info)
                if (ConnectionOwnerResolver.isValidUid(retried)) {
                    TcpFlowUidIndex.note(info, retried)
                }
            }
        } catch (_: RejectedExecutionException) {
            // Pool saturated — SocksUidBridge still waits / uses last-uid fallback.
        }
    }

    private fun isDnsQueryToVpnDns(packet: ByteArray, length: Int, vpnDns: ByteArray): Boolean {
        if (length < 28) return false
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return false
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (length < ihl + 8) return false
        if (packet[9].toInt() and 0xff != PROTO_UDP) return false
        for (i in 0 until 4) {
            if (packet[16 + i] != vpnDns[i]) return false
        }
        val destPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or (packet[ihl + 3].toInt() and 0xff)
        return destPort == 53
    }

    /** Learn QNAME from outbound DNS queries (DNSCrypt divert or FakeDNS). */
    private fun snoopDnsOutbound(packet: ByteArray, length: Int) {
        val payload = udpDnsPayload(packet, length, expectDestPort53 = true) ?: return
        val parsed = DnsPacketParser.parse(packet, payload.first, payload.second) ?: return
        val qname = parsed.qname ?: return
        // Pending map by (srcPort, queryId) — 16-bit DNS IDs alone collide under load.
        if (!parsed.isResponse && parsed.queryId >= 0) {
            val ihl = (packet[0].toInt() and 0x0f) * 4
            val srcPort = ((packet[ihl].toInt() and 0xff) shl 8) or (packet[ihl + 1].toInt() and 0xff)
            val key = pendingQnameKey(srcPort, parsed.queryId)
            pendingQnames[key] = qname
            if (pendingQnames.size > PENDING_QNAME_CAP) {
                val it = pendingQnames.keys.iterator()
                var n = 0
                while (it.hasNext() && n < 64) {
                    it.next()
                    it.remove()
                    n++
                }
            }
        }
    }

    /** Learn IP→host from inbound DNS replies (hev FakeDNS → TUN). */
    private fun snoopDnsInbound(packet: ByteArray, length: Int) {
        val payload = udpDnsPayload(packet, length, expectDestPort53 = false) ?: return
        // Source port 53 = DNS response toward the client.
        val ihl = (packet[0].toInt() and 0x0f) * 4
        val srcPort = ((packet[ihl].toInt() and 0xff) shl 8) or (packet[ihl + 1].toInt() and 0xff)
        if (srcPort != 53) return
        val dstPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or (packet[ihl + 3].toInt() and 0xff)
        learnFromDnsPayload(packet, payload.first, payload.second, clientSport = dstPort)
    }

    private fun learnFromDnsPayload(buf: ByteArray, offset: Int, length: Int, clientSport: Int = -1) {
        val parsed = DnsPacketParser.parse(buf, offset, length) ?: return
        if (!parsed.isResponse) return
        val pendingKey = if (clientSport >= 0 && parsed.queryId >= 0) {
            pendingQnameKey(clientSport, parsed.queryId)
        } else {
            -1L
        }
        val host = parsed.qname
            ?: pendingQnames.remove(pendingKey)
            ?: return
        if (pendingKey >= 0) pendingQnames.remove(pendingKey)
        for (ip in parsed.aRecords) {
            DnsHostnameCache.put(ip, host)
        }
    }

    /**
     * @return Pair(dnsOffset, dnsLength) for UDP/53 payloads, or null.
     * @param expectDestPort53 true for client→resolver, false to skip dest-port check.
     */
    private fun udpDnsPayload(
        packet: ByteArray,
        length: Int,
        expectDestPort53: Boolean,
    ): Pair<Int, Int>? {
        if (length < 28) return null
        val version = (packet[0].toInt() ushr 4) and 0x0f
        if (version != 4) return null
        val ihl = (packet[0].toInt() and 0x0f) * 4
        if (length < ihl + 8) return null
        if (packet[9].toInt() and 0xff != PROTO_UDP) return null
        if (expectDestPort53) {
            val destPort = ((packet[ihl + 2].toInt() and 0xff) shl 8) or (packet[ihl + 3].toInt() and 0xff)
            if (destPort != 53) return null
        }
        val dnsOffset = ihl + 8
        val dnsLen = length - dnsOffset
        if (dnsLen < 12) return null
        return dnsOffset to dnsLen
    }

    private fun handleDnsQuery(packet: ByteArray, length: Int, tunOut: FileOutputStream) {
        if (!running.get()) return
        try {
            val ihl = (packet[0].toInt() and 0x0f) * 4
            val dnsOffset = ihl + 8
            if (length <= dnsOffset) return

            val queryLen = length - dnsOffset
            val parsedQuery = DnsPacketParser.parse(packet, dnsOffset, queryLen) ?: return
            val qname = parsedQuery.qname
            val expectId = parsedQuery.queryId
            val route = TorNetPolicy.classifyDnsQuery(qname)
            if (route == TorNetPolicy.DnsRoute.Drop) {
                Timber.d("DNS query dropped — invalid QNAME q=$qname")
                return
            }
            val useTorAutomap = route == TorNetPolicy.DnsRoute.TorAutomap
            val scratch = checkNotNull(dnsScratch.get())

            if (useTorAutomap && synthesizeOnionAutomap) {
                val host = qname ?: return
                val virtIp = OnionAutomapAllocator.ipv4ForHostname(host)
                val dnsPayload = DnsOnionAutomapReply.buildAResponse(
                    packet,
                    dnsOffset,
                    queryLen,
                    virtIp,
                ) ?: return
                learnFromDnsPayload(dnsPayload, 0, dnsPayload.size)
                val replyLen = buildDnsReplyInto(
                    request = packet,
                    requestLen = length,
                    dnsPayload = dnsPayload,
                    dnsLen = dnsPayload.size,
                    out = scratch.replyBuf,
                ) ?: return
                synchronized(tunWriteLock) {
                    if (!running.get()) return
                    tunOut.write(scratch.replyBuf, 0, replyLen)
                }
                return
            }

            if (useTorAutomap && torDnsPort <= 0) {
                Timber.d("Onion DNS dropped — Tor DNSPort not configured q=$qname")
                return
            }
            val upstreamHost = if (useTorAutomap) torDnsAddress else dnsCryptAddress
            val upstreamPort = if (useTorAutomap) torDnsPort else dnsCryptPort

            val socket = scratch.socket()
            socket.soTimeout = DNS_TIMEOUT_MS
            socket.send(
                DatagramPacket(
                    packet,
                    dnsOffset,
                    queryLen,
                    upstreamHost,
                    upstreamPort,
                ),
            )
            // Shared ThreadLocal socket can still hold a late reply from a prior timeout —
            // only accept responses whose DNS ID matches this query (prevents Automap/cache poison).
            val response = DatagramPacket(scratch.responseBuf, scratch.responseBuf.size)
            val deadlineNs = System.nanoTime() + DNS_TIMEOUT_MS * 1_000_000L
            var matched = false
            while (System.nanoTime() < deadlineNs) {
                val remainingMs = ((deadlineNs - System.nanoTime()) / 1_000_000L).coerceAtLeast(1L)
                socket.soTimeout = remainingMs.toInt().coerceAtMost(DNS_TIMEOUT_MS)
                try {
                    socket.receive(response)
                } catch (_: java.net.SocketTimeoutException) {
                    break
                }
                if (expectId < 0 || response.length < 2) continue
                val respId =
                    ((scratch.responseBuf[0].toInt() and 0xff) shl 8) or
                        (scratch.responseBuf[1].toInt() and 0xff)
                if (respId == expectId) {
                    val flags =
                        ((scratch.responseBuf[2].toInt() and 0xff) shl 8) or
                            (scratch.responseBuf[3].toInt() and 0xff)
                    if (flags and 0x8000 == 0) continue // QR
                    matched = true
                    break
                }
                Timber.d("TunDnsMux DNS id mismatch expect=$expectId got=$respId — skip stale")
            }
            if (!matched) {
                // One shorter retry on a fresh socket — total budget ≈ DNSCrypt timeout + slack.
                Timber.d("DNS forward timeout/mismatch — retry once q=$qname")
                scratch.resetSocket()
                val retrySock = scratch.socket()
                retrySock.soTimeout = DNS_RETRY_TIMEOUT_MS
                retrySock.send(
                    DatagramPacket(
                        packet,
                        dnsOffset,
                        queryLen,
                        upstreamHost,
                        upstreamPort,
                    ),
                )
                val retryDeadline = System.nanoTime() + DNS_RETRY_TIMEOUT_MS * 1_000_000L
                while (System.nanoTime() < retryDeadline) {
                    val remainingMs =
                        ((retryDeadline - System.nanoTime()) / 1_000_000L).coerceAtLeast(1L)
                    retrySock.soTimeout = remainingMs.toInt().coerceAtMost(DNS_RETRY_TIMEOUT_MS)
                    try {
                        retrySock.receive(response)
                    } catch (_: java.net.SocketTimeoutException) {
                        break
                    }
                    if (expectId < 0 || response.length < 2) continue
                    val respId =
                        ((scratch.responseBuf[0].toInt() and 0xff) shl 8) or
                            (scratch.responseBuf[1].toInt() and 0xff)
                    if (respId == expectId) {
                        val flags =
                            ((scratch.responseBuf[2].toInt() and 0xff) shl 8) or
                                (scratch.responseBuf[3].toInt() and 0xff)
                        if (flags and 0x8000 == 0) continue
                        matched = true
                        break
                    }
                }
            }
            if (!matched) {
                Timber.d("DNS forward timeout/mismatch — query dropped q=$qname")
                return
            }

            // Attribute resolved A records → QNAME from the *query* (most reliable), then
            // fall back to message/pending parse. DNSCrypt replies can omit/compress QNAME
            // in ways that previously skipped A harvest when gated on response qname.
            val parsedReply = DnsPacketParser.parse(scratch.responseBuf, 0, response.length)
            val hostForCache = qname?.takeIf { it.isNotEmpty() }
                ?: parsedReply?.qname?.takeIf { it.isNotEmpty() }
            if (hostForCache != null && parsedReply != null && parsedReply.aRecords.isNotEmpty()) {
                for (ip in parsedReply.aRecords) {
                    DnsHostnameCache.put(ip, hostForCache)
                }
            } else {
                val ihlOut = (packet[0].toInt() and 0x0f) * 4
                val clientSport =
                    ((packet[ihlOut].toInt() and 0xff) shl 8) or
                        (packet[ihlOut + 1].toInt() and 0xff)
                learnFromDnsPayload(
                    scratch.responseBuf,
                    0,
                    response.length,
                    clientSport = clientSport,
                )
            }

            val replyLen = buildDnsReplyInto(
                request = packet,
                requestLen = length,
                dnsPayload = scratch.responseBuf,
                dnsLen = response.length,
                out = scratch.replyBuf,
            ) ?: return
            synchronized(tunWriteLock) {
                if (!running.get()) return
                tunOut.write(scratch.replyBuf, 0, replyLen)
            }
        } catch (error: Exception) {
            if (running.get()) {
                when (error) {
                    is java.net.SocketTimeoutException ->
                        Timber.d("DNS forward timeout — query dropped")
                    is java.net.ConnectException ->
                        Timber.d(error, "DNS stub refused — query dropped")
                    is java.net.PortUnreachableException ->
                        Timber.d(error, "DNS port unreachable — query dropped")
                    else ->
                        Timber.d(error, "DNS forward failed — query dropped")
                }
            }
        } finally {
            // Close ThreadLocal sockets before worker threads time out (StrictMode leak).
            runCatching { dnsScratch.get()?.resetSocket() }
        }
    }

    /** @return reply length, or null if too large */
    private fun buildDnsReplyInto(
        request: ByteArray,
        requestLen: Int,
        dnsPayload: ByteArray,
        dnsLen: Int,
        out: ByteArray,
    ): Int? {
        val ihl = (request[0].toInt() and 0x0f) * 4
        val totalLen = ihl + 8 + dnsLen
        if (totalLen > MTU || dnsLen < 0 || totalLen > out.size || requestLen < ihl + 8) return null

        System.arraycopy(request, 0, out, 0, ihl)
        for (i in 0 until 4) {
            out[12 + i] = request[16 + i]
            out[16 + i] = request[12 + i]
        }
        out[10] = 0
        out[11] = 0
        out[2] = (totalLen ushr 8).toByte()
        out[3] = (totalLen and 0xff).toByte()
        val ipSum = checksum(out, 0, ihl)
        out[10] = (ipSum ushr 8).toByte()
        out[11] = (ipSum and 0xff).toByte()

        out[ihl] = request[ihl + 2]
        out[ihl + 1] = request[ihl + 3]
        out[ihl + 2] = request[ihl]
        out[ihl + 3] = request[ihl + 1]
        val udpLen = 8 + dnsLen
        out[ihl + 4] = (udpLen ushr 8).toByte()
        out[ihl + 5] = (udpLen and 0xff).toByte()
        out[ihl + 6] = 0
        out[ihl + 7] = 0

        System.arraycopy(dnsPayload, 0, out, ihl + 8, dnsLen)
        return totalLen
    }

    private fun checksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xff) shl 8) or (buf[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (buf[i].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }

    private class DnsScratch {
        val responseBuf = ByteArray(DNS_RESPONSE_CAP)
        val replyBuf = ByteArray(MTU)
        private var socket: DatagramSocket? = null

        fun socket(): DatagramSocket {
            val existing = socket
            if (existing != null && !existing.isClosed) return existing
            runCatching { existing?.close() }
            socket = null
            // Bind loopback — never let the stub pick a clearnet interface.
            return DatagramSocket(0, InetAddress.getByName(TunnelEndpoints.LOOPBACK)).also {
                it.soTimeout = DNS_TIMEOUT_MS
                socket = it
            }
        }

        fun resetSocket() {
            runCatching { socket?.close() }
            socket = null
        }
    }

    companion object {
        private const val MTU = 1280
        private const val PROTO_UDP = 17
        /**
         * Align with Arti/C Tor resolve budgets (~60s) + one short retry.
         * Arti stream resolve_timeout default was 10s (too tight vs little-t).
         */
        private const val DNS_TIMEOUT_MS = 25_000
        private const val DNS_RETRY_TIMEOUT_MS = 15_000
        private const val DNS_RESPONSE_CAP = 2048
        private const val EMPTY_READ_BASE_NS = 200_000L // 0.2ms base, exponential cap ~51ms
        private val DNS_CORE_THREADS =
            Runtime.getRuntime().availableProcessors().coerceIn(2, 4)
        private val DNS_MAX_THREADS = (DNS_CORE_THREADS + 4).coerceAtMost(8)
        private const val DNS_QUEUE_CAP = 256
        private const val PENDING_QNAME_CAP = 512

        private val dnsScratch = ThreadLocal.withInitial { DnsScratch() }

        /** (srcPort << 16 | queryId) → QNAME for FakeDNS responses that rely on query correlation. */
        private val pendingQnames =
            java.util.concurrent.ConcurrentHashMap<Long, String>(64)

        private fun pendingQnameKey(srcPort: Int, queryId: Int): Long =
            (srcPort.toLong() and 0xffffL shl 16) or (queryId.toLong() and 0xffffL)
    }
}
