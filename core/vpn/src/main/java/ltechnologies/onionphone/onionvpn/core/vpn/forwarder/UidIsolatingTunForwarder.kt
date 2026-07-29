package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.LockSupport
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.vpn.dns.DnsHostnameCache
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.ConnectionOwnerResolver
import ltechnologies.onionphone.onionvpn.core.vpn.firewall.IpPacketParser
import ltechnologies.onionphone.onionvpn.core.vpn.profile.TunForwarder
import timber.log.Timber

/**
 * TUN → Tor SOCKS forwarder with **per-app** IsolateSOCKSAuth tokens (`u{uid}` / `p{uid}`).
 *
 * Clearnet DNS → DNSCrypt; `.onion`/`.exit` → Tor DNSPort Automap → SOCKS5A.
 * Non-DNS UDP / QUIC / STUN / WebRTC are blackholed (force TCP fallback; Tor TCP-only).
 */
class UidIsolatingTunForwarder(
    private val context: Context,
    @Suppress("UNUSED_PARAMETER") dnsMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    private val protectSocket: ((Socket) -> Boolean)? = null,
    private val onFatal: ((Throwable) -> Unit)? = null,
) : TunForwarder {
    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(supervisor + Dispatchers.IO)
    private val ownerResolver = ConnectionOwnerResolver(context)
    private val sessions = ConcurrentHashMap<Long, TcpTunSession>()
    private val running = AtomicBoolean(false)

    private var tunDup: ParcelFileDescriptor? = null
    private var dnsMux: TunDnsMux? = null
    private var engineIn: FileInputStream? = null
    private var engineOut: FileOutputStream? = null
    private var engineThread: Thread? = null
    private val tunWriteLock = Any()

    override fun start(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
    ) {
        stop()
        val pair = HevSocks5TunForwarder.createPacketSocketPair()
        val engineEnd = pair[0]
        val muxEnd = pair[1]
        tunDup = engineEnd

        dnsMux = TunDnsMux(
            tunFd = tunFd.dup(),
            hevFd = muxEnd,
            dnsCryptHost = TunnelEndpoints.LOOPBACK,
            dnsCryptPort = dnsCryptPort,
            vpnDnsAddress = TunnelEndpoints.VPN_DNS_ADDRESS,
            divertDnsToDnsCrypt = true,
            torDnsHost = TunnelEndpoints.LOOPBACK,
            torDnsPort = torDnsPort,
            onFatal = { error ->
                Timber.e(error, "TunDnsMux died")
                onFatal?.invoke(error)
            },
        ).also { it.start() }

        running.set(true)
        val localIn = FileInputStream(engineEnd.fileDescriptor)
        val localOut = FileOutputStream(engineEnd.fileDescriptor)
        engineIn = localIn
        engineOut = localOut

        engineThread = Thread({
            val buf = ByteArray(TunnelEndpoints.VPN_MTU)
            try {
                while (running.get()) {
                    val n = localIn.read(buf)
                    when {
                        n < 0 -> break
                        n == 0 -> {
                            LockSupport.parkNanos(50_000L)
                            continue
                        }
                        else -> handleIpPacket(buf, n, socksHost, socksPort)
                    }
                }
            } catch (error: Exception) {
                if (running.get()) {
                    Timber.e(error, "UidIsolatingTunForwarder stopped")
                    onFatal?.invoke(
                        TunnelFailure.ForwarderDead(
                            "UID SOCKS forwarder exited: ${error.message}",
                            error,
                        ),
                    )
                }
            }
        }, "onionvpn-uid-socks").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
            start()
        }

        Timber.i(
            "UidIsolatingTunForwarder started socks=$socksPort " +
                "dnsCrypt=$dnsCryptPort torDns=$torDnsPort divertDns=true",
        )
    }

    override fun stop() {
        running.set(false)
        sessions.values.toList().forEach { it.close(sendRst = true) }
        sessions.clear()
        engineThread?.interrupt()
        engineThread = null
        runCatching { engineIn?.close() }
        runCatching { engineOut?.close() }
        engineIn = null
        engineOut = null
        dnsMux?.stop()
        dnsMux = null
        supervisor.cancelChildren()
        tunDup?.close()
        tunDup = null
    }

    private fun handleIpPacket(buf: ByteArray, length: Int, socksHost: String, socksPort: Int) {
        if (LeakPacketFilter.shouldDropEarly(buf, length)) {
            LeakPacketFilter.noteBlackhole(LeakPacketFilter.classifyBlackholeReason(buf, length))
            return
        }
        if (LeakPacketFilter.shouldBlackholeUdp(buf, length)) {
            LeakPacketFilter.noteBlackhole(LeakPacketFilter.classifyBlackholeReason(buf, length))
            return
        }
        if (!LeakPacketFilter.isTorrifiableIpv4Tcp(buf, length)) {
            LeakPacketFilter.noteBlackhole(LeakPacketFilter.classifyBlackholeReason(buf, length))
            return
        }
        val meta = TcpPacketBuilder.parseTcpMeta(buf, length) ?: return
        val key = TcpTunSession.flowKey(meta.srcIp, meta.srcPort, meta.dstIp, meta.dstPort)
        var session = sessions[key]
        if (session == null) {
            if (!meta.synOnly) return
            val destIp = TcpTunSession.formatIpv4(meta.dstIp)
            val remoteHost = resolveSocksDestHost(destIp) ?: run {
                Timber.d("Drop SYN to Automap IP without hostname $destIp:${meta.dstPort}")
                return
            }
            val info = IpPacketParser.parse(buf, length)
            val uid = info?.let { ownerResolver.resolveUid(it) } ?: Process.INVALID_UID
            // Never IsolateSOCKSAuth as uunknown — wait for owner (matches firewall fail-closed).
            if (!ConnectionOwnerResolver.isValidUid(uid)) {
                Timber.d("Drop SYN — UID not resolved yet ${destIp}:${meta.dstPort}")
                return
            }
            val user = TunnelEndpoints.socksUserForUid(uid)
            val pass = TunnelEndpoints.socksPassForUid(uid)
            session = TcpTunSession(
                key = key,
                clientIp = meta.srcIp,
                clientPort = meta.srcPort,
                remoteIp = meta.dstIp,
                remotePort = meta.dstPort,
                remoteHost = remoteHost,
                uid = uid,
                socksHost = socksHost,
                socksPort = socksPort,
                socksUser = user,
                socksPass = pass,
                protect = protectSocket,
                writeToTun = { pkt -> writeEngine(pkt) },
                onClosed = { s -> sessions.remove(s.key, s) },
            )
            sessions[key] = session
            Timber.d("TCP session uid=$uid $user → $remoteHost:${meta.dstPort} ($destIp)")
        }
        session.handlePacket(buf, meta)
    }

    private fun writeEngine(packet: ByteArray) {
        val out = engineOut ?: return
        synchronized(tunWriteLock) {
            try {
                out.write(packet)
            } catch (e: Exception) {
                Timber.d(e, "writeEngine failed")
            }
        }
    }

    /**
     * Automap virtual IPs must SOCKS5A the `.onion`/`.exit` hostname learned from DNSPort.
     * Never CONNECT the fake IP (would try an exit / fail SafeSocks).
     */
    private fun resolveSocksDestHost(destIp: String): String? {
        if (!TunnelEndpoints.isAutomapVirtualIpv4(destIp)) return destIp
        val host = DnsHostnameCache.lookup(destIp) ?: return null
        return if (TunnelEndpoints.isOnionLikeHostname(host)) host else null
    }
}
