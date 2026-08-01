package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.TunnelFailure
import ltechnologies.onionphone.onionvpn.core.model.observability.OpTrace
import ltechnologies.onionphone.onionvpn.core.model.stability.ProcessLogLevel
import ltechnologies.onionphone.onionvpn.core.vpn.profile.TunForwarder
import timber.log.Timber

/**
 * Routes TUN TCP through hev-socks5-tunnel → [SocksUidBridge] → Tor apps SocksPort.
 *
 * hev provides the native TCP stack; the bridge adds per-UID IsolateSOCKSAuth (`u{uid}`).
 * DNS: [TunDnsMux] divert to DNSCrypt / Tor Automap (UDP blackhole otherwise).
 */
class HevSocks5TunForwarder(
    private val context: Context,
    private val dnsMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    private val protectSocket: ((Socket) -> Boolean)? = null,
    private val onFatal: ((Throwable) -> Unit)? = null,
) : TunForwarder {
    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(supervisor + Dispatchers.IO)
    private val worker = AtomicReference<Job?>(null)
    private var tunDup: ParcelFileDescriptor? = null
    private var dnsMux: TunDnsMux? = null
    private var uidBridge: SocksUidBridge? = null

    override fun start(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
        synthesizeOnionAutomap: Boolean,
    ) {
        OpTrace.step("hev", "start socks=$socksPort dnsCrypt=$dnsCryptPort", ProcessLogLevel.INFO) {
            stop()
            if (dnsMode != DnsResolverMode.DNSCRYPT_MUX) {
                OpTrace.info("hev", "dnsMode=$dnsMode coerced to DNSCRYPT_MUX divert")
                Timber.i("dnsMode=$dnsMode coerced to DNSCRYPT_MUX divert (FakeDNS disabled)")
            }
            startWithMux(
                tunFd = tunFd,
                torSocksPort = socksPort,
                dnsCryptPort = dnsCryptPort,
                torDnsPort = torDnsPort,
                useMapDns = false,
                divertDns = true,
                synthesizeOnionAutomap = synthesizeOnionAutomap,
            )
        }
    }

    private fun startWithMux(
        tunFd: ParcelFileDescriptor,
        torSocksPort: Int,
        dnsCryptPort: Int,
        torDnsPort: Int,
        useMapDns: Boolean,
        divertDns: Boolean,
        synthesizeOnionAutomap: Boolean = false,
    ) {
        // Bridge before hev so the first SOCKS CONNECT never hits a closed port.
        val bridge = SocksUidBridge(
            context = context,
            protectSocket = protectSocket,
            onFatal = onFatal,
        )
        bridge.start(torSocks = torSocksPort)
        uidBridge = bridge

        val pair = createPacketSocketPair()
        val hevEnd = pair[0]
        val muxEnd = pair[1]
        tunDup = hevEnd

        val bridgeHost = TunnelEndpoints.LOOPBACK
        val bridgePort = TunnelEndpoints.SOCKS_UID_BRIDGE_PORT
        val job = scope.launch {
            val configFile = File(context.filesDir, "hev-socks5-tunnel.yaml")
            configFile.writeText(buildConfig(bridgeHost, bridgePort, useMapDns = useMapDns))
            Timber.i(
                "Starting hev-socks5-tunnel (mux/dgram) on fd=${hevEnd.fd} " +
                    "bridge=$bridgeHost:$bridgePort torSocks=$torSocksPort " +
                    "dnscrypt=$dnsCryptPort torDns=$torDnsPort mapdns=$useMapDns divertDns=$divertDns",
            )
            try {
                hev.sockstun.TProxyService.TProxyStartService(configFile.absolutePath, hevEnd.fd)
            } catch (error: Exception) {
                Timber.e(error, "hev-socks5-tunnel (mux) exited")
                onFatal?.invoke(
                    TunnelFailure.ForwarderDead(
                        "hev-socks5-tunnel exited: ${error.message}",
                        error,
                    ),
                )
            }
        }
        worker.set(job)

        val mux = TunDnsMux(
            context = context,
            tunFd = tunFd.dup(),
            hevFd = muxEnd,
            dnsCryptHost = TunnelEndpoints.LOOPBACK,
            dnsCryptPort = dnsCryptPort,
            vpnDnsAddress = TunnelEndpoints.VPN_DNS_ADDRESS,
            divertDnsToDnsCrypt = divertDns,
            torDnsHost = TunnelEndpoints.LOOPBACK,
            torDnsPort = torDnsPort,
            synthesizeOnionAutomap = synthesizeOnionAutomap,
            onFatal = { error ->
                Timber.e(error, "TunDnsMux died")
                onFatal?.invoke(error)
            },
        )
        dnsMux = mux
        mux.start()
    }

    override fun stop() {
        OpTrace.debug("hev", "stop")
        dnsMux?.stop()
        dnsMux = null
        try {
            hev.sockstun.TProxyService.TProxyStopService()
        } catch (error: Exception) {
            OpTrace.warn("hev", "Failed to stop hev-socks5-tunnel", error)
            Timber.w(error, "Failed to stop hev-socks5-tunnel")
        }
        worker.getAndSet(null)?.cancel()
        supervisor.cancelChildren()
        uidBridge?.stop()
        uidBridge = null
        tunDup?.close()
        tunDup = null
    }

    private fun buildConfig(socksHost: String, socksPort: Int, useMapDns: Boolean): String = buildString {
        appendLine("tunnel:")
        appendLine("  mtu: ${TunnelEndpoints.VPN_MTU}")
        appendLine("  ipv4: ${TunnelEndpoints.VPN_CLIENT_ADDRESS}")
        appendLine("  ipv6: '${TunnelEndpoints.VPN_CLIENT_ADDRESS_V6}'")
        appendLine("  icmp: 'off'")
        appendLine("socks5:")
        appendLine("  port: $socksPort")
        appendLine("  address: '$socksHost'")
        appendLine("  udp: 'tcp'")
        // No username — SocksUidBridge accepts NO AUTH and adds u{uid} toward Tor.
        if (useMapDns) {
            appendLine("mapdns:")
            appendLine("  address: ${TunnelEndpoints.VPN_DNS_ADDRESS}")
            appendLine("  port: 53")
            appendLine("  network: ${TunnelEndpoints.FAKE_DNS_NETWORK}")
            appendLine("  netmask: ${TunnelEndpoints.FAKE_DNS_NETMASK}")
            appendLine("  cache-size: ${TunnelEndpoints.FAKE_DNS_CACHE_SIZE}")
        }
        appendLine("misc:")
        appendLine("  log-level: warn")
        appendLine("  tcp-read-write-timeout: 300000")
        appendLine("  udp-read-write-timeout: 60000")
    }

    companion object {
        /**
         * Packet-oriented mux↔hev link.
         *
         * Must stay SOCK_DGRAM: hev-socks5-tunnel treats the VPN fd as a datagram TUN
         * (one write = one IP packet). SOCK_SEQPACKET broke payload forward after SOCKS
         * CONNECT (Speedtest: CONNECT ok, zero pipe first-bytes, Read/SSL timeouts).
         */
        fun createPacketSocketPair(): Array<ParcelFileDescriptor> {
            val fd0 = FileDescriptor()
            val fd1 = FileDescriptor()
            try {
                Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, fd0, fd1)
            } catch (error: ErrnoException) {
                throw TunnelFailure.ForwarderDead(
                    "socketpair failed errno=${error.errno}: ${error.message}",
                    error,
                )
            }
            runCatching {
                // 4 MiB each side — parallel CDN flows (Speedtest/OneTrust) need headroom
                // so a full DGRAM queue does not drop TLS records.
                val buf = 4 * 1024 * 1024
                Os.setsockoptInt(fd0, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, buf)
                Os.setsockoptInt(fd0, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, buf)
                Os.setsockoptInt(fd1, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, buf)
                Os.setsockoptInt(fd1, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, buf)
            }
            val left = ParcelFileDescriptor.dup(fd0)
            val right = ParcelFileDescriptor.dup(fd1)
            runCatching { Os.close(fd0) }
            runCatching { Os.close(fd1) }
            return arrayOf(left, right)
        }
    }
}
