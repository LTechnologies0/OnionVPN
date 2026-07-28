package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
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
import ltechnologies.onionphone.onionvpn.core.vpn.profile.TunForwarder
import timber.log.Timber

/**
 * Routes TUN traffic through Tor SOCKS using hev-socks5-tunnel.
 *
 * - [DnsResolverMode.FAKE_IP_SOCKS5A]: hev mapdns FakeDNS on [TunnelEndpoints.VPN_DNS_ADDRESS]:53
 * - [DnsResolverMode.DNSCRYPT_MUX]: no mapdns — DNS handled by [TunDnsMux] toward DNSCrypt
 */
class HevSocks5TunForwarder(
    private val context: Context,
    private val dnsMode: DnsResolverMode = DnsResolverMode.DNSCRYPT_MUX,
    private val onFatal: ((Throwable) -> Unit)? = null,
) : TunForwarder {
    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(supervisor + Dispatchers.IO)
    private val worker = AtomicReference<Job?>(null)
    private var tunDup: ParcelFileDescriptor? = null
    private var dnsMux: TunDnsMux? = null

    override fun start(tunFd: ParcelFileDescriptor, socksHost: String, socksPort: Int, dnsCryptPort: Int) {
        stop()
        // Always mux TUN↔hev so PacketFirewall can inspect both DNSCRYPT_MUX and FakeDNS paths.
        val useMapDns = dnsMode == DnsResolverMode.FAKE_IP_SOCKS5A
        val divertDns = dnsMode == DnsResolverMode.DNSCRYPT_MUX
        startWithMux(tunFd, socksHost, socksPort, dnsCryptPort, useMapDns, divertDns)
    }

    private fun startWithMux(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
        useMapDns: Boolean,
        divertDns: Boolean,
    ) {
        // SOCK_DGRAM (not STREAM): preserve IP packet boundaries for hev.
        val pair = createPacketSocketPair()
        val hevEnd = pair[0]
        val muxEnd = pair[1]
        tunDup = hevEnd

        val job = scope.launch {
            val configFile = File(context.filesDir, "hev-socks5-tunnel.yaml")
            configFile.writeText(buildConfig(socksHost, socksPort, useMapDns = useMapDns))
            Timber.i(
                "Starting hev-socks5-tunnel (mux/dgram) on fd=${hevEnd.fd} " +
                    "socks=$socksPort dnscrypt=$dnsCryptPort mapdns=$useMapDns divertDns=$divertDns",
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
            tunFd = tunFd.dup(),
            hevFd = muxEnd,
            dnsCryptHost = TunnelEndpoints.LOOPBACK,
            dnsCryptPort = dnsCryptPort,
            vpnDnsAddress = TunnelEndpoints.VPN_DNS_ADDRESS,
            divertDnsToDnsCrypt = divertDns,
            onFatal = { error ->
                Timber.e(error, "TunDnsMux died")
                onFatal?.invoke(error)
            },
        )
        dnsMux = mux
        mux.start()
    }

    override fun stop() {
        dnsMux?.stop()
        dnsMux = null
        try {
            hev.sockstun.TProxyService.TProxyStopService()
        } catch (error: Exception) {
            Timber.w(error, "Failed to stop hev-socks5-tunnel")
        }
        worker.getAndSet(null)?.cancel()
        // Cancel children; keep supervisor alive for subsequent start().
        supervisor.cancelChildren()
        tunDup?.close()
        tunDup = null
    }

    private fun buildConfig(socksHost: String, socksPort: Int, useMapDns: Boolean): String = buildString {
        appendLine("tunnel:")
        appendLine("  mtu: ${TunnelEndpoints.VPN_MTU}")
        appendLine("  ipv4: ${TunnelEndpoints.VPN_CLIENT_ADDRESS}")
        // Orbot: declare IPv6 on hev so ::/0 packets entering the TUN are handled
        // (SOCKS or drop) instead of ignored / leaked.
        appendLine("  ipv6: '${TunnelEndpoints.VPN_CLIENT_ADDRESS_V6}'")
        // Tor VPN threat model: ICMP/ping is not useful over Tor and can fingerprint.
        appendLine("  icmp: 'off'")
        appendLine("socks5:")
        appendLine("  port: $socksPort")
        appendLine("  address: '$socksHost'")
        // Force UDP associate over TCP — no clearnet UDP side-channel.
        appendLine("  udp: 'tcp'")
        // Shared IsolateSOCKSAuth token (hev has no per-stream auth).
        // Circuit diversity for apps comes from TorStreamIsolationMode on the
        // apps SocksPort + MaxCircuitDirtiness — not from this static credential.
        appendLine("  username: '${TunnelEndpoints.SOCKS_ISOLATION_USER}'")
        appendLine("  password: '${TunnelEndpoints.SOCKS_ISOLATION_PASS}'")
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
         * Datagram socketpair so each TUN IP packet stays a discrete message
         * (SOCK_STREAM coalesces packets and breaks hev).
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
                val buf = 1024 * 1024
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
