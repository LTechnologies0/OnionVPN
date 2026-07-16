package ltechnologies.onionphone.onionvpn.core.vpn

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileDescriptor
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import ltechnologies.onionphone.onionvpn.core.model.DnsResolverMode
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
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
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val worker = AtomicReference<Job?>(null)
    private var tunDup: ParcelFileDescriptor? = null
    private var dnsMux: TunDnsMux? = null

    override fun start(tunFd: ParcelFileDescriptor, socksHost: String, socksPort: Int, dnsCryptPort: Int) {
        stop()
        when (dnsMode) {
            DnsResolverMode.DNSCRYPT_MUX -> startWithDnsMux(tunFd, socksHost, socksPort, dnsCryptPort)
            DnsResolverMode.FAKE_IP_SOCKS5A -> startDirect(tunFd, socksHost, socksPort, useMapDns = true)
        }
    }

    private fun startDirect(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        useMapDns: Boolean,
    ) {
        val dup = tunFd.dup()
        val fd = dup.fd
        tunDup = dup
        val job = scope.launch {
            val configFile = File(context.filesDir, "hev-socks5-tunnel.yaml")
            configFile.writeText(buildConfig(socksHost, socksPort, useMapDns = useMapDns))
            Timber.i(
                "Starting hev-socks5-tunnel on fd=$fd socks=$socksPort mapdns=$useMapDns mode=$dnsMode",
            )
            try {
                hev.sockstun.TProxyService.TProxyStartService(configFile.absolutePath, fd)
            } catch (error: Exception) {
                Timber.e(error, "hev-socks5-tunnel exited")
                onFatal?.invoke(error)
            }
        }
        worker.set(job)
    }

    private fun startWithDnsMux(
        tunFd: ParcelFileDescriptor,
        socksHost: String,
        socksPort: Int,
        dnsCryptPort: Int,
    ) {
        // SOCK_DGRAM (not STREAM): preserve IP packet boundaries for hev.
        val pair = createPacketSocketPair()
        val hevEnd = pair[0]
        val muxEnd = pair[1]
        tunDup = hevEnd

        val job = scope.launch {
            val configFile = File(context.filesDir, "hev-socks5-tunnel.yaml")
            configFile.writeText(buildConfig(socksHost, socksPort, useMapDns = false))
            Timber.i(
                "Starting hev-socks5-tunnel (mux/dgram) on fd=${hevEnd.fd} socks=$socksPort dnscrypt=$dnsCryptPort",
            )
            try {
                hev.sockstun.TProxyService.TProxyStartService(configFile.absolutePath, hevEnd.fd)
            } catch (error: Exception) {
                Timber.e(error, "hev-socks5-tunnel (mux) exited")
                onFatal?.invoke(error)
            }
        }
        worker.set(job)

        val mux = TunDnsMux(
            tunFd = tunFd.dup(),
            hevFd = muxEnd,
            dnsCryptHost = TunnelEndpoints.LOOPBACK,
            dnsCryptPort = dnsCryptPort,
            vpnDnsAddress = TunnelEndpoints.VPN_DNS_ADDRESS,
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
        // IsolateSOCKSAuth: dedicated Tor circuits for OnionVPN's SOCKS stream.
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
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, fd0, fd1)
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
