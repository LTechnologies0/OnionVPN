package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.locks.LockSupport
import timber.log.Timber

/**
 * Resolves the UID that owns an outbound socket matching the TUN packet 5-tuple.
 *
 * API 29+: [ConnectivityManager.getConnectionOwnerUid] (must be called while this app's
 * [android.net.VpnService] is the active VPN — SecurityException otherwise).
 *
 * Hot path uses a **single** attempt — never parks the TUN reader thread. First SYN
 * races are acceptable as "unknown" and re-checked on the next SYN.
 *
 * Addresses are built from int IPs (no dotted-string parse) with ThreadLocal scratch bytes.
 */
class ConnectionOwnerResolver(context: Context) {
    private val appContext = context.applicationContext
    private val connectivity =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun resolveUid(info: IpPacketInfo): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val apiUid = resolveApi29Once(info)
            if (isValidUid(apiUid)) return apiUid
            // Waydroid / some OEM stacks: getConnectionOwnerUid misses while socket exists in proc.
            val procUid = resolveProcNet(info)
            if (isValidUid(procUid)) return procUid
            return apiUid
        }
        return resolveProcNet(info)
    }

    /**
     * SYN→UID races: the kernel often has not registered the socket when the first
     * TUN SYN is read. A few short retries (off the hot path when possible) recover
     * most stamps so [SocksUidBridge] does not deny Signal/WhatsApp reconnect storms.
     */
    fun resolveUidWithRetry(
        info: IpPacketInfo,
        attempts: Int = SYN_UID_RETRY,
        parkNs: Long = SYN_UID_PARK_NS,
    ): Int {
        var uid = resolveUid(info)
        if (isValidUid(uid)) return uid
        repeat((attempts - 1).coerceAtLeast(0)) {
            LockSupport.parkNanos(parkNs)
            uid = resolveUid(info)
            if (isValidUid(uid)) return uid
        }
        return uid
    }

    /**
     * UID of the peer that connected to an accepted loopback server socket (PAC SOCKS).
     * Uses the app's 5-tuple view: local=peer ephemeral, remote=listen port.
     */
    fun resolveAcceptedClientUid(client: Socket): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return Process.INVALID_UID
        }
        val peer = client.remoteSocketAddress as? InetSocketAddress ?: return Process.INVALID_UID
        val local = client.localSocketAddress as? InetSocketAddress ?: return Process.INVALID_UID
        repeat(PAC_UID_RETRY) { attempt ->
            val uid = try {
                @Suppress("NewApi")
                connectivity.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, peer, local)
            } catch (error: SecurityException) {
                Timber.w(error, "getConnectionOwnerUid denied for PAC client")
                return Process.INVALID_UID
            } catch (error: Exception) {
                Timber.w(error, "getConnectionOwnerUid failed for PAC client")
                Process.INVALID_UID
            }
            if (isValidUid(uid)) return uid
            if (attempt < PAC_UID_RETRY - 1) {
                try {
                    Thread.sleep(PAC_UID_SLEEP_MS)
                } catch (_: InterruptedException) {
                    return Process.INVALID_UID
                }
            }
        }
        // Waydroid / OEM: same miss as TUN SYN — /proc/net/tcp{,6} from client 5-tuple.
        val procUid = resolveAcceptedProcNet(peer, local)
        if (isValidUid(procUid)) return procUid
        return Process.INVALID_UID
    }

    /**
     * Proc fallback for accepted loopback TCP (ArtiSocksRoleMux / PAC SOCKS).
     * Tuple matches [getConnectionOwnerUid]: local=client ephemeral, remote=listen port.
     */
    private fun resolveAcceptedProcNet(peer: InetSocketAddress, local: InetSocketAddress): Int {
        val peerAddr = peer.address ?: return Process.INVALID_UID
        val localAddr = local.address ?: return Process.INVALID_UID
        if (!peerAddr.isLoopbackAddress || !localAddr.isLoopbackAddress) {
            return Process.INVALID_UID
        }
        return when (peerAddr.address.size) {
            4 -> {
                val info = IpPacketInfo(
                    protocol = IpPacketParser.PROTO_TCP,
                    srcIpInt = ipv4BytesToInt(peerAddr.address),
                    dstIpInt = ipv4BytesToInt(localAddr.address),
                    srcPort = peer.port,
                    dstPort = local.port,
                    isTcpSyn = false,
                    isTcp = true,
                    isUdp = false,
                )
                resolveProcNet(info)
            }
            16 -> {
                val info = IpPacketInfo(
                    protocol = IpPacketParser.PROTO_TCP,
                    srcIpInt = 0,
                    dstIpInt = 0,
                    srcPort = peer.port,
                    dstPort = local.port,
                    isTcpSyn = false,
                    isTcp = true,
                    isUdp = false,
                    ipVersion = 6,
                    srcHostOverride = peerAddr.hostAddress,
                    dstHostOverride = localAddr.hostAddress,
                )
                resolveProcNet6(info)
            }
            else -> Process.INVALID_UID
        }
    }

    private fun ipv4BytesToInt(bytes: ByteArray): Int {
        require(bytes.size == 4)
        return (bytes[0].toInt() and 0xff) or
            ((bytes[1].toInt() and 0xff) shl 8) or
            ((bytes[2].toInt() and 0xff) shl 16) or
            ((bytes[3].toInt() and 0xff) shl 24)
    }

    private fun resolveApi29Once(info: IpPacketInfo): Int {
        return try {
            val protocol = when (info.protocol) {
                IpPacketParser.PROTO_TCP -> OsConstants.IPPROTO_TCP
                IpPacketParser.PROTO_UDP -> OsConstants.IPPROTO_UDP
                else -> return Process.INVALID_UID
            }
            val local: InetSocketAddress
            val remote: InetSocketAddress
            if (info.isIpv6) {
                local = InetSocketAddress(InetAddress.getByName(info.srcIp), info.srcPort)
                remote = InetSocketAddress(InetAddress.getByName(info.dstIp), info.dstPort)
            } else {
                val scratch = addressScratch.get()
                local = socketAddress(info.srcIpInt, info.srcPort, scratch.localBytes)
                remote = socketAddress(info.dstIpInt, info.dstPort, scratch.remoteBytes)
            }
            @Suppress("NewApi")
            connectivity.getConnectionOwnerUid(protocol, local, remote)
        } catch (error: SecurityException) {
            Timber.w(error, "getConnectionOwnerUid denied — VPN not active owner?")
            Process.INVALID_UID
        } catch (error: Exception) {
            Timber.w(error, "getConnectionOwnerUid failed")
            Process.INVALID_UID
        }
    }

    private fun socketAddress(ip: Int, port: Int, bytes: ByteArray): InetSocketAddress {
        IpPacketParser.ipv4Bytes(ip, bytes)
        return InetSocketAddress(InetAddress.getByAddress(bytes), port)
    }

    private fun resolveProcNet(info: IpPacketInfo): Int {
        if (info.isIpv6) {
            return resolveProcNet6(info)
        }
        val file = when (info.protocol) {
            IpPacketParser.PROTO_TCP -> File("/proc/net/tcp")
            IpPacketParser.PROTO_UDP -> File("/proc/net/udp")
            else -> return Process.INVALID_UID
        }
        if (!file.canRead()) return Process.INVALID_UID
        val remoteHex = ipv4PortHex(info.dstIpInt, info.dstPort)
        val localHex = ipv4PortHex(info.srcIpInt, info.srcPort)
        return try {
            file.bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size < 8) return@forEach
                    val local = parts[1]
                    val remote = parts[2]
                    if (remote.equals(remoteHex, ignoreCase = true) &&
                        (local.equals(localHex, ignoreCase = true) || info.isUdp)
                    ) {
                        return@useLines parts[7].toIntOrNull() ?: Process.INVALID_UID
                    }
                }
                Process.INVALID_UID
            }
        } catch (error: Exception) {
            Timber.w(error, "proc net uid lookup failed")
            Process.INVALID_UID
        }
    }

    /** IPv6 proc fallback when API 29+ owner lookup misses (Waydroid). */
    private fun resolveProcNet6(info: IpPacketInfo): Int {
        val file = when (info.protocol) {
            IpPacketParser.PROTO_TCP -> File("/proc/net/tcp6")
            IpPacketParser.PROTO_UDP -> File("/proc/net/udp6")
            else -> return Process.INVALID_UID
        }
        if (!file.canRead()) return Process.INVALID_UID
        val remoteHex = ipv6PortHex(info.dstIp, info.dstPort)
        val localHex = ipv6PortHex(info.srcIp, info.srcPort)
        return try {
            file.bufferedReader().useLines { lines ->
                lines.drop(1).forEach { line ->
                    val parts = line.trim().split(Regex("\\s+"))
                    if (parts.size < 8) return@forEach
                    val local = parts[1]
                    val remote = parts[2]
                    if (remote.equals(remoteHex, ignoreCase = true) &&
                        (local.equals(localHex, ignoreCase = true) || info.isUdp)
                    ) {
                        return@useLines parts[7].toIntOrNull() ?: Process.INVALID_UID
                    }
                }
                Process.INVALID_UID
            }
        } catch (error: Exception) {
            Timber.w(error, "proc net6 uid lookup failed")
            Process.INVALID_UID
        }
    }

    private fun ipv6PortHex(ip: String, port: Int): String {
        val addr = InetAddress.getByName(ip)
        val bytes = addr.address
        if (bytes.size != 16) return ""
        val ipHex = buildString(32) {
            for (b in bytes) {
                append(String.format("%02X", b.toInt() and 0xff))
            }
        }
        val portHex = String.format("%04X", port)
        return "$ipHex:$portHex"
    }

    private fun ipv4PortHex(ip: Int, port: Int): String {
        val ipHex = String.format(
            "%02X%02X%02X%02X",
            ip and 0xff,
            (ip ushr 8) and 0xff,
            (ip ushr 16) and 0xff,
            (ip ushr 24) and 0xff,
        )
        val portHex = String.format("%04X", port)
        return "$ipHex:$portHex"
    }

    private class AddressScratch {
        val localBytes = ByteArray(4)
        val remoteBytes = ByteArray(4)
    }

    companion object {
        private val addressScratch = ThreadLocal.withInitial { AddressScratch() }
        private const val PAC_UID_RETRY = 5
        private const val PAC_UID_SLEEP_MS = 4L
        private const val SYN_UID_RETRY = 8
        private const val SYN_UID_PARK_NS = 2_000_000L // 2ms × 8 ≈ 16ms SYN race window

        fun isValidUid(uid: Int): Boolean =
            uid != Process.INVALID_UID && uid >= 0
    }
}
