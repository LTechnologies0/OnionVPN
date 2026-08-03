package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import ltechnologies.onionphone.onionvpn.core.model.TorNetPolicy
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import ltechnologies.onionphone.onionvpn.core.model.stability.TorStabilityCodes

/**
 * Minimal SOCKS5 client with USERNAME/PASSWORD auth (RFC 1928 / 1929).
 * Used for IsolateSOCKSAuth tokens (path-spec strong isolation).
 * SOCKS reply codes use [TorStabilityCodes.SocksReply] (RFC 1928 + Tor F0–F7).
 *
 * Also supports Tor’s SOCKS `RESOLVE` (0xF0) extension used by C Tor / Arti /
 * onionmasq sidecar (`TorClient::resolve`).
 */
class Socks5Client(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val username: String,
    private val password: String,
    private val connectTimeoutMs: Int = 20_000,
    /**
     * Bound for SOCKS greeting/auth/CONNECT reply.
     * Must stay ≥ Tor [SocksTimeout] (default 120s) — aborting earlier causes false
     * ECONNRESET while little-t is still attaching a circuit (Tor man + forum.torproject).
     */
    private val handshakeTimeoutMs: Int = 120_000,
    private val protect: ((Socket) -> Boolean)? = null,
) {
    fun connect(destHost: String, destPort: Int): Socket {
        val socket = openAuthedSocket()
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())
        try {
            writeDestinationRequest(output, CMD_CONNECT, destHost, destPort)
            readSocksReply(input, "CONNECT")
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw wrapHandshake(e)
        }
        // Streaming payload — no idle read deadline on the tunnel pipe.
        socket.soTimeout = 0
        return socket
    }

    /**
     * Tor SOCKS extension: resolve [hostname] over Tor without opening a stream.
     * Returns the first IPv4/IPv6 from the SOCKS reply (BND.ADDR).
     */
    fun resolve(hostname: String): InetAddress {
        if (!TorNetPolicy.isValidSocksDestination(hostname)) {
            throw IOException("SOCKS5 RESOLVE invalid hostname")
        }
        if (TunnelEndpoints.parseIpv4Literal(hostname) != null || hostname.indexOf(':') >= 0) {
            return InetAddress.getByName(hostname)
        }
        openAuthedSocket().use { socket ->
            val input = DataInputStream(socket.getInputStream())
            val output = DataOutputStream(socket.getOutputStream())
            try {
                writeDestinationRequest(output, CMD_RESOLVE, hostname, destPort = 0)
                return readResolveReply(input)
            } catch (e: Exception) {
                throw wrapHandshake(e)
            }
        }
    }

    private fun openAuthedSocket(): Socket {
        val socket = Socket()
        val protectedOk = protect?.invoke(socket) ?: true
        if (!protectedOk && !isLoopback(proxyHost)) {
            runCatching { socket.close() }
            throw IOException("VpnService.protect failed for SOCKS $proxyHost:$proxyPort")
        }
        socket.tcpNoDelay = true
        socket.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)
        socket.soTimeout = handshakeTimeoutMs
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())

        require(username.isNotBlank() && password.isNotBlank()) {
            "SOCKS5 username/password required for IsolateSOCKSAuth"
        }
        try {
            output.write(byteArrayOf(0x05, 0x01, 0x02))
            output.flush()
            val ver = input.readUnsignedByte()
            val method = input.readUnsignedByte()
            if (ver != 0x05 || method != 0x02) {
                throw IOException("SOCKS5 auth method rejected ver=$ver method=$method")
            }

            val userBytes = username.toByteArray(StandardCharsets.UTF_8)
            val passBytes = password.toByteArray(StandardCharsets.UTF_8)
            if (userBytes.size > 255 || passBytes.size > 255) {
                throw IOException("SOCKS5 credentials too long")
            }
            output.writeByte(0x01)
            output.writeByte(userBytes.size)
            output.write(userBytes)
            output.writeByte(passBytes.size)
            output.write(passBytes)
            output.flush()
            val authVer = input.readUnsignedByte()
            val authStatus = input.readUnsignedByte()
            if (authVer != 0x01 || authStatus != 0x00) {
                throw IOException("SOCKS5 username/password rejected")
            }
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw wrapHandshake(e)
        }
        return socket
    }

    private fun writeDestinationRequest(
        output: DataOutputStream,
        command: Int,
        destHost: String,
        destPort: Int,
    ) {
        if (command == CMD_CONNECT) {
            if (!TorNetPolicy.isValidSocksDestination(destHost) || !TorNetPolicy.isValidPort(destPort)) {
                throw IOException("SOCKS5 invalid destination")
            }
        }
        val hostBytes = destHost.toByteArray(StandardCharsets.UTF_8)
        val isIpv4 = TunnelEndpoints.parseIpv4Literal(destHost) != null
        val isIpv6 = !isIpv4 && destHost.indexOf(':') >= 0
        output.writeByte(0x05)
        output.writeByte(command)
        output.writeByte(0x00)
        when {
            isIpv4 -> {
                output.writeByte(0x01)
                output.write(InetAddress.getByName(destHost).address)
            }
            isIpv6 -> {
                val addr = InetAddress.getByName(destHost).address
                if (addr.size != 16) {
                    throw IOException("SOCKS5 IPv6 address length ${addr.size}")
                }
                output.writeByte(0x04)
                output.write(addr)
            }
            else -> {
                if (hostBytes.size > 255) {
                    throw IOException("SOCKS5 hostname too long")
                }
                output.writeByte(0x03)
                output.writeByte(hostBytes.size)
                output.write(hostBytes)
            }
        }
        output.writeShort(destPort)
        output.flush()
    }

    private fun readSocksReply(input: DataInputStream, op: String) {
        val respVer = input.readUnsignedByte()
        val respStatus = input.readUnsignedByte()
        input.readUnsignedByte() // reserved
        val atyp = input.readUnsignedByte()
        when (atyp) {
            0x01 -> input.skipBytes(4)
            0x03 -> {
                val n = input.readUnsignedByte()
                input.skipBytes(n)
            }
            0x04 -> input.skipBytes(16)
            else -> throw IOException("SOCKS5 bad atyp=$atyp")
        }
        input.skipBytes(2) // bind port
        if (respVer != 0x05 || respStatus != 0x00) {
            val signal = TorStabilityCodes.SocksReply.signalFor(respStatus)
            throw IOException(
                "SOCKS5 $op failed status=$respStatus (${signal.detail.ifBlank { signal.code }})",
            )
        }
    }

    private fun readResolveReply(input: DataInputStream): InetAddress {
        val respVer = input.readUnsignedByte()
        val respStatus = input.readUnsignedByte()
        input.readUnsignedByte() // reserved
        val atyp = input.readUnsignedByte()
        val addr: InetAddress = when (atyp) {
            0x01 -> {
                val raw = ByteArray(4)
                input.readFully(raw)
                InetAddress.getByAddress(raw)
            }
            0x04 -> {
                val raw = ByteArray(16)
                input.readFully(raw)
                InetAddress.getByAddress(raw)
            }
            0x03 -> {
                val n = input.readUnsignedByte()
                input.skipBytes(n)
                throw IOException("SOCKS5 RESOLVE returned hostname (expected IP)")
            }
            else -> throw IOException("SOCKS5 RESOLVE bad atyp=$atyp")
        }
        input.skipBytes(2) // bind port
        if (respVer != 0x05 || respStatus != 0x00) {
            val signal = TorStabilityCodes.SocksReply.signalFor(respStatus)
            throw IOException(
                "SOCKS5 RESOLVE failed status=$respStatus (${signal.detail.ifBlank { signal.code }})",
            )
        }
        return addr
    }

    private fun wrapHandshake(e: Exception): IOException {
        if (e is java.net.SocketTimeoutException) {
            return IOException(
                "SOCKS5 handshake timed out after ${handshakeTimeoutMs}ms " +
                    "(cold circuit / congested Tor)",
                e,
            )
        }
        if (e is IOException) return e
        return IOException("SOCKS5 handshake failed: ${e.message}", e)
    }

    companion object {
        /** RFC 1928 CONNECT. */
        const val CMD_CONNECT = 0x01
        /** Tor extension: hostname → IP via Tor (`TorClient::resolve` / C Tor RESOLVE). */
        const val CMD_RESOLVE = 0xF0

        private fun isLoopback(host: String): Boolean =
            host == "127.0.0.1" || host.equals("localhost", ignoreCase = true) ||
                host == "::1" || host == TunnelEndpoints.LOOPBACK
    }
}
