package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import ltechnologies.onionphone.onionvpn.core.model.stability.TorStabilityCodes

/**
 * Minimal SOCKS5 client with USERNAME/PASSWORD auth (RFC 1928 / 1929).
 * Used for IsolateSOCKSAuth tokens (path-spec strong isolation).
 * SOCKS reply codes use [TorStabilityCodes.SocksReply] (RFC 1928 + Tor F0–F7).
 */
class Socks5Client(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val username: String,
    private val password: String,
    private val connectTimeoutMs: Int = 20_000,
    private val protect: ((Socket) -> Boolean)? = null,
) {
    fun connect(destHost: String, destPort: Int): Socket {
        val socket = Socket()
        protect?.invoke(socket)
        socket.tcpNoDelay = true
        socket.soTimeout = 0
        socket.connect(InetSocketAddress(proxyHost, proxyPort), connectTimeoutMs)
        val input = DataInputStream(socket.getInputStream())
        val output = DataOutputStream(socket.getOutputStream())

        // Greeting: offer USERNAME/PASSWORD only (RFC 1929) — never anonymous SOCKS.
        // Tor IsolateSOCKSAuth needs a non-empty token for per-app circuit attribution.
        require(username.isNotBlank() && password.isNotBlank()) {
            "SOCKS5 username/password required for IsolateSOCKSAuth"
        }
        output.write(byteArrayOf(0x05, 0x01, 0x02))
        output.flush()
        val ver = input.readUnsignedByte()
        val method = input.readUnsignedByte()
        if (ver != 0x05 || method != 0x02) {
            socket.close()
            throw IOException("SOCKS5 auth method rejected ver=$ver method=$method")
        }

        val userBytes = username.toByteArray(StandardCharsets.UTF_8)
        val passBytes = password.toByteArray(StandardCharsets.UTF_8)
        if (userBytes.size > 255 || passBytes.size > 255) {
            socket.close()
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
            socket.close()
            throw IOException("SOCKS5 username/password rejected")
        }

        // CONNECT
        val hostBytes = destHost.toByteArray(StandardCharsets.UTF_8)
        val isIpv4 = destHost.matches(IPV4_REGEX)
        output.writeByte(0x05)
        output.writeByte(0x01) // CONNECT
        output.writeByte(0x00)
        if (isIpv4) {
            output.writeByte(0x01)
            output.write(InetAddress.getByName(destHost).address)
        } else {
            if (hostBytes.size > 255) {
                socket.close()
                throw IOException("SOCKS5 hostname too long")
            }
            output.writeByte(0x03)
            output.writeByte(hostBytes.size)
            output.write(hostBytes)
        }
        output.writeShort(destPort)
        output.flush()

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
            else -> {
                socket.close()
                throw IOException("SOCKS5 bad atyp=$atyp")
            }
        }
        input.skipBytes(2) // bind port
        if (respVer != 0x05 || respStatus != 0x00) {
            socket.close()
            val signal = TorStabilityCodes.SocksReply.signalFor(respStatus)
            throw IOException(
                "SOCKS5 CONNECT failed status=$respStatus (${signal.detail.ifBlank { signal.code }})",
            )
        }
        return socket
    }

    companion object {
        private val IPV4_REGEX = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
    }
}
