package ltechnologies.onionphone.onionvpn.core.vpn.pac

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Chrome/Edge PAC clients probe UDP ASSOCIATE against the SOCKS bridge.
 * Rejecting without draining DST.ADDR/PORT desyncs the stream and floods
 * Broken-pipe logs — this regression covers clean 0x07 replies.
 */
class DnsCryptSocksBridgeTest {

    @Test
    fun udpAssociateIsRejectedWithCommandNotSupported() {
        val free = java.net.ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = free.localPort
        free.close()

        val underTest = DnsCryptSocksBridge(listenPort = port)
        underTest.updateUpstream(torSocks = 9_050, dnsCrypt = 9_051)
        underTest.start()
        try {
            Socket("127.0.0.1", port).use { sock ->
                sock.soTimeout = 5_000
                sock.tcpNoDelay = true
                val out = DataOutputStream(sock.getOutputStream())
                val inp = DataInputStream(sock.getInputStream())

                // Greeting: VER=5, 1 method NO AUTH
                out.writeByte(0x05)
                out.writeByte(0x01)
                out.writeByte(0x00)
                out.flush()
                assertEquals(0x05, inp.readUnsignedByte())
                assertEquals(0x00, inp.readUnsignedByte())

                // UDP ASSOCIATE to 0.0.0.0:0 (Chrome-style probe)
                out.writeByte(0x05) // ver
                out.writeByte(0x03) // UDP ASSOCIATE
                out.writeByte(0x00) // rsv
                out.writeByte(0x01) // IPv4
                out.write(byteArrayOf(0, 0, 0, 0))
                out.writeShort(0)
                out.flush()

                assertEquals(0x05, inp.readUnsignedByte())
                assertEquals(0x07, inp.readUnsignedByte()) // command not supported
                assertEquals(0x00, inp.readUnsignedByte()) // rsv
                assertEquals(0x01, inp.readUnsignedByte()) // atyp IPv4
                inp.skipBytes(4)
                assertEquals(0, inp.readUnsignedShort())
            }
        } finally {
            underTest.stop()
            // Give accept thread a moment to exit cleanly.
            TimeUnit.MILLISECONDS.sleep(50)
        }
    }

    @Test
    fun bindIsRejectedWithCommandNotSupported() {
        val free = java.net.ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = free.localPort
        free.close()

        val underTest = DnsCryptSocksBridge(listenPort = port)
        underTest.updateUpstream(9_050, 9_051)
        underTest.start()
        try {
            Socket("127.0.0.1", port).use { sock ->
                sock.soTimeout = 5_000
                val out = DataOutputStream(sock.getOutputStream())
                val inp = DataInputStream(sock.getInputStream())
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                assertEquals(0x05, inp.readUnsignedByte())
                assertEquals(0x00, inp.readUnsignedByte())

                // BIND example.com:443
                val host = "example.com".toByteArray()
                out.writeByte(0x05)
                out.writeByte(0x02) // BIND
                out.writeByte(0x00)
                out.writeByte(0x03)
                out.writeByte(host.size)
                out.write(host)
                out.writeShort(443)
                out.flush()

                assertEquals(0x05, inp.readUnsignedByte())
                val rep = inp.readUnsignedByte()
                assertEquals(0x07, rep)
                assertTrue(inp.readUnsignedByte() == 0x00)
            }
        } finally {
            underTest.stop()
            TimeUnit.MILLISECONDS.sleep(50)
        }
    }
}
