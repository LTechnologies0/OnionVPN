package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class SocksAuthInjectingRelayTest {
    @Test
    fun acceptNoAuthConnect_parsesIpv4Connect() {
        val greetingAndConnect = byteArrayOf(
            0x05, 0x01, 0x00,
            0x05, 0x01, 0x00, 0x01,
            203.toByte(), 0x00, 113.toByte(), 0x0A,
            0x01, 0xBB.toByte(), // 443
        )
        val input = DataInputStream(ByteArrayInputStream(greetingAndConnect))
        val replyBuf = ByteArrayOutputStream()
        val output = DataOutputStream(replyBuf)

        val dest = SocksAuthInjectingRelay.acceptNoAuthConnect(input, output)

        assertEquals("203.0.113.10", dest.host)
        assertEquals(443, dest.port)
        assertTrue(replyBuf.toByteArray().contentEquals(byteArrayOf(0x05, 0x00)))
    }

    @Test
    fun acceptNoAuthConnect_parsesDomainConnect() {
        val host = "vpn.example.com"
        val hostBytes = host.toByteArray(Charsets.UTF_8)
        val buf = ByteArrayOutputStream()
        buf.write(byteArrayOf(0x05, 0x02, 0x00, 0x02)) // offers NO AUTH + USER/PASS → prefer NO AUTH
        buf.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hostBytes.size.toByte()))
        buf.write(hostBytes)
        buf.write(byteArrayOf(0x04, 0x73)) // port 1139
        val input = DataInputStream(ByteArrayInputStream(buf.toByteArray()))
        val replyBuf = ByteArrayOutputStream()

        val dest = SocksAuthInjectingRelay.acceptNoAuthConnect(
            input,
            DataOutputStream(replyBuf),
        )

        assertEquals(host, dest.host)
        assertEquals(1139, dest.port)
        assertTrue(replyBuf.toByteArray().contentEquals(byteArrayOf(0x05, 0x00)))
    }

    @Test
    fun negotiateMethod_selectsUserPassWhenOnlyOffered() {
        val input = DataInputStream(
            ByteArrayInputStream(byteArrayOf(0x05, 0x01, 0x02)),
        )
        val replyBuf = ByteArrayOutputStream()
        val method = SocksAuthInjectingRelay.negotiateMethod(
            input,
            DataOutputStream(replyBuf),
        )
        assertEquals(SocksAuthInjectingRelay.Method.USER_PASS, method)
        assertTrue(replyBuf.toByteArray().contentEquals(byteArrayOf(0x05, 0x02)))
    }

    @Test
    fun acceptUsernamePassword_acceptsOpenVpnTokens() {
        val user = TunnelEndpoints.SOCKS_OPENVPN_USER.toByteArray()
        val pass = TunnelEndpoints.SOCKS_OPENVPN_PASS.toByteArray()
        val buf = ByteArrayOutputStream()
        buf.write(0x01)
        buf.write(user.size)
        buf.write(user)
        buf.write(pass.size)
        buf.write(pass)
        val replyBuf = ByteArrayOutputStream()
        SocksAuthInjectingRelay.acceptUsernamePassword(
            DataInputStream(ByteArrayInputStream(buf.toByteArray())),
            DataOutputStream(replyBuf),
        )
        assertTrue(replyBuf.toByteArray().contentEquals(byteArrayOf(0x01, 0x00)))
    }

    @Test
    fun negotiateMethod_rejectsWhenNeitherOffered() {
        val input = DataInputStream(
            ByteArrayInputStream(byteArrayOf(0x05, 0x01, 0x01)), // GSSAPI only
        )
        val replyBuf = ByteArrayOutputStream()
        try {
            SocksAuthInjectingRelay.negotiateMethod(input, DataOutputStream(replyBuf))
            fail("expected IOException")
        } catch (_: IOException) {
            assertTrue(
                replyBuf.toByteArray().contentEquals(
                    byteArrayOf(0x05, 0xFF.toByte()),
                ),
            )
        }
    }
}
