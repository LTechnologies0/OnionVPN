package ltechnologies.onionphone.onionvpn.core.vpn.firewall

import org.junit.Assert.assertEquals
import org.junit.Test

class ConnectionOwnerResolverProcNetTest {
    @Test
    fun ipv4_loopback_isLittleEndianProcHex() {
        // 127.0.0.1 network-order int → /proc/net/tcp "0100007F"
        val ip = (127 shl 24) or 1
        assertEquals("0100007F:0050", ConnectionOwnerResolver.procNetIpv4PortHex(ip, 80))
    }

    @Test
    fun ipv6_loopback_isPerWordLittleEndian() {
        val bytes = ByteArray(16).also { it[15] = 1 } // ::1
        assertEquals(
            "00000000000000000000000001000000:01BB",
            ConnectionOwnerResolver.procNetIpv6PortHex(bytes, 443),
        )
    }
}
