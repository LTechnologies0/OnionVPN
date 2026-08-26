package ltechnologies.onionphone.onionvpn.core.openvpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OpenVpnAndroidManagementTest {
    @Test
    fun parseNeedOk_icsQuotedIfconfig() {
        val (type, extra) = OpenVpnAndroidManagement.parseNeedOkArgument(
            "Need 'IFCONFIG' confirmation MSG:10.233.222.129 10.233.222.130 1280 net30",
        )
        assertEquals("IFCONFIG", type)
        assertEquals("10.233.222.129 10.233.222.130 1280 net30", extra)
    }

    @Test
    fun parseNeedOk_icsOpentunAndPersist() {
        assertEquals(
            "OPENTUN" to "tun",
            OpenVpnAndroidManagement.parseNeedOkArgument(
                "Need 'OPENTUN' confirmation MSG:tun",
            ),
        )
        assertEquals(
            "PERSIST_TUN_ACTION" to "tunmethod",
            OpenVpnAndroidManagement.parseNeedOkArgument(
                "Need 'PERSIST_TUN_ACTION' confirmation MSG:tunmethod",
            ),
        )
    }

    @Test
    fun parseNeedOk_bareLegacy() {
        assertEquals(
            "IFCONFIG" to "10.8.0.2 255.255.255.0 1500 net30",
            OpenVpnAndroidManagement.parseNeedOkArgument(
                "IFCONFIG 10.8.0.2 255.255.255.0 1500 net30",
            ),
        )
        assertEquals(
            "OPENTUN" to "tun",
            OpenVpnAndroidManagement.parseNeedOkArgument("OPENTUN tun"),
        )
    }

    @Test
    fun connectedAndNotReadyStateHelpers() {
        assertTrue(
            OpenVpnAndroidManagement.isConnectedState(">STATE:1,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4"),
        )
        assertTrue(
            OpenVpnAndroidManagement.isControlNotReadyState(">STATE:2,RECONNECTING,ping-restart,,,"),
        )
        assertTrue(
            OpenVpnAndroidManagement.isControlNotReadyState(">STATE:3,WAIT,,,,"),
        )
        assertFalse(
            OpenVpnAndroidManagement.isControlNotReadyState(">STATE:1,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4"),
        )
    }
}
