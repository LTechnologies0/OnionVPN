package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import org.junit.Assert.assertNull
import org.junit.Test

class LanClearnetDialTest {
    @Test
    fun selectLanUplink_nullConnectivity_returnsNull() {
        assertNull(LanClearnetDial.selectLanUplink(null))
    }
}
