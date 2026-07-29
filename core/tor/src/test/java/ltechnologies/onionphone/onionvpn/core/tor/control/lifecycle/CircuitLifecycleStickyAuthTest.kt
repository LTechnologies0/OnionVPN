package ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle

import ltechnologies.onionphone.onionvpn.core.model.TunnelEndpoints
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CircuitLifecycleStickyAuthTest {
    @Test
    fun uidToken_isSticky() {
        val user = TunnelEndpoints.socksUserForUid(10123)
        assertTrue(CircuitLifecycleManager.isStickySocksAuth(user))
    }

    @Test
    fun dnsCryptToken_isSticky() {
        assertTrue(CircuitLifecycleManager.isStickySocksAuth(TunnelEndpoints.SOCKS_DNSCRYPT_USER))
    }

    @Test
    fun blank_isNotSticky() {
        assertFalse(CircuitLifecycleManager.isStickySocksAuth(null))
        assertFalse(CircuitLifecycleManager.isStickySocksAuth(""))
        assertFalse(CircuitLifecycleManager.isStickySocksAuth("random"))
    }
}
