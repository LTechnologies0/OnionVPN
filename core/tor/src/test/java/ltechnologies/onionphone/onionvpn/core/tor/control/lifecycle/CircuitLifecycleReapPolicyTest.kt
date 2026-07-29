package ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Documents that UID reap must use PACKAGE_* intents with EXTRA_UID — never
 * ActivityManager.runningAppProcesses (incomplete list → false CLOSECIRCUIT).
 */
class CircuitLifecycleReapPolicyTest {
    @Test
    fun stickyAuth_includesUidTokens() {
        assertEquals(true, CircuitLifecycleManager.isStickySocksAuth("u10123"))
        assertEquals(true, CircuitLifecycleManager.isStickySocksAuth("dnscrypt"))
        assertEquals(false, CircuitLifecycleManager.isStickySocksAuth("ephemeral"))
    }
}
