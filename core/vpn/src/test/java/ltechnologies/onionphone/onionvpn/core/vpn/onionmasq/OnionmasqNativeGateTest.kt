package ltechnologies.onionphone.onionvpn.core.vpn.onionmasq

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression: 0.3.46 called native isRunning()/closeProxy from stop() before init,
 * which SIGABRTs inside libonionmasq_mobile.so (unwrap on OnionmasqMobile::get).
 */
class OnionmasqNativeGateTest {
    @Test
    fun stopSkippedWhenProxyNeverOwned() {
        // start() invokes stop() on a fresh forwarder — must not touch JNI.
        assertFalse(OnionmasqNativeGate.mayStopNativeProxy(proxyOwned = false))
    }

    @Test
    fun stopAllowedOnlyAfterFdHandedToNative() {
        assertTrue(OnionmasqNativeGate.mayStopNativeProxy(proxyOwned = true))
    }

    @Test
    fun nativeRunningProbeRequiresJavaInit() {
        assertFalse(OnionmasqNativeGate.mayProbeNativeRunning(javaInitialized = false))
        assertTrue(OnionmasqNativeGate.mayProbeNativeRunning(javaInitialized = true))
    }
}
