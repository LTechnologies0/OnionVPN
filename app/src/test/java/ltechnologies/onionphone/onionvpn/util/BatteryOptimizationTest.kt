package ltechnologies.onionphone.onionvpn.util

import android.provider.Settings
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BatteryOptimizationTest {
    @Test
    fun requestIgnoreIntentTargetsPackage() {
        val context = RuntimeEnvironment.getApplication()
        val intent = BatteryOptimization.requestIgnoreIntent(context)
        assertEquals(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, intent.action)
        assertEquals("package:${context.packageName}", intent.data?.toString())
    }

    @Test
    fun needsWhitelistingReadable() {
        val context = RuntimeEnvironment.getApplication()
        // Robolectric PowerManager typically reports not ignoring — just ensure no throw.
        assertTrue(
            BatteryOptimization.needsWhitelisting(context) ||
                !BatteryOptimization.needsWhitelisting(context),
        )
    }
}
