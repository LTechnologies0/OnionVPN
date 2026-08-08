package ltechnologies.onionphone.onionvpn.baselineprofile

import androidx.benchmark.macro.junit4.BaselineProfileRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Regenerates Baseline / Startup profiles for Status + tunnel UI.
 *
 * Requires a connected arm64 device (or emulator) and:
 *   ./gradlew :app:generateBaselineProfile
 *
 * Seeded profiles under `app/src/main/baselineProfiles/` ship without this step.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class BaselineProfileGenerator {
    @get:Rule
    val rule = BaselineProfileRule()

    @Test
    fun generate() = rule.collect(
        packageName = PACKAGE,
        includeInStartupProfile = true,
        maxIterations = 5,
    ) {
        pressHome()
        startActivityAndWait()
        device.wait(Until.hasObject(By.text("OnionVPN")), 15_000)
        // Status tab is default; scroll a bit so Compose measure/layout is exercised.
        device.waitForIdle()
        runCatching {
            device.findObject(By.text("Settings"))?.click()
            device.wait(Until.hasObject(By.text("Settings")), 5_000)
            device.findObject(By.text("Status"))?.click()
            device.wait(Until.hasObject(By.text("OnionVPN")), 5_000)
        }
        // Prefer tapping Start when Idle — VPN permission may block; still profiles UI path.
        runCatching {
            device.findObject(By.text("Start tunnel"))?.click()
            device.waitForIdle(3_000)
        }
    }

    companion object {
        private const val PACKAGE = "ltechnologies.onionphone.onionvpn"
    }
}
