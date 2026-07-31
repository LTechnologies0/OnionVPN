package ltechnologies.onionphone.onionvpn.core.model.stability

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessLogLevelTest {
    @Test
    fun parse_cTorBracketLevels() {
        assertEquals(ProcessLogLevel.DEBUG, ProcessLogLevel.parse("[debug] Opening log"))
        assertEquals(ProcessLogLevel.INFO, ProcessLogLevel.parse("[info] Bootstrapped 80%"))
        assertEquals(ProcessLogLevel.INFO, ProcessLogLevel.parse("[notice] Opening Socks listener"))
        assertEquals(ProcessLogLevel.WARN, ProcessLogLevel.parse("[warn] Problem bootstrapping"))
        assertEquals(ProcessLogLevel.ERROR, ProcessLogLevel.parse("[err] Dying"))
        assertEquals(ProcessLogLevel.ERROR, ProcessLogLevel.parse("[error] Fatal"))
    }

    @Test
    fun parse_artiTracingWordLevels() {
        assertEquals(
            ProcessLogLevel.INFO,
            ProcessLogLevel.parse(
                "2026-07-31T15:33:30.627731Z  INFO arti_mobile_ex: Sufficiently bootstrapped",
            ),
        )
        assertEquals(
            ProcessLogLevel.WARN,
            ProcessLogLevel.parse(
                "2026-07-31T15:33:29Z  WARN arti::reload_cfg: Couldn't reload configuration: error: tor",
            ),
        )
        assertEquals(
            ProcessLogLevel.ERROR,
            ProcessLogLevel.parse("2026-07-31T15:33:29Z  ERROR tor_dirmgr: directory failed"),
        )
        assertEquals(
            ProcessLogLevel.TRACE,
            ProcessLogLevel.parse("2026-07-31T15:33:29Z  TRACE tor_chanmgr: channel idle"),
        )
        assertEquals(
            ProcessLogLevel.DEBUG,
            ProcessLogLevel.parse("2026-07-31T15:33:29Z  DEBUG tor_circmgr: building circuit"),
        )
    }

    @Test
    fun parse_dnsCryptBracketLevels() {
        assertEquals(ProcessLogLevel.DEBUG, ProcessLogLevel.parse("[DEBUG] probe timeout waiting"))
        assertEquals(ProcessLogLevel.CRITICAL, ProcessLogLevel.parse("[CRITICAL] no servers available"))
        assertEquals(ProcessLogLevel.WARN, ProcessLogLevel.parse("[WARNING] certificate nearly expired"))
    }

    @Test
    fun parse_doesNotTreatBodyErrorAsLevel() {
        // "error:" in message body must not override WARN.
        assertEquals(
            ProcessLogLevel.WARN,
            ProcessLogLevel.parse(
                "2026-07-31T15:33:29Z  WARN arti::reload_cfg: configuration: error: invalid",
            ),
        )
    }

    @Test
    fun parse_blankIsNull() {
        assertNull(ProcessLogLevel.parse(""))
        assertNull(ProcessLogLevel.parse("   "))
    }

    @Test
    fun androidPriorityMapping() {
        assertEquals(ProcessLogLevel.TRACE, ProcessLogLevel.fromAndroidPriority(2))
        assertEquals(ProcessLogLevel.DEBUG, ProcessLogLevel.fromAndroidPriority(3))
        assertEquals(ProcessLogLevel.INFO, ProcessLogLevel.fromAndroidPriority(4))
        assertEquals(ProcessLogLevel.WARN, ProcessLogLevel.fromAndroidPriority(5))
        assertEquals(ProcessLogLevel.ERROR, ProcessLogLevel.fromAndroidPriority(6))
        assertEquals(ProcessLogLevel.CRITICAL, ProcessLogLevel.fromAndroidPriority(7))
    }

    @Test
    fun severityOrder() {
        assertTrue(StabilitySeverity.TRACE < StabilitySeverity.DEBUG)
        assertTrue(StabilitySeverity.DEBUG < StabilitySeverity.INFO)
        assertTrue(StabilitySeverity.INFO < StabilitySeverity.WARN)
        assertTrue(StabilitySeverity.WARN < StabilitySeverity.ERROR)
        assertTrue(StabilitySeverity.ERROR < StabilitySeverity.CRITICAL)
    }
}
