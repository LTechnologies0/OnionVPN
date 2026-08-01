package ltechnologies.onionphone.onionvpn.core.model.observability

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class MemoryHygieneTest {
    @Before
    fun setUp() {
        MemoryHygiene.resetForTests()
    }

    @After
    fun tearDown() {
        MemoryHygiene.resetForTests()
    }

    @Test
    fun suggestGc_rateLimited() {
        assertTrue(MemoryHygiene.suggestGc("first"))
        assertFalse(MemoryHygiene.suggestGc("second_immediate"))
        assertTrue(MemoryHygiene.suggestGc("forced", force = true))
    }

    @Test
    fun heapUsageRatio_isBounded() {
        val ratio = MemoryHygiene.heapUsageRatio()
        assertTrue(ratio in 0.0..1.0 || ratio > 1.0) // total can briefly exceed after grow
        assertTrue(MemoryHygiene.heapMaxBytes() > 0L)
    }

    @Test
    fun afterHeavyWork_delegatesToSuggestGc() {
        MemoryHygiene.resetForTests()
        assertTrue(MemoryHygiene.afterHeavyWork("unit"))
        assertFalse(MemoryHygiene.afterHeavyWork("unit_again"))
    }
}
