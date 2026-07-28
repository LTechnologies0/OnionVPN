package ltechnologies.onionphone.onionvpn.firewall

import ltechnologies.onionphone.onionvpn.core.model.DomainThreatCategory
import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatEmojiTest {
    @Test
    fun notificationEmojiMatchesThreatCategory() {
        // 🟢 safe (not tagged tracking/malware)
        assertEquals("🟢", DomainThreatCategory.NONE.notificationEmoji())
        // 🟠 tracking / ads / telemetry
        assertEquals("🟠", DomainThreatCategory.TRACKING.notificationEmoji())
        // 🔴 malware / C2
        assertEquals("🔴", DomainThreatCategory.MALWARE.notificationEmoji())
    }
}
