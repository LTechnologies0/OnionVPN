package ltechnologies.onionphone.onionvpn.core.model.observability

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ProcFsParserTest {
    @Test
    fun parseStatus_readsRssSizeThreads() {
        val text = """
            Name:	onionvpn
            State:	S (sleeping)
            VmSize:	  512000 kB
            VmRSS:	   98304 kB
            Threads:	42
            voluntary_ctxt_switches:	10
        """.trimIndent()
        val m = ProcFsParser.parseStatus(text)
        assertEquals(98304L, m.vmRssKb)
        assertEquals(512000L, m.vmSizeKb)
        assertEquals(42, m.threads)
    }

    @Test
    fun parseStatCpu_readsUtimeStime() {
        // Minimal /proc/self/stat with (comm) then fields; utime/stime at positions 14/15.
        // After ") ": state + 10 fields then utime/stime (proc(5) fields 14–15).
        val text = "1 (a) S 0 0 0 0 0 0 0 0 0 0 100 50 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
        val cpu = ProcFsParser.parseStatCpu(text)
        assertNotNull(cpu)
        assertEquals(100L, cpu!!.utimeTicks)
        assertEquals(50L, cpu.stimeTicks)
        assertEquals(150L, cpu.totalTicks)
    }

    @Test
    fun parseStatCpu_rejectsMalformed() {
        assertNull(ProcFsParser.parseStatCpu("no-parens"))
        assertNull(ProcFsParser.parseStatCpu("1 (x) S"))
    }
}
