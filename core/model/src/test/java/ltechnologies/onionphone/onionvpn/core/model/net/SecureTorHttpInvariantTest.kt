package ltechnologies.onionphone.onionvpn.core.model.net

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Source invariant: every OkHttpClient.Builder used for Tor/HTTPS must call
 * [SecureTorHttp.applyTorClientHardening] (no redirects + MODERN_TLS).
 */
class SecureTorHttpInvariantTest {
    @Test
    fun everyOkHttpBuilderAppliesTorHardening() {
        val root = File(".").canonicalFile.let { dir ->
            generateSequence(dir) { it.parentFile }
                .firstOrNull { File(it, "settings.gradle.kts").exists() }
                ?: dir
        }
        val ktFiles = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { !it.path.contains("/build/") }
            .filter { !it.path.contains("/test/") } // production sources only
            .toList()

        val builders = mutableListOf<File>()
        val hardened = mutableListOf<File>()
        for (f in ktFiles) {
            val text = f.readText()
            if (text.contains("OkHttpClient.Builder()")) {
                builders.add(f)
                if (text.contains("applyTorClientHardening()")) {
                    hardened.add(f)
                }
            }
        }
        assertTrue("expected OkHttpClient.Builder usages", builders.isNotEmpty())
        val missing = builders.filterNot { it in hardened }
        assertTrue(
            "OkHttp builders missing applyTorClientHardening: " +
                missing.joinToString { it.relativeTo(root).path },
            missing.isEmpty(),
        )
        assertFalse(hardened.isEmpty())
    }
}
