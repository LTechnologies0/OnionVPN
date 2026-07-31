package org.torproject.arti

/**
 * OnionVPN Ext JNI for arti-client 0.36.0 control ops not in stock arti-mobile.
 *
 * Symbols live in the same `libarti_mobile_ex.so` as [ArtiJNI]. Stock Maven AARs
 * lack these symbols — [isAvailable] then returns false and callers fall back.
 *
 * Patched builds (see `native/arti-mobile-ex/`) export control-api ≥ 2:
 * - [setDormant] → `TorClient::set_dormant(Soft|Normal)`
 * - [applyMaxDirtiness] / [applyCircuitTiming] → `max_dirtiness` + `prediction_lifetime`
 * - [applyExitCountry] → SOCKS `StreamPrefs::exit_country` (geoip)
 * - [resolveHostname] → `TorClient::resolve`
 * - [bootstrapFraction] / [readyForTraffic] / [bootstrapBlockage] → `BootstrapStatus`
 */
object ArtiControlNative {
    @Volatile
    private var cachedAvailable: Boolean? = null

    init {
        // Ensure arti_mobile_ex is loaded via the AAR's ArtiJNI static initializer.
        runCatching {
            Class.forName("org.torproject.arti.ArtiJNI")
        }
    }

    /**
     * True when the loaded `libarti_mobile_ex.so` includes OnionVPN Ext symbols
     * ([controlApiVersion] ≥ 1).
     */
    @JvmStatic
    fun isAvailable(): Boolean {
        cachedAvailable?.let { return it }
        val ok = try {
            controlApiVersionJNI() >= 1
        } catch (_: UnsatisfiedLinkError) {
            false
        } catch (_: Throwable) {
            false
        }
        cachedAvailable = ok
        return ok
    }

    /** Soft dormant (true) or Normal/ACTIVE (false). */
    @JvmStatic
    fun setDormant(soft: Boolean): Boolean {
        if (!isAvailable()) return false
        return try {
            setDormantJNI(soft)
        } catch (_: UnsatisfiedLinkError) {
            cachedAvailable = false
            false
        }
    }

    /** Live MaxCircuitDirtiness analogue (seconds, clamped 60..7200). */
    @JvmStatic
    fun applyMaxDirtiness(seconds: Int): Boolean {
        if (!isAvailable()) return false
        return try {
            applyMaxDirtinessJNI(seconds)
        } catch (_: UnsatisfiedLinkError) {
            cachedAvailable = false
            false
        }
    }

    /**
     * Live max_dirtiness + prediction_lifetime (NewCircuitPeriod analogue).
     * Requires control-api ≥ 2.
     */
    @JvmStatic
    fun applyCircuitTiming(maxDirtinessSec: Int, predictionLifetimeSec: Int): Boolean {
        if (controlApiVersion() < 2) {
            return applyMaxDirtiness(maxDirtinessSec)
        }
        return try {
            applyCircuitTimingJNI(maxDirtinessSec, predictionLifetimeSec)
        } catch (_: UnsatisfiedLinkError) {
            applyMaxDirtiness(maxDirtinessSec)
        }
    }

    /**
     * Single ISO-3166 alpha-2 exit country for SOCKS streams, or empty to clear.
     * Requires control-api ≥ 2 + geoip.
     */
    @JvmStatic
    fun applyExitCountry(countryCode: String?): Boolean {
        if (controlApiVersion() < 2) return false
        return try {
            applyExitCountryJNI(countryCode.orEmpty())
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    /**
     * `TorClient::resolve` — returns first IP or null on failure.
     * Result wire format from native: `OK:ip[,ip…]` or `Error:…`.
     */
    @JvmStatic
    fun resolveHostname(hostname: String): String? {
        if (controlApiVersion() < 2) return null
        return try {
            val raw = resolveHostnameJNI(hostname) ?: return null
            when {
                raw.startsWith("OK:") -> raw.removePrefix("OK:").substringBefore(',').trim()
                    .takeIf { it.isNotEmpty() }
                else -> null
            }
        } catch (_: UnsatisfiedLinkError) {
            null
        }
    }

    /** BootstrapStatus::blocked debug string, or empty if unblocked / unavailable. */
    @JvmStatic
    fun bootstrapBlockage(): String {
        if (controlApiVersion() < 2) return ""
        return try {
            bootstrapBlockageJNI().orEmpty()
        } catch (_: UnsatisfiedLinkError) {
            ""
        }
    }

    /** BootstrapStatus::as_frac, or null if unavailable / client not running. */
    @JvmStatic
    fun bootstrapFraction(): Float? {
        if (!isAvailable()) return null
        return try {
            val f = bootstrapFractionJNI()
            if (f < 0f) null else f.coerceIn(0f, 1f)
        } catch (_: UnsatisfiedLinkError) {
            cachedAvailable = false
            null
        }
    }

    @JvmStatic
    fun readyForTraffic(): Boolean {
        if (!isAvailable()) return false
        return try {
            readyForTrafficJNI()
        } catch (_: UnsatisfiedLinkError) {
            cachedAvailable = false
            false
        }
    }

    @JvmStatic
    fun controlApiVersion(): Int {
        if (!isAvailable()) return 0
        return try {
            controlApiVersionJNI()
        } catch (_: UnsatisfiedLinkError) {
            0
        }
    }

    // Native — only resolved when patched .so is packaged.
    @JvmStatic
    private external fun controlApiVersionJNI(): Int

    @JvmStatic
    private external fun setDormantJNI(soft: Boolean): Boolean

    @JvmStatic
    private external fun applyMaxDirtinessJNI(seconds: Int): Boolean

    @JvmStatic
    private external fun applyCircuitTimingJNI(maxDirtinessSec: Int, predictionLifetimeSec: Int): Boolean

    @JvmStatic
    private external fun applyExitCountryJNI(countryCode: String): Boolean

    @JvmStatic
    private external fun resolveHostnameJNI(hostname: String): String?

    @JvmStatic
    private external fun bootstrapBlockageJNI(): String?

    @JvmStatic
    private external fun bootstrapFractionJNI(): Float

    @JvmStatic
    private external fun readyForTrafficJNI(): Boolean
}
