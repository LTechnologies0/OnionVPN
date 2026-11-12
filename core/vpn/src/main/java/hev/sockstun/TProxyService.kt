package hev.sockstun

/**
 * JNI bridge for prebuilt [libhev-socks5-tunnel.so] (sockstun / v2rayNG).
 * The native library registers natives against this exact class name.
 *
 * [TProxyStartServiceFromStr] is registered by [libhev_fromstr_jni.so] (dlsym →
 * `hev_socks5_tunnel_main_from_str`) so session passwords never need a path.
 */
object TProxyService {
    private val fromStrReady: Boolean

    init {
        System.loadLibrary("hev-socks5-tunnel")
        fromStrReady =
            runCatching {
                System.loadLibrary("hev_fromstr_jni")
                true
            }.getOrDefault(false)
    }

    fun isFromStrAvailable(): Boolean = fromStrReady

    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int)

    /**
     * Registered by hev_fromstr_jni. Call only when [isFromStrAvailable] is true.
     * @return 0 on spawn OK; negative on shim/dlsym failure.
     */
    @JvmStatic
    external fun TProxyStartServiceFromStr(config: String, fd: Int): Int

    /** Prefer FromStr; returns negative if shim missing or spawn failed (caller may path-fallback). */
    fun startFromStr(config: String, fd: Int): Int {
        if (!fromStrReady) return -100
        return TProxyStartServiceFromStr(config, fd)
    }

    @JvmStatic
    external fun TProxyStopService()

    @JvmStatic
    external fun TProxyGetStats(): LongArray?
}
