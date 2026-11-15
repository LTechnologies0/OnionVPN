package hev.sockstun

import timber.log.Timber

/**
 * JNI bridge for prebuilt [libhev-socks5-tunnel.so] (sockstun / v2rayNG).
 * The native library registers natives against this exact class name.
 *
 * [TProxyStartServiceFromStr] is registered by [libhev_fromstr_jni.so] (dlsym →
 * `hev_socks5_tunnel_main_from_str`) so session passwords never need a path.
 *
 * Initialization is **fail-closed**: if either native library is missing or its
 * JNI registration fails, [fromStrReady] is false and all Start calls return
 * an error code. Callers must check [isFromStrAvailable] before attempting
 * to start the tunnel — silent no-op would blackhole traffic.
 */
object TProxyService {
    private var fromStrReady: Boolean = false
    private var initError: String? = null

    init {
        var error: String? = null
        try {
            System.loadLibrary("hev-socks5-tunnel")
        } catch (e: UnsatisfiedLinkError) {
            error = "hev-socks5-tunnel: $e"
        }
        if (error == null) {
            try {
                System.loadLibrary("hev_fromstr_jni")
                fromStrReady = true
            } catch (e: UnsatisfiedLinkError) {
                error = "hev_fromstr_jni: $e"
                fromStrReady = false
            }
        } else {
            fromStrReady = false
        }
        if (error != null) {
            initError = error
            Timber.e("TProxyService init FAIL-CLOSED: $error")
        } else {
            Timber.i("TProxyService ready (fromStr=%b)", fromStrReady)
        }
    }

    fun isFromStrAvailable(): Boolean = fromStrReady

    fun initError(): String? = initError

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
