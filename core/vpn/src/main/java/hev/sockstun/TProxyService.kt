package hev.sockstun

/**
 * JNI bridge for prebuilt [libhev-socks5-tunnel.so] (sockstun / v2rayNG).
 * The native library registers natives against this exact class name.
 */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    @JvmStatic
    external fun TProxyStartService(configPath: String, fd: Int)

    @JvmStatic
    external fun TProxyStopService()

    @JvmStatic
    external fun TProxyGetStats(): LongArray?
}
