package ltechnologies.onionphone.onionvpn.core.vpn.forwarder

import android.util.Log
import timber.log.Timber

internal object VpnForwarderDebug {
    private const val TAG_SOCKS = "SocksUidBridge"
    private const val TAG_UID = "UidIsolatingTunForwarder"

    @JvmStatic
    inline fun socksLog(message: () -> String) {
        if (Log.isLoggable(TAG_SOCKS, Log.DEBUG)) {
            Timber.tag(TAG_SOCKS).d(message())
        }
    }

    @JvmStatic
    inline fun socksLog(throwable: Throwable, message: () -> String) {
        if (Log.isLoggable(TAG_SOCKS, Log.DEBUG)) {
            Timber.tag(TAG_SOCKS).d(throwable, message())
        }
    }

    @JvmStatic
    inline fun uidLog(message: () -> String) {
        if (Log.isLoggable(TAG_UID, Log.DEBUG)) {
            Timber.tag(TAG_UID).d(message())
        }
    }

    @JvmStatic
    inline fun uidLog(throwable: Throwable, message: () -> String) {
        if (Log.isLoggable(TAG_UID, Log.DEBUG)) {
            Timber.tag(TAG_UID).d(throwable, message())
        }
    }
}
