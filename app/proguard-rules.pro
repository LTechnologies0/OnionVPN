# Keep VPN service, JNI bridge, and native entry points.
-keep class ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService { *; }
-keep class ltechnologies.onionphone.onionvpn.service.TunnelForegroundService { *; }
-keep class hev.sockstun.TProxyService { *; }

# Arti mobile (Rust Tor) — JNI + log callback must survive R8.
-keep class org.torproject.arti.** { *; }
-keepclassmembers class org.torproject.arti.** { *; }

# onionmasq (Rust) calls Java statics by name from libonionmasq_mobile.so.
# R8 removed getAndroidAPI/protect/postEvent → NoSuchMethodError → ART abort
# (private-space tombstone 0.3.48: "no static method …getAndroidAPI()I").
-keep class org.torproject.onionmasq.** { *; }
-keepclassmembers class org.torproject.onionmasq.** { *; }
-keepclassmembers class org.torproject.onionmasq.OnionMasqJni {
    public static boolean protect(int);
    public static int getAndroidAPI();
    public static void postEvent(java.lang.String);
    public static native <methods>;
}

# kotlin-tor (composite) — keep engine; ignore JVM-only FFM/ProcessHandle refs.
-keep class org.kotlintor.** { *; }
-dontwarn java.lang.ProcessHandle
-dontwarn java.lang.foreign.**
-dontwarn org.kotlintor.os.SeccompBpf
-dontwarn org.kotlintor.os.SeccompBpf$*
-dontwarn org.kotlintor.config.PidFile
