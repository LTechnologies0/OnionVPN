# Keep VPN service, JNI bridge, and native entry points.
-keep class ltechnologies.onionphone.onionvpn.core.vpn.OnionVpnService { *; }
-keep class ltechnologies.onionphone.onionvpn.service.TunnelForegroundService { *; }
-keep class hev.sockstun.TProxyService { *; }

# Arti mobile (Rust Tor) — JNI + log callback must survive R8.
-keep class org.torproject.arti.** { *; }
-keepclassmembers class org.torproject.arti.** { *; }
