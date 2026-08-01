# OnionVPN fork notes for Guardian arti-mobile-ex
#
# Patches (common/src/lib.rs + android.rs + third_party/arti-1.7.0-onionvpn):
# - Rename cdylib to arti_mobile_ex (matches Maven AAR loadLibrary)
# - Hold TorClient handle for control ops
# - Apply CircuitTimingBuilder::max_dirtiness + prediction_lifetime from
#   state_dir/onionvpn_circuit_timing
# - SocksTimeout parity: circuit_timing.request_timeout=120s; stream
#   connect=90s / resolve=60s / resolve_ptr=30s (Arti defaults were 60/10/10)
# - ExitNodes country via patched SOCKS StreamPrefs::exit_country (geoip)
# - Conjure TransportConfig from state_dir/onionvpn_pt_plugins
# - JNI Ext class org.torproject.arti.ArtiControlNative (control-api=2):
#     controlApiVersionJNI / setDormantJNI / applyMaxDirtinessJNI /
#     applyCircuitTimingJNI / applyExitCountryJNI / resolveHostnameJNI /
#     bootstrapFractionJNI / readyForTrafficJNI / bootstrapBlockageJNI
#
# Build (from repo root):
#   ./native/arti-mobile-ex/build-onionvpn.sh
#
# Requires: Rust stable ≥1.86, cargo-ndk 3.5+, Android NDK 27+.
# Links with -Wl,-z,max-page-size=16384 for Android 16 KB pages.
