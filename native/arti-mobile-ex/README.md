# OnionVPN fork notes for Guardian arti-mobile-ex
#
# Patches (common/src/lib.rs + android.rs):
# - Rename cdylib to arti_mobile_ex (matches Maven AAR loadLibrary)
# - Hold TorClient handle for control ops
# - Apply CircuitTimingBuilder::max_dirtiness from state_dir/onionvpn_circuit_timing
# - JNI Ext class org.torproject.arti.ArtiControlNative:
#     controlApiVersionJNI / setDormantJNI / applyMaxDirtinessJNI /
#     bootstrapFractionJNI / readyForTrafficJNI
#
# Build (from repo root):
#   ./native/arti-mobile-ex/build-onionvpn.sh
#
# Requires: Rust stable ≥1.86, cargo-ndk 3.5+, Android NDK 27+.
