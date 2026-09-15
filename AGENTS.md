# AGENTS.md

## Cursor Cloud specific instructions

This is an Android app (Gradle Kotlin DSL, AGP 9.1.1, Kotlin 2.2.10, JDK 21,
`compileSdk`/`targetSdk` 37, `minSdk` 26). Standard build/run commands are in
`README.md` and `.github/workflows/ci.yml`.

### Environment (already provisioned in the VM snapshot)
- Android SDK lives at `/opt/android-sdk` (`platforms;android-37.0`,
  `build-tools;37.0.0`, `platform-tools`). `ANDROID_HOME`/`ANDROID_SDK_ROOT` are
  exported from `~/.bashrc`.
- `local.properties` (gitignored) already contains `sdk.dir=/opt/android-sdk`.
- There is **no KVM / Android emulator** in this VM, so the app cannot be launched
  on a device here. Validate changes the same way CI does: unit tests + a debug APK
  build. Instrumented (`androidTest`) tests cannot run.

### Build & test
- Debug APK (fastest — single ABI): `./gradlew :app:assembleDebug -Ponionphone.devAbi=arm64-v8a --no-daemon`
  → `app/build/outputs/apk/debug/app-debug.apk`.
- Unit tests: `./gradlew test --no-daemon`.
