plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.test) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.parcelize) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.hilt) apply false
    alias(libs.plugins.androidx.baselineprofile) apply false
}

// Compiler throughput: fork javac out of the Gradle daemon JVM (less GC contention)
// and keep incremental compilation on for ABI-compatible edits.
subprojects {
    tasks.withType<JavaCompile>().configureEach {
        options.isFork = true
        options.isIncremental = true
        options.forkOptions.memoryMaximumSize = "1g"
    }
}
