plugins {
    alias(libs.plugins.android.library)
}

fun findComposite(vararg relatives: String): Boolean =
    relatives
        .map { rootProject.file(it) }
        .any { dir ->
            dir.isDirectory &&
                (dir.resolve("settings.gradle.kts").isFile || dir.resolve("settings.gradle").isFile)
        }

val hasKotlinTor: Boolean = findComposite("composite/kotlin-tor", "../../kotlin-tor")

android {
    namespace = "ltechnologies.onionphone.onionvpn.core.tor"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    sourceSets {
        getByName("main").apply {
            java.srcDir(if (hasKotlinTor) "src/compositeEngines/java" else "src/stubEngines/java")
            // AGP Kotlin compile reads kotlin.srcDirs separately from java.srcDirs.
            kotlin.srcDir(if (hasKotlinTor) "src/compositeEngines/java" else "src/stubEngines/java")
        }
    }
}

dependencies {
    implementation(project(":core:model"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.timber)
    implementation(libs.androidx.core.ktx)
    implementation(libs.okhttp)
    // Tor Project / Guardian Project Arti mobile (Rust Tor) — dual-engine with libtor.so
    implementation(libs.arti.mobile)
    if (hasKotlinTor) {
        implementation("org.kotlintor:android")
    }

    testImplementation(libs.junit)
}
