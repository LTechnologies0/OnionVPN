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

val hasKotlinDnsCrypt: Boolean =
    findComposite("composite/kotlin-DNSCrypt", "../kotlin-DNSCrypt")

android {
    namespace = "ltechnologies.onionphone.onionvpn.core.dnscrypt"
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
            java.srcDir(
                if (hasKotlinDnsCrypt) "src/compositeEngines/java" else "src/stubEngines/java",
            )
            kotlin.srcDir(
                if (hasKotlinDnsCrypt) "src/compositeEngines/java" else "src/stubEngines/java",
            )
        }
    }
}

dependencies {
    implementation(project(":core:model"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.timber)
    if (hasKotlinDnsCrypt) {
        implementation("org.kotlindnscrypt:core")
    }

    testImplementation(libs.junit)
}
