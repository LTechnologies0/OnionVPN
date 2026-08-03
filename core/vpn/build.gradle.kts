plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "ltechnologies.onionphone.onionvpn.core.vpn"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

dependencies {
    implementation(project(":core:model"))
    implementation(project(":third_party:onionmasq-android"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    implementation(libs.timber)

    testImplementation(libs.junit)
}
