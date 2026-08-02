plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.torproject.onionmasq"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}

dependencies {
    implementation(libs.androidx.appcompat)
    implementation("androidx.annotation:annotation:1.9.1")
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation("com.google.code.gson:gson:2.13.1")
    // Pluggable transports used by OnionMasq.start(fd, bridgeLines)
    implementation("com.netzarchitekten:IPtProxy:5.4.2")
}
