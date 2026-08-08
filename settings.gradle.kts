pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        // Guardian Project Maven — org.torproject:arti-mobile (Arti for Android)
        maven {
            url = uri("https://raw.githubusercontent.com/guardianproject/gpmaven/master")
        }
    }
}

rootProject.name = "onion-vpn"

include(
    ":app",
    ":baselineprofile",
    ":core:model",
    ":core:tor",
    ":core:dnscrypt",
    ":core:vpn",
    ":core:validation",
    ":third_party:onionmasq-android",
)

// ARM64 hosts (Termux / aarch64 CI): AGP's Maven aapt2 is linux-x86_64 and needs QEMU.
// Prefer a native aapt2 when present. Explicit -P / env / arm-host.local.properties wins.
run {
    val arch = System.getProperty("os.arch")?.lowercase().orEmpty()
    if (arch != "aarch64" && arch != "arm64") return@run

    fun prop(key: String): String? =
        providers.gradleProperty(key).orNull?.takeIf { it.isNotBlank() }
            ?: gradle.startParameter.projectProperties[key]?.takeIf { it.isNotBlank() }

    fun loadArmLocal(): Map<String, String> {
        val armLocal = file("gradle/arm-host.local.properties")
        if (!armLocal.isFile) return emptyMap()
        return armLocal.readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && '=' in it }
            .associate { line ->
                val idx = line.indexOf('=')
                line.substring(0, idx).trim() to line.substring(idx + 1).trim()
            }
            .filterKeys { it.isNotEmpty() }
            .filterValues { it.isNotEmpty() }
    }

    val fromFile = loadArmLocal()
    val extras = linkedMapOf<String, String>()
    fromFile.forEach { (k, v) ->
        if (prop(k) == null) extras[k] = v
    }

    if (prop("android.aapt2FromMavenOverride") == null &&
        System.getenv("AAPT2_OVERRIDE").isNullOrBlank() &&
        !extras.containsKey("android.aapt2FromMavenOverride")
    ) {
        val prefix = System.getenv("PREFIX") // Termux
        val candidates = listOfNotNull(
            System.getenv("AAPT2_PATH"),
            "/usr/bin/aapt2",
            prefix?.let { "$it/bin/aapt2" },
            System.getenv("ANDROID_HOME")?.let { "$it/build-tools/35.0.2/aapt2" },
            System.getenv("ANDROID_HOME")?.let { "$it/build-tools/36.0.0/aapt2" },
            System.getenv("ANDROID_SDK_ROOT")?.let { "$it/build-tools/35.0.2/aapt2" },
        )
        candidates.firstOrNull { path ->
            val f = file(path)
            f.isFile && f.canExecute()
        }?.let { extras["android.aapt2FromMavenOverride"] = it }
    }

    if (extras.isNotEmpty()) {
        val merged = HashMap(gradle.startParameter.projectProperties)
        extras.forEach { (k, v) -> merged.putIfAbsent(k, v) }
        gradle.startParameter.setProjectProperties(merged)
    }
}
