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
    ":core:model",
    ":core:tor",
    ":core:dnscrypt",
    ":core:vpn",
    ":core:validation",
    ":third_party:onionmasq-android",
)

// kotlin-tor composite: TorEngine.KOTLIN_TOR on HEV_SOCKS
fun kotlinTorRoot(): java.io.File {
    val env = System.getenv("KOTLIN_TOR_HOME")
    if (!env.isNullOrBlank()) {
        val fromEnv = file(env)
        if (fromEnv.resolve("settings.gradle.kts").isFile) return fromEnv
    }
    val candidates = listOf(
        rootDir.resolve("../kotlin-tor"),
        rootDir.resolve("../../kotlin-tor"),
        rootDir.resolve("third_party/kotlin-tor"),
    )
    return candidates.firstOrNull { it.resolve("settings.gradle.kts").isFile }
        ?: error(
            "kotlin-tor not found. Clone https://github.com/LTechnologies0/kotlin-tor " +
                "next to this repo (../kotlin-tor or ../../kotlin-tor), or set KOTLIN_TOR_HOME.",
        )
}

includeBuild(kotlinTorRoot()) {
    dependencySubstitution {
        substitute(module("org.kotlintor:android")).using(project(":android"))
        substitute(module("org.kotlintor:core")).using(project(":core"))
        substitute(module("org.kotlintor:control")).using(project(":control"))
        substitute(module("org.kotlintor:proxy")).using(project(":proxy"))
    }
}
