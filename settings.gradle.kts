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
includeBuild("../../kotlin-tor") {
    dependencySubstitution {
        substitute(module("org.kotlintor:android")).using(project(":android"))
        substitute(module("org.kotlintor:core")).using(project(":core"))
        substitute(module("org.kotlintor:control")).using(project(":control"))
        substitute(module("org.kotlintor:proxy")).using(project(":proxy"))
    }
}
