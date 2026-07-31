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
)
