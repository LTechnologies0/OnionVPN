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
