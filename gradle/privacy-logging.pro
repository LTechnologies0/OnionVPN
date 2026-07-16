# Privacy-safe release logging — strip verbose Timber in release.

-assumenosideeffects class timber.log.Timber {
    public static void v(...);
    public static void d(...);
}
