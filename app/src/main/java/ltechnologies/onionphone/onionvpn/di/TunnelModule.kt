package ltechnologies.onionphone.onionvpn.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import ltechnologies.onionphone.onionvpn.core.dnscrypt.DnsCryptProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.TorProcessManager
import ltechnologies.onionphone.onionvpn.core.tor.control.lifecycle.CircuitLifecycleManager

@Module
@InstallIn(SingletonComponent::class)
object TunnelModule {
    @Provides
    @Singleton
    fun provideTorProcessManager(
        @ApplicationContext context: Context,
    ): TorProcessManager = TorProcessManager(context)

    @Provides
    @Singleton
    fun provideDnsCryptProcessManager(
        @ApplicationContext context: Context,
    ): DnsCryptProcessManager = DnsCryptProcessManager(context)

    @Provides
    @Singleton
    fun provideCircuitLifecycleManager(
        @ApplicationContext context: Context,
        tor: TorProcessManager,
    ): CircuitLifecycleManager = CircuitLifecycleManager(context, tor.control)
}
