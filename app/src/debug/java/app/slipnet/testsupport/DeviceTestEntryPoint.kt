package app.slipnet.testsupport

import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.repository.ProfileRepository
import app.slipnet.service.VpnConnectionManager
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

@EntryPoint
@InstallIn(SingletonComponent::class)
interface DeviceTestEntryPoint {
    fun profileRepository(): ProfileRepository
    fun preferencesDataStore(): PreferencesDataStore
    fun vpnConnectionManager(): VpnConnectionManager
}
