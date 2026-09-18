package app.slipnet.emergencydns

import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.domain.model.ResolverScanResult
import kotlinx.coroutines.flow.first
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ResolverMemoryStore @Inject constructor(
    private val preferences: PreferencesDataStore,
) {
    suspend fun load(): List<ResolverMemoryRecord> =
        ResolverMemoryCodec.decode(preferences.emergencyDnsResolverMemory.first())

    suspend fun learn(
        scopeId: String,
        result: ResolverScanResult,
        nowMs: Long = System.currentTimeMillis(),
    ): List<ResolverMemoryRecord> {
        val updated = ResolverMemoryCodec.update(
            records = load(),
            scopeId = scopeId,
            host = result.host,
            port = result.port,
            success = result.isEmergencyDiscoverySuccess(),
            prismVerified = result.prismVerified == true,
            nowMs = nowMs,
        )
        preferences.setEmergencyDnsResolverMemory(ResolverMemoryCodec.encode(updated))
        return updated
    }

    suspend fun clear() = preferences.setEmergencyDnsResolverMemory("")
}
