package app.slipnet.tunnel

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.domain.model.TunnelType
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticatedEchSeedPersistenceInstrumentedTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() =
        EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun exactIdAtomicSeedUpdatePreservesLatestProfileState() = runBlocking {
        val repository = entryPoint.profileRepository()
        val manager = entryPoint.vpnConnectionManager()
        val source = repository.getActiveProfile().first() ?: error("active profile required")
        require(source.tunnelType == TunnelType.VLESS) { "active VLESS profile required" }
        var targetId = -1L
        var neighborId = -1L
        try {
            targetId = repository.saveProfile(
                source.copy(
                    id = 0L,
                    name = "SlipNet EA ECH Renewal Persistence Target",
                    isActive = false,
                    vlessFailureProviderId = "renewal-target-provider",
                    vlessFailureAccountId = "renewal-target-account",
                    vlessFailureHostname = "renewal-target.invalid",
                    vlessEchConfigUpdatedAt = 17L,
                )
            )
            neighborId = repository.saveProfile(
                source.copy(
                    id = 0L,
                    name = "SlipNet EA ECH Renewal Persistence Neighbor",
                    isActive = false,
                    vlessFailureProviderId = "renewal-neighbor-provider",
                    vlessFailureAccountId = "renewal-neighbor-account",
                    vlessFailureHostname = "renewal-neighbor.invalid",
                )
            )

            val beforeEdit = requireNotNull(repository.getProfileById(targetId))
            val edited = beforeEdit.copy(
                name = "SlipNet EA ECH Renewal Persistence Target Edited",
                vlessFailureProviderId = "renewal-target-provider-edited",
                sortOrder = beforeEdit.sortOrder + 137,
                updatedAt = beforeEdit.updatedAt + 1L,
            )
            repository.updateProfile(edited)
            val neighborBefore = requireNotNull(repository.getProfileById(neighborId))

            val accepted = byteArrayOf(0x00, 0x03, 0x01, 0x02, 0x03)
            val encoded = requireNotNull(EchConfigResolver.encodeStoredSeed(accepted))
            val timestamp = 1_789_550_000_123L
            assertTrue(manager.persistAuthenticatedVlessEchSeed(targetId, accepted, timestamp))

            val after = requireNotNull(repository.getProfileById(targetId))
            assertEquals(encoded, after.vlessEchConfigSeed)
            assertEquals(timestamp, after.vlessEchConfigUpdatedAt)
            assertEquals(
                edited.copy(
                    vlessEchConfigSeed = encoded,
                    vlessEchConfigUpdatedAt = timestamp,
                ),
                after,
            )
            assertEquals(neighborBefore, repository.getProfileById(neighborId))
        } finally {
            if (targetId > 0) try { repository.deleteProfile(targetId) } catch (_: Exception) {}
            if (neighborId > 0) try { repository.deleteProfile(neighborId) } catch (_: Exception) {}
        }
    }
}
