package app.slipnet.tunnel

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class EchSeedProvisioningInstrumentedTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() = EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun provisionActiveProfileSeedAndRoundTrip() = runBlocking {
        val encoded = InstrumentationRegistry.getArguments().getString("echSeed").orEmpty().trim()
        val bytes = EchConfigResolver.decodeStoredSeed(encoded)
        assertNotNull("valid non-empty echSeed argument required", bytes)
        assertTrue(bytes!!.isNotEmpty())
        val repo = entryPoint.profileRepository()
        val active = repo.getActiveProfile().first()
        assertNotNull("active profile required", active)
        val now = System.currentTimeMillis()
        repo.updateProfile(active!!.copy(vlessEchConfigSeed = encoded, vlessEchConfigUpdatedAt = now))
        val reloaded = repo.getProfileById(active.id)
        assertNotNull(reloaded)
        assertTrue(reloaded!!.vlessEchConfigUpdatedAt >= now)
        assertArrayEquals(bytes, EchConfigResolver.decodeStoredSeed(reloaded.vlessEchConfigSeed))
    }
}
