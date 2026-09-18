package app.slipnet.product

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.testsupport.DeviceTestEntryPoint
import app.slipnet.data.export.ConfigExporter
import app.slipnet.data.export.ConfigImporter
import app.slipnet.data.export.ImportResult
import dagger.hilt.EntryPoints
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class R4ProductSurfaceInstrumentedTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() =
        EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun personalLabelAndFailureMetadataRoundTripPreserveEchSeed() = runBlocking {
        assertEquals("SlipNet EA", context.packageManager.getApplicationLabel(context.applicationInfo).toString())
        val repo = entryPoint.profileRepository()
        val active = repo.getActiveProfile().first()
        assertNotNull("active profile required", active)
        val original = active!!
        val disposable = original.copy(
            id = 0,
            name = "SlipNet EA R4 metadata lab",
            vlessFailureProviderId = "r4-provider",
            vlessFailureAccountId = "r4-account",
            vlessFailureHostname = "r4-failure.example",
        )
        var createdId = 0L
        try {
            createdId = repo.saveProfile(disposable)
            val loaded = repo.getProfileById(createdId)
            assertNotNull("saved profile missing", loaded)
            loaded!!
            assertEquals("r4-provider", loaded.vlessFailureProviderId)
            assertEquals("r4-account", loaded.vlessFailureAccountId)
            assertEquals("r4-failure.example", loaded.vlessFailureHostname)
            assertEquals(original.vlessEchConfigSeed, loaded.vlessEchConfigSeed)
            assertEquals(original.vlessEchConfigUpdatedAt, loaded.vlessEchConfigUpdatedAt)

            val exported = ConfigExporter().exportSingleProfile(loaded)
            val importedResult = ConfigImporter().parseAndImport(exported)
            assertTrue("v29 export/import failed: $importedResult", importedResult is ImportResult.Success)
            val imported = (importedResult as ImportResult.Success).profiles.single()
            assertEquals("r4-provider", imported.vlessFailureProviderId)
            assertEquals("r4-account", imported.vlessFailureAccountId)
            assertEquals("r4-failure.example", imported.vlessFailureHostname)
            assertEquals(loaded.vlessEchConfigSeed, imported.vlessEchConfigSeed)
            assertEquals(loaded.vlessEchConfigUpdatedAt, imported.vlessEchConfigUpdatedAt)
            assertTrue("original active profile changed", repo.getActiveProfile().first()?.id == original.id)
        } finally {
            if (createdId > 0) repo.deleteProfile(createdId)
            repo.setActiveProfile(original.id)
        }
    }
}
