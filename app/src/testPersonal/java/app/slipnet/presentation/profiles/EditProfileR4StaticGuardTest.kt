package app.slipnet.presentation.profiles

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class EditProfileR4StaticGuardTest {
    private fun source(name: String): String {
        val candidates = listOf(
            File("src/main/java/app/slipnet/presentation/profiles/$name"),
            File("app/src/main/java/app/slipnet/presentation/profiles/$name"),
        )
        return candidates.firstOrNull { it.isFile }?.readText()
            ?: error("$name not found")
    }

    @Test
    fun editFlowPreservesEchAndPersistsExplicitFailureDomains() {
        val vm = source("EditProfileViewModel.kt")
        for (field in listOf("vlessFailureProviderId", "vlessFailureAccountId", "vlessFailureHostname")) {
            assertTrue(vm.contains("$field = profile.$field"))
            assertTrue(vm.contains("$field = if (state.isVless) state.$field.trim() else \"\""))
        }
        assertTrue(vm.contains("vlessEchConfigSeed = profile.vlessEchConfigSeed"))
        assertTrue(vm.contains("vlessEchConfigSeed = if (state.isVless) state.vlessEchConfigSeed else \"\""))
        assertTrue(vm.contains("vlessEchConfigUpdatedAt = if (state.isVless) state.vlessEchConfigUpdatedAt else 0L"))
    }

    @Test
    fun personalEditorExposesOnlyExplicitFailureDomainInputsAndDefaultsToEchMode() {
        val vm = source("EditProfileViewModel.kt")
        val screen = source("EditProfileScreen.kt")
        assertTrue(vm.contains("sniFragmentEnabled: Boolean = !BuildConfig.PERSONAL_BUILD"))
        assertTrue(screen.contains("Provider ID"))
        assertTrue(screen.contains("Account ID"))
        assertTrue(screen.contains("Failure Hostname"))
        assertTrue(screen.contains("Values are never inferred"))
        assertTrue(screen.contains("ECH_REQUIRED uses the stored ECH seed"))
    }
}
