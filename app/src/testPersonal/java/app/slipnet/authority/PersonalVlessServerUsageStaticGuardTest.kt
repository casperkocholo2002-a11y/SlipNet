package app.slipnet.authority

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersonalVlessServerUsageStaticGuardTest {
    private fun source(path: String): String {
        val candidates = listOf(File(path), File("app/" + path))
        return candidates.firstOrNull { it.isFile }?.readText() ?: error(path + " not found")
    }

    @Test
    fun unlockedPersonalVlessAdoptsServerUsageAfterAuthenticatedProbe() {
        val service = source("src/main/java/app/slipnet/service/SlipNetVpnService.kt")
        val marker = "timeoutMs = 2_500"
        assertTrue(service.windowed(marker.length).count { it == marker } == 2)
        assertTrue(service.contains("val authProbe = withContext(Dispatchers.IO) { VlessBridge.probeAuthenticated() }"))
        assertTrue(service.contains(".onSuccess { managedUsage = it }"))
    }

    @Test
    fun repositoryAuthorityIsNotRestrictedToLockedProfiles() {
        val repository = source("src/main/java/app/slipnet/data/repository/VpnRepositoryImpl.kt")
        val syncStart = repository.indexOf("suspend fun syncManagedSubscriptionUsage")
        val syncEnd = repository.indexOf("private fun applyManagedSubscriptionUsage", syncStart)
        val syncBlock = repository.substring(syncStart, syncEnd)
        assertFalse(syncBlock.contains("!profile.isLocked"))

        val applyStart = repository.indexOf("private fun applyManagedSubscriptionUsage")
        val applyEnd = repository.indexOf("fun refreshTrafficStats", applyStart)
        val applyBlock = repository.substring(applyStart, applyEnd)
        assertFalse(applyBlock.contains("!profile.isLocked"))
        assertTrue(applyBlock.contains("managedUsageProfileId != profile.id"))
    }

    @Test
    fun eachVlessConnectClearsOnlyActiveServerAuthorityBeforeFreshSync() {
        val service = source("src/main/java/app/slipnet/service/SlipNetVpnService.kt")
        val marker = "vpnRepository.clearServerAuthoritativeUsageSession()"
        assertTrue(service.windowed(marker.length).count { it == marker } == 2)
    }

    @Test
    fun unlockedFallbackIsLimitedToOptionalAuthorityFailures() {
        val service = source("src/main/java/app/slipnet/service/SlipNetVpnService.kt")
        assertTrue(service.contains("OptionalSubscriptionAuthorityException"))
        assertTrue(service.contains("FatalSubscriptionAuthorityException"))
        assertTrue(service.contains("usageFailure !is OptionalSubscriptionAuthorityException"))
        assertTrue(service.contains("Subscription authority returned HTTP"))
    }

    @Test
    fun visibleSubscriptionLabelUsesActualServerAuthorityNotProfileLock() {
        val repository = source("src/main/java/app/slipnet/data/repository/VpnRepositoryImpl.kt")
        val screen = source("src/main/java/app/slipnet/presentation/main/MainScreen.kt")
        assertTrue(repository.contains("isServerAuthoritative = true"))
        assertTrue(screen.contains("isSubscriptionUsage = uiState.trafficStats.isServerAuthoritative"))
        assertFalse(screen.contains("isSubscriptionUsage = uiState.activeProfile?.isLocked == true"))
    }

    @Test
    fun oneTimeEnrollmentIsClaimedByFirstConnectWithoutActivationDialog() {
        val screen = source("src/main/java/app/slipnet/presentation/main/MainScreen.kt")
        val viewModel = source("src/main/java/app/slipnet/presentation/main/MainViewModel.kt")
        val preferences = source("src/main/java/app/slipnet/data/local/datastore/PreferencesDataStore.kt")
        val enrollment = source("src/main/java/app/slipnet/data/enrollment/EnrollmentManager.kt")

        assertFalse(screen.contains("Activate on this device?"))
        assertFalse(viewModel.contains("fun confirmEnrollment()"))
        assertTrue(viewModel.contains("setPendingEnrollment("))
        assertTrue(viewModel.contains("getPendingEnrollment(targetProfile.id)"))
        assertTrue(viewModel.contains("connectPendingEnrollment(targetProfile, pendingEnrollment)"))
        assertTrue(viewModel.contains("enrollmentImportMutex.withLock"))
        assertTrue(viewModel.contains("getProfilesUseCase().first().firstOrNull"))
        assertFalse(viewModel.contains("_uiState.value.profiles.firstOrNull { profile ->\n                            profile.name == name"))
        assertTrue(preferences.contains("pending_enrollment_\${profileId}_v1"))
        assertTrue(enrollment.contains("ENROLLMENT_TRUSTED_WORKER_SUFFIXES"))
        assertTrue(enrollment.contains("backupEndpoint"))
    }
}
