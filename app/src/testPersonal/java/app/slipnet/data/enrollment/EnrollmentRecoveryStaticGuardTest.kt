package app.slipnet.data.enrollment

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentRecoveryStaticGuardTest {
    private fun source(path: String): String {
        val candidates = listOf(File(path), File("app/" + path))
        return candidates.firstOrNull { it.isFile }?.readText()
            ?: error(path + " not found")
    }

    @Test
    fun durablePairMarkerPrecedesCompletionAndSurvivesCompletionFailure() {
        val viewModel = source(
            "src/main/java/app/slipnet/presentation/main/MainViewModel.kt"
        )
        val start = viewModel.indexOf(
            "private suspend fun connectPendingEnrollment"
        )
        val end = viewModel.indexOf("fun disconnect()", start)
        val block = viewModel.substring(start, end)

        val recoveryRead = block.indexOf(
            "getPendingEnrollmentPair(placeholder.id)"
        )
        val redeem = block.indexOf("enrollmentManager.redeem(enrollment)")
        val marker = block.indexOf(
            "preferencesDataStore.setPendingEnrollmentPair("
        )
        val finalize = block.indexOf(
            "val activePrimary = finalizePendingEnrollment("
        )

        assertTrue(start >= 0)
        assertTrue(end > start)
        assertTrue(recoveryRead >= 0)
        assertTrue(redeem > recoveryRead)
        assertTrue(marker > redeem)
        assertTrue(finalize > marker)
        assertTrue(block.contains("var recoveryMarkerWritten = false"))
        assertTrue(block.contains("recoveryMarkerWritten = true"))
        assertTrue(block.contains("if (!recoveryMarkerWritten)"))
        assertTrue(block.contains("for (id in createdIds)"))
    }

    @Test
    fun serverCompletionPrecedesPlaceholderDeletionAndPendingStateClear() {
        val viewModel = source(
            "src/main/java/app/slipnet/presentation/main/MainViewModel.kt"
        )
        val start = viewModel.indexOf(
            "private suspend fun finalizePendingEnrollment"
        )
        val end = viewModel.indexOf(
            "private suspend fun connectPendingEnrollment",
            start,
        )
        val block = viewModel.substring(start, end)

        val complete = block.indexOf(
            "enrollmentManager.complete(enrollment).getOrThrow()"
        )
        val activate = block.indexOf(
            "setActiveProfileUseCase(managedPair.primary.id)"
        )
        val deletePlaceholder = block.indexOf(
            "deleteProfileUseCase(placeholder.id)"
        )
        val clearPending = block.indexOf(
            "preferencesDataStore.clearPendingEnrollment(placeholder.id)"
        )

        assertTrue(start >= 0)
        assertTrue(end > start)
        assertTrue(complete >= 0)
        assertTrue(activate > complete)
        assertTrue(deletePlaceholder > activate)
        assertTrue(clearPending > deletePlaceholder)
    }

    @Test
    fun pendingPairUsesExactPersistedIdsAndClearRemovesBothRecoveryKeys() {
        val viewModel = source(
            "src/main/java/app/slipnet/presentation/main/MainViewModel.kt"
        )
        val preferences = source(
            "src/main/java/app/slipnet/data/local/datastore/PreferencesDataStore.kt"
        )

        assertTrue(viewModel.contains("profileRepository.getProfileById(recoveryIds.first)"))
        assertTrue(viewModel.contains("profileRepository.getProfileById(recoveryIds.second)"))
        assertTrue(viewModel.contains("hasSameEnrollmentIdentity(it, profile)"))
        assertTrue(viewModel.contains("require(matches.size <= 1)"))
        assertTrue(preferences.contains("pending_enrollment_pair_"))

        val clearStart = preferences.indexOf(
            "suspend fun clearPendingEnrollment(profileId: Long)"
        )
        val clearEnd = preferences.indexOf(
            "private fun managedUsageSentKey",
            clearStart,
        )
        val clearBlock = preferences.substring(clearStart, clearEnd)
        assertTrue(clearStart >= 0)
        assertTrue(clearEnd > clearStart)
        assertTrue(clearBlock.contains("prefs.remove(pendingEnrollmentKey(profileId))"))
        assertTrue(clearBlock.contains("prefs.remove(pendingEnrollmentPairKey(profileId))"))
    }

    @Test
    fun completionUsesDistinctSignedClaimAndTrustedCompleteEndpoint() {
        val enrollment = source(
            "src/main/java/app/slipnet/data/enrollment/EnrollmentManager.kt"
        )

        assertTrue(enrollment.contains("COMPLETE_CLAIM_VERSION"))
        assertTrue(enrollment.contains("slipnet-enroll-complete-v1"))
        assertTrue(enrollment.contains("claimVersion = COMPLETE_CLAIM_VERSION"))
        assertTrue(enrollment.contains("val version: Int"))
        assertTrue(enrollment.contains("require(version in 1..2)"))
        assertTrue(enrollment.contains("if (!descriptor.requiresCompletion)"))
        assertTrue(enrollment.contains("/api/enrollment/complete"))
        assertTrue(enrollment.contains("/complete"))
    }
}
