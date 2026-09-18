package app.slipnet.authority

import org.junit.Assert.assertEquals
import org.junit.Test

class PersonalVlessSwitchGuardTest {
    private val target = PersonalVlessRouteDescriptor(2, "profile:2", "p2", "a2", "b.example")

    @Test fun exactFreshTargetIsAdmitted() {
        assertEquals(
            PersonalVlessSwitchDecision.ADMIT,
            PersonalVlessSwitchGuard.decide(1, target, target.copy(), emptySet()),
        )
    }

    @Test fun missingTargetIsRejected() {
        assertEquals(
            PersonalVlessSwitchDecision.NO_TARGET,
            PersonalVlessSwitchGuard.decide(1, null, null, emptySet()),
        )
    }

    @Test fun sameProfileTargetIsRejected() {
        val same = target.copy(profileId = 1, routeId = "profile:1")
        assertEquals(
            PersonalVlessSwitchDecision.SAME_PROFILE,
            PersonalVlessSwitchGuard.decide(1, same, same, emptySet()),
        )
    }

    @Test fun attemptedTargetPreventsSwitchLoop() {
        assertEquals(
            PersonalVlessSwitchDecision.TARGET_ALREADY_ATTEMPTED,
            PersonalVlessSwitchGuard.decide(1, target, target, setOf(2L)),
        )
    }

    @Test fun incompleteMetadataIsRejected() {
        val incomplete = target.copy(accountId = "")
        assertEquals(
            PersonalVlessSwitchDecision.TARGET_METADATA_INCOMPLETE,
            PersonalVlessSwitchGuard.decide(1, incomplete, incomplete, emptySet()),
        )
    }

    @Test fun staleMetadataIsRejected() {
        val changed = target.copy(hostname = "changed.example")
        assertEquals(
            PersonalVlessSwitchDecision.TARGET_STALE,
            PersonalVlessSwitchGuard.decide(1, target, changed, emptySet()),
        )
    }

    @Test fun disabledTargetIsRejected() {
        val disabled = target.copy(enabled = false)
        assertEquals(
            PersonalVlessSwitchDecision.TARGET_DISABLED,
            PersonalVlessSwitchGuard.decide(1, disabled, disabled, emptySet()),
        )
    }
}
