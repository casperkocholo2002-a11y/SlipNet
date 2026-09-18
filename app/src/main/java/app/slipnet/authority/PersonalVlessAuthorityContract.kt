package app.slipnet.authority

enum class PersonalVlessAuthorityFact {
    STRUCTURAL_SUCCESS, STRUCTURAL_FAILURE, TERMINAL_SUCCESS,
    TRANSPORT_FAILURE, TRANSPORT_STALL, NETWORK_CHANGED,
}

enum class PersonalVlessReconnectOrigin { USER_EXPLICIT, AUTONOMOUS }

enum class PersonalVlessReconnectDisposition {
    ALLOW_LEGACY, ALLOW_USER_SAME_PROFILE, BLOCK_FAIL_CLOSED,
}

data class PersonalVlessRouteDescriptor(
    val profileId: Long,
    val routeId: String,
    val providerId: String,
    val accountId: String,
    val hostname: String,
    val basePriority: Int = 100,
    val enabled: Boolean = true,
) {
    val hasCompleteFailureDomain: Boolean
        get() = providerId.isNotBlank() && accountId.isNotBlank() && hostname.isNotBlank()
}

data class PersonalVlessAuthorityHookSnapshot(
    val routeId: String,
    val healthState: String,
    val lastFailure: String,
    val authorityAction: String,
    val qualifiedSwitchTarget: String?,
)

enum class PersonalVlessSwitchDecision {
    ADMIT,
    NO_TARGET,
    SAME_PROFILE,
    TARGET_ALREADY_ATTEMPTED,
    TARGET_DISABLED,
    TARGET_METADATA_INCOMPLETE,
    TARGET_STALE,
}

object PersonalVlessSwitchGuard {
    fun decide(
        activeProfileId: Long,
        expectedTarget: PersonalVlessRouteDescriptor?,
        latestTarget: PersonalVlessRouteDescriptor?,
        attemptedProfileIds: Set<Long>,
    ): PersonalVlessSwitchDecision {
        val expected = expectedTarget ?: return PersonalVlessSwitchDecision.NO_TARGET
        if (expected.profileId == activeProfileId) return PersonalVlessSwitchDecision.SAME_PROFILE
        if (expected.profileId in attemptedProfileIds) {
            return PersonalVlessSwitchDecision.TARGET_ALREADY_ATTEMPTED
        }
        if (!expected.enabled) return PersonalVlessSwitchDecision.TARGET_DISABLED
        if (!expected.hasCompleteFailureDomain) {
            return PersonalVlessSwitchDecision.TARGET_METADATA_INCOMPLETE
        }
        val latest = latestTarget ?: return PersonalVlessSwitchDecision.TARGET_STALE
        if (!latest.enabled) return PersonalVlessSwitchDecision.TARGET_DISABLED
        if (!latest.hasCompleteFailureDomain) {
            return PersonalVlessSwitchDecision.TARGET_METADATA_INCOMPLETE
        }
        if (latest != expected) return PersonalVlessSwitchDecision.TARGET_STALE
        return PersonalVlessSwitchDecision.ADMIT
    }
}

interface PersonalVlessAuthorityHooks {
    fun selectRoute(activeRoute: PersonalVlessRouteDescriptor, routes: List<PersonalVlessRouteDescriptor>)
    fun clearRoute()
    fun observe(fact: PersonalVlessAuthorityFact, detail: String?, timestampEpochMs: Long)
    fun reconnectDisposition(origin: PersonalVlessReconnectOrigin): PersonalVlessReconnectDisposition
    fun qualifiedSwitchTargetDescriptorOrNull(): PersonalVlessRouteDescriptor?
    fun snapshot(): PersonalVlessAuthorityHookSnapshot?
}

class NoOpPersonalVlessAuthorityHooks : PersonalVlessAuthorityHooks {
    override fun selectRoute(activeRoute: PersonalVlessRouteDescriptor, routes: List<PersonalVlessRouteDescriptor>) = Unit
    override fun clearRoute() = Unit
    override fun observe(fact: PersonalVlessAuthorityFact, detail: String?, timestampEpochMs: Long) = Unit
    override fun reconnectDisposition(origin: PersonalVlessReconnectOrigin) = PersonalVlessReconnectDisposition.ALLOW_LEGACY
    override fun qualifiedSwitchTargetDescriptorOrNull(): PersonalVlessRouteDescriptor? = null
    override fun snapshot(): PersonalVlessAuthorityHookSnapshot? = null
}
