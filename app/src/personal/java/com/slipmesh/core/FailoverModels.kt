package com.slipmesh.core


enum class FailoverState {
    STABLE,
    PROBING,
    FAILING_OVER,
    RECOVERING,
    DEGRADED
}


enum class FailoverAction {
    NONE,
    PROBE_CURRENT,
    SWITCH_TO_TARGET,
    WAIT_COOLDOWN,
    WAIT_FOR_ROUTE
}


enum class FailoverCause {
    CURRENT_HEALTHY,
    HEALTH_UNKNOWN,
    FAILURE_BELOW_THRESHOLD,
    FAILURE_THRESHOLD_REACHED,
    CURRENT_UNREACHABLE,
    SUSPECTED_BLOCK,
    ROUTE_IN_COOLDOWN,
    NETWORK_CHANGED,
    NO_ACTIVE_ROUTE,
    ACTIVE_ROUTE_UNAVAILABLE,
    NO_ALTERNATE_ROUTE,
    COOLDOWN_ACTIVE,
    SWITCH_IN_PROGRESS,
    SWITCH_SUCCEEDED,
    SWITCH_FAILED,
    RECOVERY_PROGRESS,
    RECOVERY_COMPLETE,
    ACTIVE_ROUTE_SUCCESS,
    STALE_EVENT,
    NON_ACTIVE_SUCCESS,
    UNEXPECTED_SWITCH_RESULT
}


data class FailoverPolicyConfig(
    val failoverFailureThreshold: Int = 2,
    val recoverySuccessThreshold: Int = 2,
    val switchCooldownMs: Long = 15_000L,
    val failedTargetRetryMs: Long = 10_000L
) {
    init {
        require(failoverFailureThreshold > 0)
        require(recoverySuccessThreshold > 0)
        require(switchCooldownMs >= 0)
        require(failedTargetRetryMs >= 0)
    }
}


data class FailoverSnapshot(
    val state: FailoverState = FailoverState.STABLE,
    val activeRouteId: String? = null,
    val previousRouteId: String? = null,
    val targetRouteId: String? = null,
    val recoverySuccesses: Int = 0,
    val cooldownUntilEpochMs: Long? = null,
    val failedTargetRetryUntilEpochMs: Map<String, Long> =
        emptyMap(),
    val lastEventEpochMs: Long = 0L
) {
    init {
        require(
            activeRouteId == null ||
                activeRouteId.isNotBlank()
        )

        require(
            previousRouteId == null ||
                previousRouteId.isNotBlank()
        )

        require(
            targetRouteId == null ||
                targetRouteId.isNotBlank()
        )

        require(recoverySuccesses >= 0)
        require(lastEventEpochMs >= 0)

        require(
            cooldownUntilEpochMs == null ||
                cooldownUntilEpochMs >= 0
        )

        require(
            failedTargetRetryUntilEpochMs.keys
                .all { it.isNotBlank() }
        )

        require(
            failedTargetRetryUntilEpochMs.values
                .all { it >= 0 }
        )
    }
}


sealed interface FailoverEvent {

    val timestampEpochMs: Long


    data class Evaluate(
        val activeHealth: RouteHealth,
        val alternativeRouteId: String?,
        val activeRouteAvailable: Boolean = true,
        val networkChanged: Boolean = false,
        override val timestampEpochMs: Long
    ) : FailoverEvent {
        init {
            require(
                alternativeRouteId == null ||
                    alternativeRouteId.isNotBlank()
            )

            require(timestampEpochMs >= 0)
        }
    }


    data class SwitchSucceeded(
        val routeId: String,
        override val timestampEpochMs: Long
    ) : FailoverEvent {
        init {
            require(routeId.isNotBlank())
            require(timestampEpochMs >= 0)
        }
    }


    data class SwitchFailed(
        val routeId: String,
        override val timestampEpochMs: Long
    ) : FailoverEvent {
        init {
            require(routeId.isNotBlank())
            require(timestampEpochMs >= 0)
        }
    }


    data class TerminalSuccess(
        val routeId: String,
        override val timestampEpochMs: Long
    ) : FailoverEvent {
        init {
            require(routeId.isNotBlank())
            require(timestampEpochMs >= 0)
        }
    }
}


data class FailoverTransition(
    val snapshot: FailoverSnapshot,
    val action: FailoverAction,
    val cause: FailoverCause
)
