package com.slipmesh.core


/**
 * Pure deterministic failover state machine.
 *
 * Route-health collection and route selection remain outside this class.
 * The caller supplies:
 *
 * 1. current route health
 * 2. a selected alternative route, if one exists
 * 3. explicit switch/success events
 *
 * No networking, Android, persistence or production dependency exists here.
 */
object FailoverStateMachine {


    fun transition(
        snapshot: FailoverSnapshot,
        event: FailoverEvent,
        config: FailoverPolicyConfig =
            FailoverPolicyConfig()
    ): FailoverTransition {

        if (
            event.timestampEpochMs <
            snapshot.lastEventEpochMs
        ) {
            return FailoverTransition(
                snapshot = snapshot,
                action = FailoverAction.NONE,
                cause = FailoverCause.STALE_EVENT
            )
        }

        val effectiveSnapshot =
            expireFailedTargetRetriesIfNeeded(
                snapshot =
                    expireCooldownIfNeeded(
                        snapshot = snapshot,
                        now = event.timestampEpochMs
                    ),
                now = event.timestampEpochMs
            )

        return when (event) {

            is FailoverEvent.Evaluate ->
                evaluate(
                    snapshot = effectiveSnapshot,
                    event = event,
                    config = config
                )

            is FailoverEvent.SwitchSucceeded ->
                switchSucceeded(
                    snapshot = effectiveSnapshot,
                    event = event,
                    config = config
                )

            is FailoverEvent.SwitchFailed ->
                switchFailed(
                    snapshot = effectiveSnapshot,
                    event = event,
                    config = config
                )

            is FailoverEvent.TerminalSuccess ->
                terminalSuccess(
                    snapshot = effectiveSnapshot,
                    event = event,
                    config = config
                )
        }
    }


    /**
     * Recovery confidence and anti-flap cooldown are separate controls.
     *
     * previousRouteId remains available while the cooldown is active so
     * a non-critical switch back can be blocked. Once the deadline has
     * actually passed, the hysteresis metadata can be discarded.
     */
    private fun expireCooldownIfNeeded(
        snapshot: FailoverSnapshot,
        now: Long
    ): FailoverSnapshot {

        val deadline =
            snapshot.cooldownUntilEpochMs
                ?: return snapshot

        if (now < deadline) {
            return snapshot
        }

        return snapshot.copy(
            previousRouteId = null,
            cooldownUntilEpochMs = null
        )
    }


    /**
     * Failed transport-switch targets are suppressed only by policy.
     *
     * Their retry deadline is not written into HealthStore because a
     * failed switch operation is not proof of DNS/TCP/TLS failure.
     */
    private fun expireFailedTargetRetriesIfNeeded(
        snapshot: FailoverSnapshot,
        now: Long
    ): FailoverSnapshot {

        if (
            snapshot.failedTargetRetryUntilEpochMs
                .isEmpty()
        ) {
            return snapshot
        }

        val retained =
            snapshot.failedTargetRetryUntilEpochMs
                .filterValues { retryUntil ->
                    now < retryUntil
                }

        if (
            retained.size ==
            snapshot.failedTargetRetryUntilEpochMs.size
        ) {
            return snapshot
        }

        return snapshot.copy(
            failedTargetRetryUntilEpochMs =
                retained
        )
    }


    private fun evaluate(
        snapshot: FailoverSnapshot,
        event: FailoverEvent.Evaluate,
        config: FailoverPolicyConfig
    ): FailoverTransition {

        val now =
            event.timestampEpochMs

        /*
         * A transport switch is an outstanding operation.
         *
         * Do not re-evaluate, replace or clear the target until its
         * explicit SwitchSucceeded / SwitchFailed result arrives.
         *
         * We intentionally do not advance lastEventEpochMs here:
         * an asynchronously delivered switch result may have completed
         * before this later policy observation.
         */
        if (
            snapshot.state ==
            FailoverState.FAILING_OVER
        ) {
            return FailoverTransition(
                snapshot = snapshot,
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.SWITCH_IN_PROGRESS
            )
        }

        /*
         * A network change is not evidence that the route failed.
         * Probe again before making a switch decision.
         */
        if (event.networkChanged) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        state = FailoverState.PROBING,
                        targetRouteId = null,
                        recoverySuccesses = 0,
                        lastEventEpochMs = now
                    ),
                action = FailoverAction.PROBE_CURRENT,
                cause = FailoverCause.NETWORK_CHANGED
            )
        }


        val activeRouteId =
            snapshot.activeRouteId

        if (activeRouteId == null) {

            val alternative =
                event.alternativeRouteId

            return if (alternative != null) {

                FailoverTransition(
                    snapshot =
                        snapshot.copy(
                            state =
                                FailoverState.FAILING_OVER,
                            targetRouteId = alternative,
                            recoverySuccesses = 0,
                            lastEventEpochMs = now
                        ),
                    action =
                        FailoverAction.SWITCH_TO_TARGET,
                    cause =
                        FailoverCause.NO_ACTIVE_ROUTE
                )

            } else {

                FailoverTransition(
                    snapshot =
                        snapshot.copy(
                            state =
                                FailoverState.DEGRADED,
                            targetRouteId = null,
                            recoverySuccesses = 0,
                            lastEventEpochMs = now
                        ),
                    action =
                        FailoverAction.WAIT_FOR_ROUTE,
                    cause =
                        FailoverCause.NO_ALTERNATE_ROUTE
                )
            }
        }


        /*
         * Route configuration availability is not the same thing as
         * observed network health.
         *
         * If the active route disappeared from the permitted route set
         * or was explicitly disabled, fail over without inventing a
         * synthetic DNS/TCP/TLS failure.
         */
        if (!event.activeRouteAvailable) {

            return attemptFailover(
                snapshot = snapshot,
                alternativeRouteId =
                    event.alternativeRouteId,
                now = now,
                config = config,
                critical = true,
                cause =
                    FailoverCause.ACTIVE_ROUTE_UNAVAILABLE
            )
        }


        return when (
            event.activeHealth.state
        ) {

            HealthState.HEALTHY ->
                healthy(
                    snapshot = snapshot,
                    now = now
                )

            HealthState.UNKNOWN ->
                FailoverTransition(
                    snapshot =
                        snapshot.copy(
                            state =
                                FailoverState.PROBING,
                            targetRouteId = null,
                            lastEventEpochMs = now
                        ),
                    action =
                        FailoverAction.PROBE_CURRENT,
                    cause =
                        FailoverCause.HEALTH_UNKNOWN
                )

            HealthState.DEGRADED ->
                degraded(
                    snapshot = snapshot,
                    activeHealth =
                        event.activeHealth,
                    alternativeRouteId =
                        event.alternativeRouteId,
                    now = now,
                    config = config
                )

            HealthState.SUSPECTED_BLOCK ->
                attemptFailover(
                    snapshot = snapshot,
                    alternativeRouteId =
                        event.alternativeRouteId,
                    now = now,
                    config = config,
                    critical = true,
                    cause =
                        FailoverCause.SUSPECTED_BLOCK
                )

            HealthState.UNREACHABLE ->
                attemptFailover(
                    snapshot = snapshot,
                    alternativeRouteId =
                        event.alternativeRouteId,
                    now = now,
                    config = config,
                    critical = true,
                    cause =
                        FailoverCause.CURRENT_UNREACHABLE
                )

            HealthState.COOLDOWN ->
                attemptFailover(
                    snapshot = snapshot,
                    alternativeRouteId =
                        event.alternativeRouteId,
                    now = now,
                    config = config,
                    critical = true,
                    cause =
                        FailoverCause.ROUTE_IN_COOLDOWN
                )
        }
    }


    private fun healthy(
        snapshot: FailoverSnapshot,
        now: Long
    ): FailoverTransition {

        /*
         * RECOVERING requires explicit terminal-success events.
         * Merely observing HEALTHY repeatedly must not accidentally
         * satisfy the recovery hysteresis counter.
         */
        if (
            snapshot.state ==
            FailoverState.RECOVERING
        ) {
            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        lastEventEpochMs = now
                    ),
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.RECOVERY_PROGRESS
            )
        }

        return FailoverTransition(
            snapshot =
                snapshot.copy(
                    state = FailoverState.STABLE,
                    targetRouteId = null,
                    recoverySuccesses = 0,
                    lastEventEpochMs = now
                ),
            action = FailoverAction.NONE,
            cause =
                FailoverCause.CURRENT_HEALTHY
        )
    }


    private fun degraded(
        snapshot: FailoverSnapshot,
        activeHealth: RouteHealth,
        alternativeRouteId: String?,
        now: Long,
        config: FailoverPolicyConfig
    ): FailoverTransition {

        if (
            activeHealth.consecutiveFailures <
            config.failoverFailureThreshold
        ) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        state =
                            FailoverState.PROBING,
                        targetRouteId = null,
                        lastEventEpochMs = now
                    ),
                action =
                    FailoverAction.PROBE_CURRENT,
                cause =
                    FailoverCause.FAILURE_BELOW_THRESHOLD
            )
        }

        return attemptFailover(
            snapshot = snapshot,
            alternativeRouteId =
                alternativeRouteId,
            now = now,
            config = config,
            critical = false,
            cause =
                FailoverCause.FAILURE_THRESHOLD_REACHED
        )
    }


    private fun attemptFailover(
        snapshot: FailoverSnapshot,
        alternativeRouteId: String?,
        now: Long,
        config: FailoverPolicyConfig,
        critical: Boolean,
        cause: FailoverCause
    ): FailoverTransition {

        if (
            alternativeRouteId == null ||
            alternativeRouteId ==
                snapshot.activeRouteId
        ) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        state =
                            FailoverState.DEGRADED,
                        targetRouteId = null,
                        lastEventEpochMs = now
                    ),
                action =
                    FailoverAction.WAIT_FOR_ROUTE,
                cause =
                    FailoverCause.NO_ALTERNATE_ROUTE
            )
        }


        val cooldownActive =
            snapshot.cooldownUntilEpochMs
                ?.let { now < it }
                ?: false

        val switchingBack =
            alternativeRouteId ==
            snapshot.previousRouteId


        /*
         * Hysteresis:
         *
         * During normal degradation, do not immediately bounce back
         * to the route we just left.
         *
         * Critical loss (UNREACHABLE / blocked / route cooldown) may
         * override this restriction because connectivity is more
         * important than anti-flapping preference.
         */
        if (
            cooldownActive &&
            switchingBack &&
            !critical
        ) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        state =
                            FailoverState.PROBING,
                        targetRouteId = null,
                        lastEventEpochMs = now
                    ),
                action =
                    FailoverAction.WAIT_COOLDOWN,
                cause =
                    FailoverCause.COOLDOWN_ACTIVE
            )
        }


        return FailoverTransition(
            snapshot =
                snapshot.copy(
                    state =
                        FailoverState.FAILING_OVER,
                    targetRouteId =
                        alternativeRouteId,
                    recoverySuccesses = 0,
                    lastEventEpochMs = now
                ),
            action =
                FailoverAction.SWITCH_TO_TARGET,
            cause = cause
        )
    }


    private fun switchSucceeded(
        snapshot: FailoverSnapshot,
        event: FailoverEvent.SwitchSucceeded,
        config: FailoverPolicyConfig
    ): FailoverTransition {

        val expectedTarget =
            snapshot.targetRouteId

        if (
            expectedTarget == null ||
            event.routeId != expectedTarget
        ) {

            return FailoverTransition(
                snapshot = snapshot,
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.UNEXPECTED_SWITCH_RESULT
            )
        }


        val cooldownUntil =
            event.timestampEpochMs +
                config.switchCooldownMs


        return FailoverTransition(
            snapshot =
                snapshot.copy(
                    state =
                        FailoverState.RECOVERING,
                    previousRouteId =
                        snapshot.activeRouteId,
                    activeRouteId =
                        event.routeId,
                    targetRouteId = null,
                    recoverySuccesses = 0,
                    cooldownUntilEpochMs =
                        cooldownUntil,
                    lastEventEpochMs =
                        event.timestampEpochMs
                ),
            action = FailoverAction.NONE,
            cause =
                FailoverCause.SWITCH_SUCCEEDED
        )
    }


    private fun switchFailed(
        snapshot: FailoverSnapshot,
        event: FailoverEvent.SwitchFailed,
        config: FailoverPolicyConfig
    ): FailoverTransition {

        if (
            snapshot.targetRouteId == null ||
            snapshot.targetRouteId !=
                event.routeId
        ) {

            return FailoverTransition(
                snapshot = snapshot,
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.UNEXPECTED_SWITCH_RESULT
            )
        }


        val retryUntil =
            event.timestampEpochMs +
                config.failedTargetRetryMs

        val retryMap =
            snapshot.failedTargetRetryUntilEpochMs +
                (event.routeId to retryUntil)

        return FailoverTransition(
            snapshot =
                snapshot.copy(
                    state =
                        FailoverState.DEGRADED,
                    targetRouteId = null,
                    recoverySuccesses = 0,
                    failedTargetRetryUntilEpochMs =
                        retryMap,
                    lastEventEpochMs =
                        event.timestampEpochMs
                ),
            action =
                FailoverAction.WAIT_FOR_ROUTE,
            cause =
                FailoverCause.SWITCH_FAILED
        )
    }


    private fun terminalSuccess(
        snapshot: FailoverSnapshot,
        event: FailoverEvent.TerminalSuccess,
        config: FailoverPolicyConfig
    ): FailoverTransition {

        /*
         * Health evidence may still be recorded by the orchestrator,
         * but policy state must not abandon an already-issued switch.
         */
        if (
            snapshot.state ==
            FailoverState.FAILING_OVER
        ) {
            return FailoverTransition(
                snapshot = snapshot,
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.SWITCH_IN_PROGRESS
            )
        }

        if (
            event.routeId !=
            snapshot.activeRouteId
        ) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        lastEventEpochMs =
                            event.timestampEpochMs
                    ),
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.NON_ACTIVE_SUCCESS
            )
        }


        if (
            snapshot.state !=
            FailoverState.RECOVERING
        ) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        state =
                            FailoverState.STABLE,
                        targetRouteId = null,
                        recoverySuccesses = 0,
                        lastEventEpochMs =
                            event.timestampEpochMs
                    ),
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.ACTIVE_ROUTE_SUCCESS
            )
        }


        val successes =
            snapshot.recoverySuccesses + 1


        if (
            successes >=
            config.recoverySuccessThreshold
        ) {

            return FailoverTransition(
                snapshot =
                    snapshot.copy(
                        state =
                            FailoverState.STABLE,
                        targetRouteId = null,
                        recoverySuccesses = 0,
                        lastEventEpochMs =
                            event.timestampEpochMs
                    ),
                action = FailoverAction.NONE,
                cause =
                    FailoverCause.RECOVERY_COMPLETE
            )
        }


        return FailoverTransition(
            snapshot =
                snapshot.copy(
                    state =
                        FailoverState.RECOVERING,
                    recoverySuccesses =
                        successes,
                    lastEventEpochMs =
                        event.timestampEpochMs
                ),
            action = FailoverAction.NONE,
            cause =
                FailoverCause.RECOVERY_PROGRESS
        )
    }
}
