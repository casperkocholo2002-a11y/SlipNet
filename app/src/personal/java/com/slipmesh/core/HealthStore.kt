package com.slipmesh.core

/**
 * Mutable in-memory health state for routes.
 *
 * Phase-1 implementation is intentionally independent from Android,
 * persistence and networking.
 */
class HealthStore {

    private val states =
        linkedMapOf<String, RouteHealth>()


    /**
     * Newer route knowledge must never be overwritten by an older
     * asynchronously-delivered probe result.
     */
    private fun latestMutationEpochMs(
        health: RouteHealth
    ): Long? =
        listOfNotNull(
            health.lastSuccessEpochMs,
            health.lastFailureEpochMs
        ).maxOrNull()


    private fun isStale(
        previous: RouteHealth,
        timestampEpochMs: Long
    ): Boolean {

        val latest =
            latestMutationEpochMs(previous)
                ?: return false

        /*
         * Equal timestamps are allowed because millisecond precision
         * cannot reliably order two distinct events occurring in the
         * same millisecond.
         */
        return timestampEpochMs < latest
    }


    @Synchronized
    fun get(
        routeId: String
    ): RouteHealth {

        require(routeId.isNotBlank())

        return states[routeId] ?: RouteHealth()
    }


    @Synchronized
    fun snapshot(): Map<String, RouteHealth> =
        states.toMap()


    /**
     * Successful connectivity restores the route to HEALTHY and
     * clears accumulated failure history.
     */
    @Synchronized
    fun recordSuccess(
        routeId: String,
        timestampEpochMs: Long
    ): RouteHealth {

        require(routeId.isNotBlank())
        require(timestampEpochMs >= 0)

        val previous =
            states[routeId] ?: RouteHealth()

        if (
            isStale(
                previous = previous,
                timestampEpochMs = timestampEpochMs
            )
        ) {
            return previous
        }

        val updated =
            RouteHealth(
                state = HealthState.HEALTHY,
                lastFailure = FailureReason.NONE,
                consecutiveFailures = 0,
                lastSuccessEpochMs = timestampEpochMs,
                lastFailureEpochMs =
                    previous.lastFailureEpochMs
            )

        states[routeId] = updated

        return updated
    }


    /**
     * Records a classified failure.
     *
     * NETWORK_CHANGE is intentionally not counted as a route failure,
     * because changing Wi-Fi/mobile network says nothing about whether
     * the route itself is defective.
     *
     * SUSPECTED_BLOCK is intentionally never produced here. That state
     * belongs to a later inference/policy layer using multiple signals.
     */
    @Synchronized
    fun recordFailure(
        routeId: String,
        reason: FailureReason,
        timestampEpochMs: Long
    ): RouteHealth {

        require(routeId.isNotBlank())
        require(reason != FailureReason.NONE)
        require(timestampEpochMs >= 0)

        val previous =
            states[routeId] ?: RouteHealth()

        if (
            isStale(
                previous = previous,
                timestampEpochMs = timestampEpochMs
            )
        ) {
            return previous
        }

        if (reason == FailureReason.NETWORK_CHANGE) {

            val updated =
                previous.copy(
                    state = HealthState.UNKNOWN,
                    lastFailure = reason,
                    lastFailureEpochMs = timestampEpochMs
                )

            states[routeId] = updated

            return updated
        }

        val failures =
            previous.consecutiveFailures + 1

        val nextState =
            when {
                failures >= 3 ->
                    HealthState.UNREACHABLE

                else ->
                    HealthState.DEGRADED
            }

        val updated =
            previous.copy(
                state = nextState,
                lastFailure = reason,
                consecutiveFailures = failures,
                lastFailureEpochMs = timestampEpochMs
            )

        states[routeId] = updated

        return updated
    }


    /**
     * Convenience entry point used by future probes/transport engines.
     */
    @Synchronized
    fun recordObservation(
        routeId: String,
        observation: ConnectionObservation
    ): RouteHealth {

        val reason =
            FailureClassifier.classify(observation)

        if (reason != FailureReason.NONE) {

            return recordFailure(
                routeId = routeId,
                reason = reason,
                timestampEpochMs =
                    observation.timestampEpochMs
            )
        }

        /*
         * A successful intermediate layer is evidence that one stage
         * worked, not proof that the whole route is healthy.
         */
        if (!observation.terminal) {
            return get(routeId)
        }

        return recordSuccess(
            routeId = routeId,
            timestampEpochMs =
                observation.timestampEpochMs
        )
    }


    @Synchronized
    fun remove(
        routeId: String
    ) {
        states.remove(routeId)
    }


    @Synchronized
    fun clear() {
        states.clear()
    }
}
