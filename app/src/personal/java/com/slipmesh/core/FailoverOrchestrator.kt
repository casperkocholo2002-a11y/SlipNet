package com.slipmesh.core


/**
 * Coordinates route-health evidence, deterministic route ranking and
 * failover policy.
 *
 * Responsibilities remain separated:
 *
 * HealthStore:
 *     What has been observed about each route?
 *
 * RouteSelector:
 *     Which alternative route is best?
 *
 * FailoverStateMachine:
 *     Is switching appropriate now?
 *
 * This class contains no Android or network implementation.
 */
class FailoverOrchestrator(
    private val healthStore: HealthStore,
    private val config: FailoverPolicyConfig =
        FailoverPolicyConfig(),
    initialSnapshot: FailoverSnapshot =
        FailoverSnapshot(),
    private val routeScoringConfig: RouteScoringConfig =
        RouteScoringConfig.DEFAULT
) {

    private var currentSnapshot =
        initialSnapshot


    @Synchronized
    fun snapshot(): FailoverSnapshot =
        currentSnapshot


    /**
     * Evaluates current routing state using a point-in-time HealthStore
     * snapshot and the deterministic RouteSelector ranking.
     */
    @Synchronized
    fun evaluate(
        routes: List<RouteCandidate>,
        timestampEpochMs: Long,
        networkChanged: Boolean = false
    ): FailoverTransition {

        require(timestampEpochMs >= 0)

        val health =
            healthStore.snapshot()

        val activeRouteId =
            currentSnapshot.activeRouteId

        val activeRoute =
            activeRouteId?.let { id ->
                routes.firstOrNull {
                    it.id == id
                }
            }

        val activeRouteAvailable =
            activeRouteId == null ||
                (
                    activeRoute != null &&
                    activeRoute.enabled
                )

        val activeHealth =
            activeRouteId?.let { id ->
                health[id] ?: RouteHealth()
            } ?: RouteHealth()

        /*
         * A failed transport-switch target is temporarily excluded from
         * policy selection without modifying its observed route health.
         */
        val suppressedRouteIds =
            currentSnapshot
                .failedTargetRetryUntilEpochMs
                .asSequence()
                .filter { (_, retryUntil) ->
                    timestampEpochMs < retryUntil
                }
                .map { (routeId, _) ->
                    routeId
                }
                .toSet()

        val selectableRoutes =
            if (suppressedRouteIds.isEmpty()) {
                routes
            } else {
                routes.filterNot { route ->
                    route.id in suppressedRouteIds
                }
            }

        val alternative =
            RouteSelector.selectAlternative(
                routes = selectableRoutes,
                health = health,
                currentRouteId = activeRouteId,
                config = routeScoringConfig
            )

        return apply(
            FailoverEvent.Evaluate(
                activeHealth = activeHealth,
                alternativeRouteId =
                    alternative?.id,
                activeRouteAvailable =
                    activeRouteAvailable,
                networkChanged =
                    networkChanged,
                timestampEpochMs =
                    timestampEpochMs
            )
        )
    }


    /**
     * Transport layer reports that the requested route switch itself
     * completed. Connectivity is not yet considered recovered.
     */
    @Synchronized
    fun switchSucceeded(
        routeId: String,
        timestampEpochMs: Long
    ): FailoverTransition =
        apply(
            FailoverEvent.SwitchSucceeded(
                routeId = routeId,
                timestampEpochMs =
                    timestampEpochMs
            )
        )


    @Synchronized
    fun switchFailed(
        routeId: String,
        timestampEpochMs: Long
    ): FailoverTransition =
        apply(
            FailoverEvent.SwitchFailed(
                routeId = routeId,
                timestampEpochMs =
                    timestampEpochMs
            )
        )


    /**
     * A confirmed end-to-end terminal success is authoritative both for
     * route health and recovery hysteresis.
     */
    @Synchronized
    fun terminalSuccess(
        routeId: String,
        timestampEpochMs: Long
    ): FailoverTransition {

        healthStore.recordSuccess(
            routeId = routeId,
            timestampEpochMs =
                timestampEpochMs
        )

        return apply(
            FailoverEvent.TerminalSuccess(
                routeId = routeId,
                timestampEpochMs =
                    timestampEpochMs
            )
        )
    }


    private fun apply(
        event: FailoverEvent
    ): FailoverTransition {

        val transition =
            FailoverStateMachine.transition(
                snapshot = currentSnapshot,
                event = event,
                config = config
            )

        currentSnapshot =
            transition.snapshot

        return transition
    }
}
