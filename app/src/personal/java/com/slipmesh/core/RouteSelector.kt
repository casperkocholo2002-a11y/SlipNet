package com.slipmesh.core

/**
 * Deterministic route selector.
 *
 * Phase-1 goals:
 *
 * 1. Never select disabled routes.
 * 2. Never select routes currently marked UNREACHABLE or COOLDOWN.
 * 3. Prefer healthy routes.
 * 4. Penalize repeated failures.
 * 5. When leaving a route, prefer diversity across:
 *      provider
 *      account
 *      hostname
 *      transport
 *
 * This is intentionally policy-only code.
 * It performs no networking.
 */
object RouteSelector {

    data class ScoredRoute(
        val route: RouteCandidate,
        val score: Int
    )

    data class Decision(
        val selected: RouteCandidate?,
        val ranked: List<ScoredRoute>
    )

    fun select(
        routes: List<RouteCandidate>,
        health: Map<String, RouteHealth>,
        currentRouteId: String? = null,
        config: RouteScoringConfig = RouteScoringConfig.DEFAULT
    ): Decision {

        val current =
            currentRouteId?.let { id ->
                routes.firstOrNull { it.id == id }
            }

        val currentHealth =
            current?.let { route ->
                health[route.id] ?: RouteHealth()
            }

        val ranked =
            routes
                .asSequence()

                .filter { it.enabled }

                .filter { route ->
                    when (health[route.id]?.state ?: HealthState.UNKNOWN) {
                        HealthState.UNREACHABLE,
                        HealthState.COOLDOWN -> false

                        else -> true
                    }
                }

                .map { route ->

                    val routeHealth =
                        health[route.id] ?: RouteHealth()

                    val score =
                        route.basePriority +
                            healthScore(routeHealth, config) +
                            transitionScore(
                                current = current,
                                currentHealth = currentHealth,
                                candidate = route,
                                config = config
                            ) -
                            failurePenalty(routeHealth, config)

                    ScoredRoute(
                        route = route,
                        score = score
                    )
                }

                .sortedWith(
                    compareByDescending<ScoredRoute> { it.score }
                        .thenBy { it.route.id }
                )

                .toList()

        return Decision(
            selected = ranked.firstOrNull()?.route,
            ranked = ranked
        )
    }


    /**
     * Returns the highest-ranked route other than the current route.
     *
     * Ranking still evaluates the complete route set so failover
     * diversity relative to the current route is preserved.
     */
    fun selectAlternative(
        routes: List<RouteCandidate>,
        health: Map<String, RouteHealth>,
        currentRouteId: String?,
        config: RouteScoringConfig = RouteScoringConfig.DEFAULT
    ): RouteCandidate? {

        val decision =
            select(
                routes = routes,
                health = health,
                currentRouteId = currentRouteId,
                config = config
            )

        if (currentRouteId == null) {
            return decision.selected
        }

        return decision.ranked
            .asSequence()
            .map { it.route }
            .firstOrNull {
                it.id != currentRouteId
            }
    }


    private fun healthScore(
        health: RouteHealth,
        config: RouteScoringConfig
    ): Int =
        when (health.state) {

            HealthState.HEALTHY ->
                config.healthyScore

            HealthState.UNKNOWN ->
                config.unknownScore

            HealthState.DEGRADED ->
                config.degradedScore

            HealthState.SUSPECTED_BLOCK ->
                config.suspectedBlockScore

            HealthState.UNREACHABLE,
            HealthState.COOLDOWN ->
                config.unavailableScore
        }


    private fun failurePenalty(
        health: RouteHealth,
        config: RouteScoringConfig
    ): Int {

        val cappedFailures =
            health.consecutiveFailures
                .coerceAtMost(config.failurePenaltyCap)

        return cappedFailures * config.failurePenaltyPerFailure
    }


    /**
     * Diversity is evaluated relative to the route we are leaving.
     *
     * Provider diversity receives the largest bonus because switching
     * only hostname/account may still leave us inside the same provider
     * failure domain.
     */
    /**
     * Transition scoring serves two different purposes:
     *
     * 1. Keep a healthy current route sticky to avoid connection churn.
     * 2. Once failover is actually required, reward failure-domain diversity.
     *
     * Diversity must never cause migration away from a stable route by itself.
     */
    private fun transitionScore(
        current: RouteCandidate?,
        currentHealth: RouteHealth?,
        candidate: RouteCandidate,
        config: RouteScoringConfig
    ): Int {

        if (current == null)
            return 0

        if (current.id == candidate.id) {
            return when {
                currentHealth?.state == HealthState.HEALTHY &&
                    (currentHealth.consecutiveFailures == 0) ->
                    config.healthyCurrentStickiness

                currentHealth?.state == HealthState.UNKNOWN &&
                    (currentHealth.consecutiveFailures == 0) ->
                    config.unknownCurrentStickiness

                else ->
                    0
            }
        }

        val failoverNeeded =
            when (currentHealth?.state ?: HealthState.UNKNOWN) {

                HealthState.HEALTHY,
                HealthState.UNKNOWN ->
                    (currentHealth?.consecutiveFailures ?: 0) > 0

                HealthState.DEGRADED,
                HealthState.SUSPECTED_BLOCK,
                HealthState.UNREACHABLE,
                HealthState.COOLDOWN ->
                    true
            }

        if (!failoverNeeded)
            return 0

        var score = 0

        if (
            candidate.failureDomain.providerId !=
            current.failureDomain.providerId
        ) {
            score += config.providerDiversityBonus
        }

        if (
            candidate.failureDomain.accountId !=
            current.failureDomain.accountId
        ) {
            score += config.accountDiversityBonus
        }

        if (
            candidate.failureDomain.hostname !=
            current.failureDomain.hostname
        ) {
            score += config.hostnameDiversityBonus
        }

        if (
            candidate.transport !=
            current.transport
        ) {
            score += config.transportDiversityBonus
        }

        return score
    }
}
