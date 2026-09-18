package com.slipmesh.core

/**
 * Immutable scoring weights used by the sole Phase-1 RouteSelector.
 *
 * Defaults preserve the qualified pre-Phase-7 behavior exactly.
 * Phase 7 may evaluate alternate values through this seam, but callers
 * do not gain a second route selector or any network authority.
 */
data class RouteScoringConfig(
    val healthyScore: Int = 100,
    val unknownScore: Int = 40,
    val degradedScore: Int = 0,
    val suspectedBlockScore: Int = -100,
    val unavailableScore: Int = -10_000,
    val failurePenaltyPerFailure: Int = 15,
    val failurePenaltyCap: Int = 20,
    val healthyCurrentStickiness: Int = 120,
    val unknownCurrentStickiness: Int = 40,
    val providerDiversityBonus: Int = 160,
    val accountDiversityBonus: Int = 40,
    val hostnameDiversityBonus: Int = 20,
    val transportDiversityBonus: Int = 80,
) {
    init {
        require(healthyScore in SCORE_RANGE)
        require(unknownScore in SCORE_RANGE)
        require(degradedScore in SCORE_RANGE)
        require(suspectedBlockScore in SCORE_RANGE)
        require(unavailableScore in SCORE_RANGE)
        require(failurePenaltyPerFailure in NON_NEGATIVE_WEIGHT_RANGE)
        require(failurePenaltyCap in FAILURE_CAP_RANGE)
        require(healthyCurrentStickiness in NON_NEGATIVE_WEIGHT_RANGE)
        require(unknownCurrentStickiness in NON_NEGATIVE_WEIGHT_RANGE)
        require(providerDiversityBonus in NON_NEGATIVE_WEIGHT_RANGE)
        require(accountDiversityBonus in NON_NEGATIVE_WEIGHT_RANGE)
        require(hostnameDiversityBonus in NON_NEGATIVE_WEIGHT_RANGE)
        require(transportDiversityBonus in NON_NEGATIVE_WEIGHT_RANGE)
    }

    companion object {
        private val SCORE_RANGE = -10_000..10_000
        private val NON_NEGATIVE_WEIGHT_RANGE = 0..10_000
        private val FAILURE_CAP_RANGE = 0..1_000

        val DEFAULT = RouteScoringConfig()
    }
}
