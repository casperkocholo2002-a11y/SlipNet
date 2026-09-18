package app.slipnet.emergencydns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResolverSurvivalPlannerTest {
    private val now = 10_000_000L

    @Test
    fun discoveryUsesVerifiedMemoryBeforeStaticCorpus() {
        val memory = ResolverCandidate("192.0.2.10", source = ResolverCandidateSource.VERIFIED_MEMORY)
        val profile = ResolverCandidate("198.51.100.10", source = ResolverCandidateSource.PROFILE)
        val network = ResolverCandidate("203.0.113.10", source = ResolverCandidateSource.NETWORK)
        val corpus = ResolverCandidate("203.0.114.10", source = ResolverCandidateSource.CORPUS)
        val histories = mapOf(
            memory.key to ResolverHistory(
                successCount = 4,
                lastSuccessAtMs = now - 1_000,
                prismEverVerified = true,
            )
        )

        val plan = ResolverSurvivalPlanner().plan(
            candidates = listOf(corpus, network, profile, memory),
            histories = histories,
            observations = emptyList(),
            nowMs = now,
        )

        assertEquals(listOf(memory, profile, network, corpus), plan.discoveryOrder)
    }

    @Test
    fun repeatedFailureMovesResolverIntoBoundedBackoff() {
        val failed = ResolverCandidate("192.0.2.20", source = ResolverCandidateSource.VERIFIED_MEMORY)
        val fallback = ResolverCandidate("198.51.100.20", source = ResolverCandidateSource.CORPUS)
        val histories = mapOf(
            failed.key to ResolverHistory(
                consecutiveFailures = 3,
                failureCount = 3,
                lastFailureAtMs = now - 20_000,
            )
        )

        val plan = ResolverSurvivalPlanner().plan(
            candidates = listOf(failed, fallback),
            histories = histories,
            observations = emptyList(),
            nowMs = now,
        )

        assertFalse(failed in plan.discoveryOrder)
        assertTrue(failed in plan.deferredByBackoff)
        assertEquals(ResolverRejectReason.BACKOFF, plan.rejected[failed.key])
    }

    @Test
    fun activeSetRequiresAuthenticatedPrismAndRealTunnelByDefault() {
        val good = ResolverCandidate("192.0.2.30", source = ResolverCandidateSource.CORPUS)
        val noPrism = ResolverCandidate("198.51.100.30", source = ResolverCandidateSource.CORPUS)
        val noTunnel = ResolverCandidate("203.0.113.30", source = ResolverCandidateSource.CORPUS)

        val observations = listOf(
            ResolverObservation(good, prismVerified = true, e2eSuccess = true, tunnelRealism = true),
            ResolverObservation(noPrism, prismVerified = false, e2eSuccess = true, tunnelRealism = true),
            ResolverObservation(noTunnel, prismVerified = true, e2eSuccess = false, tunnelRealism = true),
        )

        val plan = ResolverSurvivalPlanner().plan(
            candidates = listOf(good, noPrism, noTunnel),
            histories = emptyMap(),
            observations = observations,
            nowMs = now,
        )

        assertEquals(listOf(good), plan.activeSet)
        assertEquals(ResolverRejectReason.PRISM_REQUIRED, plan.rejected[noPrism.key])
        assertEquals(ResolverRejectReason.E2E_REQUIRED, plan.rejected[noTunnel.key])
    }

    @Test
    fun activeSetPrefersDifferentIpv4FailureGroups() {
        val a = ResolverCandidate("192.0.2.10", source = ResolverCandidateSource.VERIFIED_MEMORY)
        val same24 = ResolverCandidate("192.0.2.11", source = ResolverCandidateSource.VERIFIED_MEMORY)
        val other = ResolverCandidate("198.51.100.10", source = ResolverCandidateSource.CORPUS)

        val observations = listOf(
            ResolverObservation(a, prismVerified = true, e2eSuccess = true, responseTimeMs = 20),
            ResolverObservation(same24, prismVerified = true, e2eSuccess = true, responseTimeMs = 25),
            ResolverObservation(other, prismVerified = true, e2eSuccess = true, responseTimeMs = 80),
        )

        val plan = ResolverSurvivalPlanner(
            ResolverSelectionPolicy(activeSetSize = 2)
        ).plan(
            candidates = listOf(a, same24, other),
            histories = emptyMap(),
            observations = observations,
            nowMs = now,
        )

        assertEquals(listOf(a, other), plan.activeSet)
    }

    @Test
    fun freshKnownSuccessBeatsStaleSuccessWithinSameSource() {
        val fresh = ResolverCandidate("192.0.2.40", source = ResolverCandidateSource.CORPUS)
        val stale = ResolverCandidate("198.51.100.40", source = ResolverCandidateSource.CORPUS)
        val histories = mapOf(
            fresh.key to ResolverHistory(successCount = 1, lastSuccessAtMs = now - 1_000),
            stale.key to ResolverHistory(successCount = 1, lastSuccessAtMs = now - 24 * 60 * 60 * 1_000L),
        )

        val plan = ResolverSurvivalPlanner().plan(
            candidates = listOf(stale, fresh),
            histories = histories,
            observations = emptyList(),
            nowMs = now,
        )

        assertEquals(fresh, plan.discoveryOrder.first())
    }

    @Test
    fun orderingIsDeterministicForEqualCandidates() {
        val a = ResolverCandidate("192.0.2.2", source = ResolverCandidateSource.CORPUS)
        val b = ResolverCandidate("192.0.2.1", source = ResolverCandidateSource.CORPUS)
        val planner = ResolverSurvivalPlanner()

        val first = planner.plan(listOf(a, b), emptyMap(), emptyList(), now).discoveryOrder
        val second = planner.plan(listOf(b, a), emptyMap(), emptyList(), now).discoveryOrder

        assertEquals(first, second)
        assertEquals(listOf(b, a), first)
    }
}
