package app.slipnet.emergencydns

import kotlin.math.min

/**
 * Pure resolver-selection core for Emergency DNS mode.
 *
 * This class never opens sockets and never owns VPN/transport failover. It only
 * prioritizes resolver discovery and selects an already-verified resolver set.
 * Network identity/memory persistence is deliberately supplied by a higher layer.
 */
enum class ResolverCandidateSource(val basePriority: Int) {
    VERIFIED_MEMORY(4_000),
    PROFILE(3_000),
    NETWORK(2_500),
    CORPUS(1_000),
}

data class ResolverCandidate(
    val host: String,
    val port: Int = 53,
    val source: ResolverCandidateSource,
) {
    val key: String get() = "$host:$port"
}

data class ResolverHistory(
    val successCount: Int = 0,
    val failureCount: Int = 0,
    val consecutiveFailures: Int = 0,
    val lastSuccessAtMs: Long? = null,
    val lastFailureAtMs: Long? = null,
    val prismEverVerified: Boolean = false,
)

data class ResolverObservation(
    val candidate: ResolverCandidate,
    val prismVerified: Boolean? = null,
    val e2eSuccess: Boolean = false,
    val tunnelRealism: Boolean = false,
    val nxdomainCorrect: Boolean = false,
    val ednsMaxPayload: Int = 0,
    val udpWorking: Boolean? = null,
    val tcpWorking: Boolean? = null,
    val responseTimeMs: Long? = null,
)

data class ResolverSelectionPolicy(
    val activeSetSize: Int = 3,
    val requirePrism: Boolean = true,
    val requireE2e: Boolean = true,
    val freshSuccessWindowMs: Long = 6 * 60 * 60 * 1_000L,
    val backoffBaseMs: Long = 30_000L,
    val backoffMaxMs: Long = 30 * 60 * 1_000L,
)

enum class ResolverRejectReason {
    BACKOFF,
    PRISM_REQUIRED,
    E2E_REQUIRED,
}

data class ResolverSurvivalPlan(
    val discoveryOrder: List<ResolverCandidate>,
    val deferredByBackoff: List<ResolverCandidate>,
    val activeSet: List<ResolverCandidate>,
    val rejected: Map<String, ResolverRejectReason>,
)

class ResolverSurvivalPlanner(
    private val policy: ResolverSelectionPolicy = ResolverSelectionPolicy(),
) {
    fun plan(
        candidates: List<ResolverCandidate>,
        histories: Map<String, ResolverHistory>,
        observations: List<ResolverObservation>,
        nowMs: Long,
    ): ResolverSurvivalPlan {
        val uniqueCandidates = candidates
            .distinctBy { it.key }

        val (ready, deferred) = uniqueCandidates.partition { candidate ->
            !isInBackoff(histories[candidate.key], nowMs)
        }

        val discoveryOrder = ready.sortedWith(
            compareByDescending<ResolverCandidate> { discoveryScore(it, histories[it.key], nowMs) }
                .thenBy { it.key }
        )

        val rejected = linkedMapOf<String, ResolverRejectReason>()
        deferred.forEach { rejected[it.key] = ResolverRejectReason.BACKOFF }

        val eligible = observations.filter { observation ->
            when {
                policy.requirePrism && observation.prismVerified != true -> {
                    rejected[observation.candidate.key] = ResolverRejectReason.PRISM_REQUIRED
                    false
                }
                policy.requireE2e && !observation.e2eSuccess -> {
                    rejected[observation.candidate.key] = ResolverRejectReason.E2E_REQUIRED
                    false
                }
                else -> true
            }
        }.sortedWith(
            compareByDescending<ResolverObservation> {
                activeScore(it, histories[it.candidate.key], nowMs)
            }.thenBy { it.candidate.key }
        )

        val active = selectWithIpv4Diversity(eligible, policy.activeSetSize)
            .map { it.candidate }

        return ResolverSurvivalPlan(
            discoveryOrder = discoveryOrder,
            deferredByBackoff = deferred.sortedBy { it.key },
            activeSet = active,
            rejected = rejected,
        )
    }

    internal fun backoffUntil(history: ResolverHistory?): Long? {
        if (history == null || history.consecutiveFailures <= 0 || history.lastFailureAtMs == null) return null
        val exponent = (history.consecutiveFailures - 1).coerceIn(0, 20)
        var delay = policy.backoffBaseMs
        repeat(exponent) { delay = min(policy.backoffMaxMs, delay * 2) }
        return history.lastFailureAtMs + min(delay, policy.backoffMaxMs)
    }

    private fun isInBackoff(history: ResolverHistory?, nowMs: Long): Boolean =
        backoffUntil(history)?.let { nowMs < it } == true

    private fun discoveryScore(
        candidate: ResolverCandidate,
        history: ResolverHistory?,
        nowMs: Long,
    ): Long {
        var score = candidate.source.basePriority.toLong()
        if (history == null) return score

        if (history.prismEverVerified) score += 1_500
        score += min(history.successCount, 50) * 20L
        score -= min(history.failureCount, 100) * 10L
        score -= min(history.consecutiveFailures, 10) * 400L

        val lastSuccess = history.lastSuccessAtMs
        if (lastSuccess != null) {
            val age = (nowMs - lastSuccess).coerceAtLeast(0L)
            if (age <= policy.freshSuccessWindowMs) {
                val freshness = policy.freshSuccessWindowMs - age
                score += 800L * freshness / policy.freshSuccessWindowMs.coerceAtLeast(1L)
            }
        }
        return score
    }

    private fun activeScore(
        observation: ResolverObservation,
        history: ResolverHistory?,
        nowMs: Long,
    ): Long {
        var score = discoveryScore(observation.candidate, history, nowMs)
        if (observation.prismVerified == true) score += 5_000
        if (observation.e2eSuccess) score += 4_000
        if (observation.tunnelRealism) score += 800
        if (observation.nxdomainCorrect) score += 200
        if (observation.ednsMaxPayload >= 1232) score += 300
        else if (observation.ednsMaxPayload >= 900) score += 150
        if (observation.udpWorking == true) score += 120
        if (observation.tcpWorking == true) score += 80
        observation.responseTimeMs?.let { score -= min(it, 2_000L) }
        return score
    }

    private fun selectWithIpv4Diversity(
        sorted: List<ResolverObservation>,
        limit: Int,
    ): List<ResolverObservation> {
        if (limit <= 0) return emptyList()
        val selected = mutableListOf<ResolverObservation>()
        val deferredSameSubnet = mutableListOf<ResolverObservation>()
        val seenGroups = mutableSetOf<String>()

        for (item in sorted) {
            val group = ipv4Group24(item.candidate.host)
            if (group == null || seenGroups.add(group)) {
                selected += item
                if (selected.size == limit) return selected
            } else {
                deferredSameSubnet += item
            }
        }

        for (item in deferredSameSubnet) {
            selected += item
            if (selected.size == limit) break
        }
        return selected
    }

    private fun ipv4Group24(host: String): String? {
        val parts = host.split('.')
        if (parts.size != 4) return null
        val octets = parts.map { it.toIntOrNull() ?: return null }
        if (octets.any { it !in 0..255 }) return null
        return "${octets[0]}.${octets[1]}.${octets[2]}"
    }
}
