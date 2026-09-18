package app.slipnet.emergencydns

import app.slipnet.domain.model.ResolverScanResult

/**
 * Deterministic decision layer for emergency DNS discovery/failover.
 * It owns no sockets and starts no background work; the existing scanner/bridges
 * remain the only network executors.
 */
class EmergencyDnsResolverController(
    private val survivalPlanner: ResolverSurvivalPlanner = ResolverSurvivalPlanner(),
    private val discoveryPlanner: ResolverStagedDiscoveryPlanner = ResolverStagedDiscoveryPlanner(),
) {
    fun discoveryBatches(
        scopeId: String,
        memory: List<ResolverMemoryRecord>,
        profileResolvers: List<Pair<String, Int>>,
        networkResolvers: List<Pair<String, Int>>,
        regionalCorpus: List<String>,
        broadCorpus: List<String>,
        nowMs: Long,
    ): List<ResolverDiscoveryBatch> {
        val scopeMemory = ResolverMemoryCodec.forScope(memory, scopeId)
        val histories = scopeMemory.associate { it.resolverKey to it.asHistory() }

        val remembered = scopeMemory
            .filter { it.prismEverVerified && it.successCount > 0 }
            .map { ResolverCandidate(it.host, it.port, ResolverCandidateSource.VERIFIED_MEMORY) }
        val profile = profileResolvers.map { (host, port) -> ResolverCandidate(host, port, ResolverCandidateSource.PROFILE) }
        val network = networkResolvers.map { (host, port) -> ResolverCandidate(host, port, ResolverCandidateSource.NETWORK) }
        val regional = regionalCorpus.map { ResolverCandidate(it, 53, ResolverCandidateSource.CORPUS) }
        val broad = broadCorpus.map { ResolverCandidate(it, 53, ResolverCandidateSource.CORPUS) }

        fun order(input: List<ResolverCandidate>): List<ResolverCandidate> =
            survivalPlanner.plan(input, histories, emptyList(), nowMs).discoveryOrder

        return discoveryPlanner.batches(
            remembered = order(remembered),
            profile = order(profile),
            network = order(network),
            regionalCorpus = order(regional),
            broadCorpus = order(broad),
        )
    }

    fun selectActiveSet(
        scopeId: String,
        memory: List<ResolverMemoryRecord>,
        results: List<Pair<ResolverScanResult, ResolverCandidateSource>>,
        nowMs: Long,
    ): ResolverSurvivalPlan {
        val histories = ResolverMemoryCodec.forScope(memory, scopeId)
            .associate { it.resolverKey to it.asHistory() }
        val candidates = results.map { (result, source) ->
            ResolverCandidate(result.host, result.port, source)
        }
        val observations = results.map { (result, source) ->
            result.toEmergencyObservation(source)
        }
        return survivalPlanner.plan(candidates, histories, observations, nowMs)
    }

    fun learn(
        memory: List<ResolverMemoryRecord>,
        scopeId: String,
        result: ResolverScanResult,
        nowMs: Long,
    ): List<ResolverMemoryRecord> = ResolverMemoryCodec.update(
        records = memory,
        scopeId = scopeId,
        host = result.host,
        port = result.port,
        success = result.isEmergencyDiscoverySuccess(),
        prismVerified = result.prismVerified == true,
        nowMs = nowMs,
    )
}
