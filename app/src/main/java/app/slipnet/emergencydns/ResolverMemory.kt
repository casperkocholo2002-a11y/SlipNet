package app.slipnet.emergencydns

import java.security.MessageDigest

/** Durable-but-disposable learning record. No SSID/BSSID/carrier identity is stored. */
data class ResolverMemoryRecord(
    val scopeId: String,
    val host: String,
    val port: Int,
    val successCount: Int,
    val failureCount: Int,
    val consecutiveFailures: Int,
    val lastSuccessAtMs: Long?,
    val lastFailureAtMs: Long?,
    val prismEverVerified: Boolean,
) {
    val resolverKey: String get() = "$host:$port"
    fun asHistory(): ResolverHistory = ResolverHistory(
        successCount = successCount,
        failureCount = failureCount,
        consecutiveFailures = consecutiveFailures,
        lastSuccessAtMs = lastSuccessAtMs,
        lastFailureAtMs = lastFailureAtMs,
        prismEverVerified = prismEverVerified,
    )
}

object ResolverNetworkScope {
    /**
     * Produces a non-reversible-ish stable identifier from normalized network facts.
     * Callers may use transport type, network-provided DNS addresses and other
     * non-secret link facts. Raw material is never returned or persisted here.
     */
    fun fingerprint(parts: List<String>): String {
        val normalized = parts
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() }
            .distinct()
            .sorted()
            .joinToString("\u0000")
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(normalized.toByteArray(Charsets.UTF_8))
        return digest.take(16).joinToString("") { "%02x".format(it) }
    }
}

object ResolverMemoryCodec {
    const val MAX_RECORDS = 256
    private const val VERSION = "v1"

    fun encode(records: List<ResolverMemoryRecord>): String = buildString {
        append(VERSION).append('\n')
        records
            .filter(::valid)
            .sortedWith(compareByDescending<ResolverMemoryRecord> { it.lastSuccessAtMs ?: Long.MIN_VALUE }
                .thenByDescending { it.prismEverVerified }
                .thenBy { it.scopeId }
                .thenBy { it.resolverKey })
            .take(MAX_RECORDS)
            .forEach { r ->
                append(r.scopeId).append('|')
                append(r.host).append('|')
                append(r.port).append('|')
                append(r.successCount).append('|')
                append(r.failureCount).append('|')
                append(r.consecutiveFailures).append('|')
                append(r.lastSuccessAtMs ?: -1L).append('|')
                append(r.lastFailureAtMs ?: -1L).append('|')
                append(if (r.prismEverVerified) '1' else '0').append('\n')
            }
    }

    fun decode(raw: String): List<ResolverMemoryRecord> {
        if (raw.isBlank()) return emptyList()
        val lines = raw.lineSequence().toList()
        if (lines.firstOrNull()?.trim() != VERSION) return emptyList()
        val out = LinkedHashMap<String, ResolverMemoryRecord>()
        for (line in lines.drop(1)) {
            val p = line.split('|')
            if (p.size != 9) continue
            val record = ResolverMemoryRecord(
                scopeId = p[0],
                host = p[1],
                port = p[2].toIntOrNull() ?: continue,
                successCount = p[3].toIntOrNull() ?: continue,
                failureCount = p[4].toIntOrNull() ?: continue,
                consecutiveFailures = p[5].toIntOrNull() ?: continue,
                lastSuccessAtMs = p[6].toLongOrNull()?.takeIf { it >= 0 },
                lastFailureAtMs = p[7].toLongOrNull()?.takeIf { it >= 0 },
                prismEverVerified = p[8] == "1",
            )
            if (!valid(record)) continue
            out["${record.scopeId}|${record.resolverKey}"] = record
            if (out.size >= MAX_RECORDS) break
        }
        return out.values.toList()
    }

    fun update(
        records: List<ResolverMemoryRecord>,
        scopeId: String,
        host: String,
        port: Int,
        success: Boolean,
        prismVerified: Boolean,
        nowMs: Long,
    ): List<ResolverMemoryRecord> {
        val key = "$scopeId|$host:$port"
        val map = records.associateBy { "${it.scopeId}|${it.resolverKey}" }.toMutableMap()
        val old = map[key] ?: ResolverMemoryRecord(
            scopeId, host, port, 0, 0, 0, null, null, false
        )
        map[key] = if (success) {
            old.copy(
                successCount = (old.successCount + 1).coerceAtMost(1_000_000),
                consecutiveFailures = 0,
                lastSuccessAtMs = nowMs,
                prismEverVerified = old.prismEverVerified || prismVerified,
            )
        } else {
            old.copy(
                failureCount = (old.failureCount + 1).coerceAtMost(1_000_000),
                consecutiveFailures = (old.consecutiveFailures + 1).coerceAtMost(30),
                lastFailureAtMs = nowMs,
            )
        }
        return decode(encode(map.values.toList()))
    }

    fun forScope(records: List<ResolverMemoryRecord>, scopeId: String): List<ResolverMemoryRecord> =
        records.filter { it.scopeId == scopeId }

    private fun valid(r: ResolverMemoryRecord): Boolean =
        r.scopeId.matches(Regex("^[0-9a-f]{16,64}$")) &&
            r.host.isNotBlank() && r.host.length <= 255 &&
            !r.host.any { it == '|' || it == '\n' || it == '\r' } &&
            r.port in 1..65535 &&
            r.successCount >= 0 && r.failureCount >= 0 && r.consecutiveFailures in 0..30
}

enum class ResolverDiscoveryStage {
    MEMORY_AND_PROFILE,
    NETWORK,
    REGIONAL_CORPUS,
    BROAD_CORPUS,
}

data class ResolverDiscoveryBatch(
    val stage: ResolverDiscoveryStage,
    val candidates: List<ResolverCandidate>,
    val concurrency: Int,
    val timeoutMs: Long,
)

data class ResolverDiscoveryBudget(
    val rememberedLimit: Int = 24,
    val networkLimit: Int = 16,
    val regionalLimit: Int = 256,
    val broadLimit: Int = 1_024,
    val rememberedConcurrency: Int = 4,
    val networkConcurrency: Int = 4,
    val regionalConcurrency: Int = 8,
    val broadConcurrency: Int = 10,
)

class ResolverStagedDiscoveryPlanner(
    private val budget: ResolverDiscoveryBudget = ResolverDiscoveryBudget(),
) {
    fun batches(
        remembered: List<ResolverCandidate>,
        profile: List<ResolverCandidate>,
        network: List<ResolverCandidate>,
        regionalCorpus: List<ResolverCandidate>,
        broadCorpus: List<ResolverCandidate>,
    ): List<ResolverDiscoveryBatch> {
        val seen = linkedSetOf<String>()
        fun unique(input: List<ResolverCandidate>, limit: Int): List<ResolverCandidate> = input
            .asSequence()
            .filter { seen.add(it.key) }
            .take(limit)
            .toList()

        val first = unique(remembered + profile, budget.rememberedLimit)
        val net = unique(network, budget.networkLimit)
        val regional = unique(regionalCorpus, budget.regionalLimit)
        val broad = unique(broadCorpus, budget.broadLimit)

        return listOfNotNull(
            first.takeIf { it.isNotEmpty() }?.let {
                ResolverDiscoveryBatch(ResolverDiscoveryStage.MEMORY_AND_PROFILE, it, budget.rememberedConcurrency, 1_200)
            },
            net.takeIf { it.isNotEmpty() }?.let {
                ResolverDiscoveryBatch(ResolverDiscoveryStage.NETWORK, it, budget.networkConcurrency, 1_200)
            },
            regional.takeIf { it.isNotEmpty() }?.let {
                ResolverDiscoveryBatch(ResolverDiscoveryStage.REGIONAL_CORPUS, it, budget.regionalConcurrency, 1_500)
            },
            broad.takeIf { it.isNotEmpty() }?.let {
                ResolverDiscoveryBatch(ResolverDiscoveryStage.BROAD_CORPUS, it, budget.broadConcurrency, 2_000)
            },
        )
    }
}
