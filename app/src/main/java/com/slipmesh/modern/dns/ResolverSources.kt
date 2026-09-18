package com.slipmesh.modern.dns

data class EchResolverSource(
    val sourceId: String,
    val failureDomainId: String,
    val enabled: Boolean = true,
) {
    init {
        require(sourceId.isNotBlank())
        require(failureDomainId.isNotBlank())
    }

    internal fun normalizedFailureDomain(): String = failureDomainId.trim().lowercase()
}

class EchResolverSourceSet(sources: Collection<EchResolverSource>) {
    val enabledSources: List<EchResolverSource>

    init {
        require(sources.map { it.sourceId }.distinct().size == sources.size) { "resolver source ids must be unique" }
        enabledSources = sources.filter { it.enabled }.sortedBy { it.sourceId }
        require(enabledSources.size >= 2) { "at least two resolver sources are required" }
        require(enabledSources.map { it.normalizedFailureDomain() }.distinct().size >= 2) {
            "resolver sources must span at least two failure domains"
        }
    }
}

enum class EchResolverFetchFailure {
    TIMEOUT,
    UNAVAILABLE,
    IO_FAILURE,
    UNKNOWN,
}

sealed interface EchResolverFetchResult {
    data class Response(val packet: ByteArray) : EchResolverFetchResult {
        private val stored = packet.copyOf()
        fun copyBytes(): ByteArray = stored.copyOf()
    }
    data class Failed(val failure: EchResolverFetchFailure) : EchResolverFetchResult
}

fun interface EchResolverFetcher {
    fun fetch(source: EchResolverSource, hostname: String): EchResolverFetchResult
}
