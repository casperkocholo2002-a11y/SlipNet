package com.slipmesh.modern.dns

sealed interface EchResolverOutcome {
    data class Found(val echConfigList: ByteArray) : EchResolverOutcome {
        private val stored = echConfigList.copyOf()
        fun copyBytes(): ByteArray = stored.copyOf()
    }
    data class FetchFailed(val failure: EchResolverFetchFailure) : EchResolverOutcome
    data class ParseRejected(val failure: EchDnsParseFailure, val rcode: Int? = null) : EchResolverOutcome
    data object NoEch : EchResolverOutcome
}

data class EchResolverAttempt(val sourceId: String, val outcome: EchResolverOutcome)

sealed interface EchDnsBootstrapResult {
    data class Resolved(
        val sourceId: String,
        val echConfigList: ByteArray,
        val attempts: List<EchResolverAttempt>,
    ) : EchDnsBootstrapResult {
        private val stored = echConfigList.copyOf()
        fun copyBytes(): ByteArray = stored.copyOf()
    }
    data class Failed(val attempts: List<EchResolverAttempt>) : EchDnsBootstrapResult
}

class DnsEchBootstrapCoordinator(
    private val sources: EchResolverSourceSet,
    private val fetcher: EchResolverFetcher,
) {
    fun resolve(hostname: String): EchDnsBootstrapResult {
        require(hostname.isNotBlank())
        val attempts = mutableListOf<EchResolverAttempt>()
        for (source in sources.enabledSources) {
            when (val fetched = fetcher.fetch(source, hostname)) {
                is EchResolverFetchResult.Failed -> attempts += EchResolverAttempt(
                    source.sourceId,
                    EchResolverOutcome.FetchFailed(fetched.failure),
                )
                is EchResolverFetchResult.Response -> when (val parsed = HttpsSvcbEchParser.parse(fetched.copyBytes())) {
                    is EchDnsParseResult.Found -> {
                        val bytes = parsed.copyBytes()
                        attempts += EchResolverAttempt(source.sourceId, EchResolverOutcome.Found(bytes))
                        return EchDnsBootstrapResult.Resolved(source.sourceId, bytes, attempts.toList())
                    }
                    EchDnsParseResult.NoEch -> attempts += EchResolverAttempt(source.sourceId, EchResolverOutcome.NoEch)
                    is EchDnsParseResult.Rejected -> attempts += EchResolverAttempt(
                        source.sourceId,
                        EchResolverOutcome.ParseRejected(parsed.failure, parsed.rcode),
                    )
                }
            }
        }
        return EchDnsBootstrapResult.Failed(attempts.toList())
    }
}
