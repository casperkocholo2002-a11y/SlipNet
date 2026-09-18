package app.slipnet.tunnel

import com.slipmesh.modern.dns.DnsEchBootstrapCoordinator
import com.slipmesh.modern.dns.EchDnsBootstrapResult
import com.slipmesh.modern.dns.EchResolverSource
import com.slipmesh.modern.dns.EchResolverSourceSet

object EchConfigResolver {
    private val sources = EchResolverSourceSet(
        listOf(
            EchResolverSource("cloudflare", "cloudflare-public-dns"),
            EchResolverSource("google", "google-public-dns"),
        )
    )

    private fun coordinator(timeoutMs: Long): DnsEchBootstrapCoordinator {
        val boundedTimeout = timeoutMs.coerceIn(500L, 10_000L).toInt()
        val endpoints = LiteralDohEndpointRegistry(
            listOf(
                LiteralDohEndpoint("cloudflare", "1.1.1.1", "cloudflare-dns.com"),
                LiteralDohEndpoint("google", "8.8.8.8", "dns.google"),
            )
        )
        val fetcher = LiteralIpDohEchResolverFetcher(
            endpoints = endpoints,
            timeoutMs = boundedTimeout,
        )
        return DnsEchBootstrapCoordinator(sources, fetcher)
    }

    suspend fun resolve(hostname: String, timeoutMs: Long = 5_000): ByteArray? {
        if (hostname.isBlank()) return null
        return when (val result = coordinator(timeoutMs).resolve(hostname.trimEnd('.'))) {
            is EchDnsBootstrapResult.Resolved -> result.copyBytes()
            is EchDnsBootstrapResult.Failed -> null
        }
    }

    private const val MAX_STORED_ECH_BYTES = 8_192

    fun decodeStoredSeed(encoded: String): ByteArray? {
        if (encoded.isBlank()) return null
        return try {
            val bytes = android.util.Base64.decode(encoded.trim(), android.util.Base64.DEFAULT)
            if (bytes.isEmpty() || bytes.size > MAX_STORED_ECH_BYTES) null else bytes
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    fun encodeStoredSeed(bytes: ByteArray): String? {
        if (bytes.isEmpty() || bytes.size > MAX_STORED_ECH_BYTES) return null
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }
}
