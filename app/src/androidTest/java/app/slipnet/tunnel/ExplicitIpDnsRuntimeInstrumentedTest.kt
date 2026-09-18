package app.slipnet.tunnel

import android.util.Log
import com.slipmesh.modern.dns.DnsEchBootstrapCoordinator
import com.slipmesh.modern.dns.EchDnsBootstrapResult
import com.slipmesh.modern.dns.EchDnsParseResult
import com.slipmesh.modern.dns.EchResolverFetchResult
import com.slipmesh.modern.dns.EchResolverSource
import com.slipmesh.modern.dns.EchResolverSourceSet
import com.slipmesh.modern.dns.HttpsSvcbEchParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ExplicitIpDnsRuntimeInstrumentedTest {
    private val hostname = "crypto.cloudflare.com"
    private val sources = listOf(
        EchResolverSource("cloudflare", "cloudflare-public-dns"),
        EchResolverSource("google", "google-public-dns"),
    )
    private val sourceSet = EchResolverSourceSet(sources)
    private val fetcher = LiteralIpDohEchResolverFetcher(
        LiteralDohEndpointRegistry(
            listOf(
                LiteralDohEndpoint("cloudflare", "1.1.1.1", "cloudflare-dns.com"),
                LiteralDohEndpoint("google", "8.8.8.8", "dns.google"),
            )
        ),
        timeoutMs = 6_000,
    )

    @Test
    fun independentEncryptedLiteralIpResolversBootstrapEch() {
        var foundCount = 0
        for (source in sourceSet.enabledSources) {
            val fetched = fetcher.fetch(source, hostname)
            assertTrue("fetch failed for ${source.sourceId}: $fetched", fetched is EchResolverFetchResult.Response)
            val parsed = HttpsSvcbEchParser.parse((fetched as EchResolverFetchResult.Response).copyBytes())
            if (parsed is EchDnsParseResult.Found) {
                assertTrue(parsed.copyBytes().isNotEmpty())
                foundCount++
            }
            assertTrue("parse rejected for ${source.sourceId}: $parsed", parsed !is EchDnsParseResult.Rejected)
            Log.i("SlipNetEADoh", "source=${source.sourceId};echFound=${parsed is EchDnsParseResult.Found}")
        }
        assertTrue("at least one independent resolver must return ECH", foundCount >= 1)
        val integrated = DnsEchBootstrapCoordinator(sourceSet, fetcher).resolve(hostname)
        assertTrue(integrated is EchDnsBootstrapResult.Resolved)
        integrated as EchDnsBootstrapResult.Resolved
        assertTrue(integrated.copyBytes().isNotEmpty())
        assertEquals(integrated.sourceId, integrated.attempts.last().sourceId)
        Log.i("SlipNetEADoh", "bootstrapSource=${integrated.sourceId};attempts=${integrated.attempts.size}")
    }
}
