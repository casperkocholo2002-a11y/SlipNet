package app.slipnet.emergencydns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ResolverMemoryTest {
    private val scope = ResolverNetworkScope.fingerprint(listOf("cellular", "dns:10.0.0.1", "iface:rmnet0"))

    @Test fun scopeFingerprintIsDeterministicAndDoesNotContainRawMaterial() {
        val a = ResolverNetworkScope.fingerprint(listOf("dns:10.0.0.1", "cellular", "iface:rmnet0"))
        val b = ResolverNetworkScope.fingerprint(listOf("IFACE:RMNET0", " cellular ", "dns:10.0.0.1"))
        assertEquals(a, b)
        assertFalse(a.contains("rmnet"))
        assertFalse(a.contains("10.0.0.1"))
        assertEquals(32, a.length)
    }

    @Test fun differentNetworkFactsProduceDifferentScopes() {
        assertNotEquals(
            ResolverNetworkScope.fingerprint(listOf("cellular", "dns:10.0.0.1")),
            ResolverNetworkScope.fingerprint(listOf("wifi", "dns:192.168.1.1")),
        )
    }

    @Test fun memoryRoundTripAndMalformedRowsFailSoft() {
        val records = listOf(
            ResolverMemoryRecord(scope, "192.0.2.1", 53, 3, 1, 0, 1000, 500, true),
            ResolverMemoryRecord(scope, "198.51.100.1", 5353, 1, 0, 0, 900, null, false),
        )
        val raw = ResolverMemoryCodec.encode(records) + "bad|row\n"
        val decoded = ResolverMemoryCodec.decode(raw)
        assertEquals(records.toSet(), decoded.toSet())
    }

    @Test fun successfulObservationClearsFailureStreakAndKeepsPrismTrust() {
        val old = ResolverMemoryRecord(scope, "192.0.2.2", 53, 1, 2, 2, 100, 200, true)
        val updated = ResolverMemoryCodec.update(listOf(old), scope, old.host, 53, true, false, 1000).single()
        assertEquals(2, updated.successCount)
        assertEquals(0, updated.consecutiveFailures)
        assertEquals(1000L, updated.lastSuccessAtMs)
        assertTrue(updated.prismEverVerified)
    }

    @Test fun failureUsesBoundedCounter() {
        var records = emptyList<ResolverMemoryRecord>()
        repeat(50) { i ->
            records = ResolverMemoryCodec.update(records, scope, "192.0.2.3", 53, false, false, i.toLong())
        }
        assertEquals(30, records.single().consecutiveFailures)
        assertEquals(50, records.single().failureCount)
    }

    @Test fun stagedDiscoveryDeduplicatesAndKeepsConcurrencyConservative() {
        val remembered = ResolverCandidate("192.0.2.1", source = ResolverCandidateSource.VERIFIED_MEMORY)
        val duplicateProfile = ResolverCandidate("192.0.2.1", source = ResolverCandidateSource.PROFILE)
        val network = ResolverCandidate("198.51.100.1", source = ResolverCandidateSource.NETWORK)
        val regional = (1..400).map { ResolverCandidate("203.0.${it / 255}.${it % 255}", source = ResolverCandidateSource.CORPUS) }
        val broad = (1..2000).map { ResolverCandidate("100.${it / 65536}.${(it / 256) % 256}.${it % 256}", source = ResolverCandidateSource.CORPUS) }

        val batches = ResolverStagedDiscoveryPlanner().batches(
            listOf(remembered), listOf(duplicateProfile), listOf(network), regional, broad
        )
        assertEquals(4, batches.size)
        assertEquals(listOf(remembered), batches[0].candidates)
        assertEquals(1, batches[1].candidates.size)
        assertEquals(256, batches[2].candidates.size)
        assertEquals(1024, batches[3].candidates.size)
        assertTrue(batches.all { it.concurrency <= 10 })
    }
}
