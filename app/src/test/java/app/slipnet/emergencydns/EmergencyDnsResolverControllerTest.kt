package app.slipnet.emergencydns

import app.slipnet.domain.model.DnsTunnelTestResult
import app.slipnet.domain.model.E2eTestResult
import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EmergencyDnsResolverControllerTest {
    private val controller = EmergencyDnsResolverController()
    private val scope = ResolverNetworkScope.fingerprint(listOf("cellular", "dns:10.0.0.1"))
    private val now = 1_000_000L

    private fun good(host: String, latency: Long = 50) = ResolverScanResult(
        host = host,
        status = ResolverStatus.WORKING,
        responseTimeMs = latency,
        tunnelTestResult = DnsTunnelTestResult(
            tunnelRealism = true,
            edns0Support = true,
            ednsMaxPayload = 1232,
            nxdomainCorrect = true,
        ),
        e2eTestResult = E2eTestResult(success = true, totalMs = 200),
        prismVerified = true,
        udpWorking = true,
        tcpWorking = true,
    )

    @Test fun stagedDiscoveryStartsWithKnownScopeMemoryAndDeduplicatesProfile() {
        val remembered = ResolverMemoryRecord(scope, "192.0.2.1", 53, 3, 0, 0, now - 100, null, true)
        val batches = controller.discoveryBatches(
            scopeId = scope,
            memory = listOf(remembered),
            profileResolvers = listOf("192.0.2.1" to 53, "198.51.100.1" to 53),
            networkResolvers = listOf("10.0.0.1" to 53),
            regionalCorpus = listOf("203.0.113.1"),
            broadCorpus = listOf("203.0.114.1"),
            nowMs = now,
        )
        assertEquals(ResolverDiscoveryStage.MEMORY_AND_PROFILE, batches.first().stage)
        assertEquals("192.0.2.1", batches.first().candidates.first().host)
        assertEquals(1, batches.flatMap { it.candidates }.count { it.host == "192.0.2.1" })
    }

    @Test fun activeSetRejectsUnauthenticatedOrNonE2eResolver() {
        val ok = good("192.0.2.2", 20)
        val untrusted = good("198.51.100.2", 10).copy(prismVerified = false)
        val broken = good("203.0.113.2", 5).copy(e2eTestResult = E2eTestResult(success = false))
        val plan = controller.selectActiveSet(
            scope, emptyList(),
            listOf(
                ok to ResolverCandidateSource.CORPUS,
                untrusted to ResolverCandidateSource.CORPUS,
                broken to ResolverCandidateSource.CORPUS,
            ),
            now,
        )
        assertEquals(listOf(ok.host), plan.activeSet.map { it.host })
        assertFalse(plan.activeSet.any { it.host == untrusted.host })
        assertFalse(plan.activeSet.any { it.host == broken.host })
    }

    @Test fun learningRequiresWorkingPrismAndE2eTogether() {
        val ok = good("192.0.2.3")
        val afterSuccess = controller.learn(emptyList(), scope, ok, now)
        assertEquals(1, afterSuccess.single().successCount)
        assertTrue(afterSuccess.single().prismEverVerified)

        val failed = ok.copy(e2eTestResult = E2eTestResult(success = false))
        val afterFailure = controller.learn(afterSuccess, scope, failed, now + 1)
        assertEquals(1, afterFailure.single().failureCount)
        assertEquals(1, afterFailure.single().consecutiveFailures)
    }
}
