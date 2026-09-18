package app.slipnet.authority

import com.slipmesh.core.ConnectionObservation
import com.slipmesh.core.FailureReason
import com.slipmesh.core.HealthState
import com.slipmesh.core.ObservationLayer
import com.slipmesh.core.ObservationOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PersonalVlessAuthorityFoundationTest {
    private val routeA = route(1, "route-a", "provider-a", "account-a", "a.example")
    private val routeB = route(2, "route-b", "provider-b", "account-b", "b.example")
    private val authority = PersonalVlessAuthorityFoundation(routeA, listOf(routeA, routeB))

    @Test fun intermediateSuccessDoesNotHealFailedRoute() {
        authority.observe(observation(ObservationLayer.TRANSPORT, ObservationOutcome.STALL, 10))
        val state = authority.observe(observation(ObservationLayer.TLS, ObservationOutcome.SUCCESS, 20))
        assertEquals(HealthState.DEGRADED, state.health.state)
        assertEquals(1, state.health.consecutiveFailures)
    }

    @Test fun terminalSuccessHealsRoute() {
        authority.observe(observation(ObservationLayer.TRANSPORT, ObservationOutcome.STALL, 10))
        val state = authority.observe(observation(ObservationLayer.WEBSOCKET, ObservationOutcome.SUCCESS, 20, 101, true))
        assertEquals(HealthState.HEALTHY, state.health.state)
        assertEquals(0, state.health.consecutiveFailures)
        assertEquals(FailureReason.NONE, state.lastClassifiedFailure)
    }

    @Test fun dnsTimeoutUsesCanonicalClassification() {
        val state = authority.observe(observation(ObservationLayer.DNS, ObservationOutcome.TIMEOUT, 10))
        assertEquals(FailureReason.DNS_FAILURE, state.lastClassifiedFailure)
    }

    @Test fun completeMetadataMakesSelectionReady() {
        assertEquals(RouteSelectionReadiness.READY, authority.snapshot().routeSelectionReadiness)
    }

    @Test fun missingMetadataBlocksSelection() {
        val incomplete = routeA.copy(providerId = "")
        val blocked = PersonalVlessAuthorityFoundation(incomplete, listOf(incomplete, routeB))
        assertEquals(RouteSelectionReadiness.BLOCKED_MISSING_FAILURE_DOMAIN_METADATA, blocked.snapshot().routeSelectionReadiness)
        assertNull(blocked.qualifiedSwitchTargetOrNull())
    }

    @Test fun firstFailureRequestsAuthorityOwnedProbeBeforeSwitch() {
        val state = authority.observe(observation(ObservationLayer.TRANSPORT, ObservationOutcome.FAILURE, 10))
        assertEquals(com.slipmesh.core.FailoverAction.PROBE_CURRENT, state.authorityAction)
        assertNull(authority.qualifiedSwitchTargetOrNull())
    }

    @Test fun repeatedFailureQualifiesDeterministicAlternateWithoutExecutingIt() {
        authority.observe(observation(ObservationLayer.TRANSPORT, ObservationOutcome.FAILURE, 10))
        val state = authority.observe(observation(ObservationLayer.TRANSPORT, ObservationOutcome.FAILURE, 20))
        assertEquals(com.slipmesh.core.FailoverAction.SWITCH_TO_TARGET, state.authorityAction)
        assertEquals("route-b", authority.qualifiedSwitchTargetOrNull())
    }

    private fun route(id: Long, routeId: String, provider: String, account: String, host: String) =
        PersonalVlessRouteDescriptor(id, routeId, provider, account, host)

    private fun observation(layer: ObservationLayer, outcome: ObservationOutcome, timestamp: Long, responseCode: Int? = null, terminal: Boolean = false) =
        ConnectionObservation(layer, outcome, responseCode, timestampEpochMs = timestamp, terminal = terminal)
}
