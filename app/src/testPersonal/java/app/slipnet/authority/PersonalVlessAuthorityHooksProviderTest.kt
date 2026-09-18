package app.slipnet.authority

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PersonalVlessAuthorityHooksProviderTest {
    private val hooks = PersonalVlessAuthorityHooksProvider.hooks
    private val a = PersonalVlessRouteDescriptor(1, "route-1", "p1", "a1", "h1")
    private val b = PersonalVlessRouteDescriptor(2, "route-2", "p2", "a2", "h2")

    @After fun reset() = hooks.clearRoute()
    private fun select() = hooks.selectRoute(a, listOf(a, b))

    @Test fun autonomousReconnectIsFailClosed() {
        select()
        assertEquals(PersonalVlessReconnectDisposition.BLOCK_FAIL_CLOSED, hooks.reconnectDisposition(PersonalVlessReconnectOrigin.AUTONOMOUS))
    }

    @Test fun explicitReconnectIsSameProfileExecution() {
        select()
        assertEquals(PersonalVlessReconnectDisposition.ALLOW_USER_SAME_PROFILE, hooks.reconnectDisposition(PersonalVlessReconnectOrigin.USER_EXPLICIT))
    }

    @Test fun terminalSuccessHealsRoute() {
        select(); hooks.observe(PersonalVlessAuthorityFact.TERMINAL_SUCCESS, "connected", 20L)
        assertEquals("HEALTHY", hooks.snapshot()!!.healthState)
    }

    @Test fun firstTransportFailureRequestsProbeOnly() {
        select()
        hooks.observe(PersonalVlessAuthorityFact.TRANSPORT_FAILURE, "fail-1", 30L)
        val snapshot = hooks.snapshot()!!
        assertEquals("PROBE_CURRENT", snapshot.authorityAction)
        assertNull(snapshot.qualifiedSwitchTarget)
    }

    @Test fun repeatedTransportFailureExposesAlternateButDoesNotExecuteIt() {
        select()
        hooks.observe(PersonalVlessAuthorityFact.TRANSPORT_FAILURE, "fail-1", 30L)
        hooks.observe(PersonalVlessAuthorityFact.TRANSPORT_FAILURE, "fail-2", 40L)
        val snapshot = hooks.snapshot()!!
        assertEquals("SWITCH_TO_TARGET", snapshot.authorityAction)
        assertEquals("route-2", snapshot.qualifiedSwitchTarget)
    }

    @Test fun incompleteCatalogNeverExposesSwitchTarget() {
        val incomplete = a.copy(accountId = "")
        hooks.selectRoute(incomplete, listOf(incomplete, b))
        hooks.observe(PersonalVlessAuthorityFact.TRANSPORT_FAILURE, "fail-1", 30L)
        hooks.observe(PersonalVlessAuthorityFact.TRANSPORT_FAILURE, "fail-2", 40L)
        assertNull(hooks.snapshot()!!.qualifiedSwitchTarget)
    }
}
