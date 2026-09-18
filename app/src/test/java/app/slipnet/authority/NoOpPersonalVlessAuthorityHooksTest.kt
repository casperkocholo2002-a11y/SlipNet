package app.slipnet.authority

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NoOpPersonalVlessAuthorityHooksTest {
    private val hooks = NoOpPersonalVlessAuthorityHooks()

    @Test
    fun legacyFlavorHookNeverOwnsReconnectPolicy() {
        val route = PersonalVlessRouteDescriptor(1, "route-1", "p", "a", "h")
        hooks.selectRoute(route, listOf(route))
        hooks.observe(PersonalVlessAuthorityFact.TRANSPORT_STALL, "ignored", 1L)
        assertEquals(
            PersonalVlessReconnectDisposition.ALLOW_LEGACY,
            hooks.reconnectDisposition(PersonalVlessReconnectOrigin.AUTONOMOUS),
        )
        assertNull(hooks.snapshot())
    }
}
