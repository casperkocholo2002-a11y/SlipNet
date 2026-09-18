package app.slipnet.domain.model

import app.slipnet.BuildConfig

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelTypeAvailabilityTest {
    @Test fun personalBuildAllowsOnlyExplicitlyQualifiedTransports() {
        assertTrue(TunnelType.VLESS.isAvailable())
        if (BuildConfig.EMERGENCY_DNS_LAB) {
            assertTrue(TunnelType.DNSTT.isAvailable())
            TunnelType.entries
                .filter { it != TunnelType.VLESS && it != TunnelType.DNSTT }
                .forEach { assertFalse("Unexpected DNS lab transport: $it", it.isAvailable()) }
        } else {
            TunnelType.entries
                .filter { it != TunnelType.VLESS }
                .forEach { assertFalse("Unexpected personal transport: $it", it.isAvailable()) }
        }
    }
}
