package app.slipnet.authority

import android.content.Context
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.service.SlipNetVpnService
import app.slipnet.tunnel.VlessBridge
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PersonalVlessDeviceAuthorityIntegrationTest {
    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val entryPoint: DeviceTestEntryPoint
        get() = EntryPoints.get(
            context.applicationContext,
            DeviceTestEntryPoint::class.java,
        )

    @Test
    fun personalProviderRuntimeSemanticsRemainPhase1Owned() {
        val hooks = PersonalVlessAuthorityHooksProvider.hooks
        hooks.clearRoute()
        val route = PersonalVlessRouteDescriptor(
            profileId = 1L,
            routeId = "device-runtime-route",
            providerId = "",
            accountId = "",
            hostname = "",
        )
        hooks.selectRoute(route, listOf(route))
        try {
            hooks.observe(
                PersonalVlessAuthorityFact.NETWORK_CHANGED,
                "device-network-change",
                100L,
            )
            val networkSnapshot = hooks.snapshot()!!
            assertEquals("UNKNOWN", networkSnapshot.healthState)
            assertEquals("NETWORK_CHANGE", networkSnapshot.lastFailure)
            assertNull(networkSnapshot.qualifiedSwitchTarget)
            assertEquals(
                PersonalVlessReconnectDisposition.BLOCK_FAIL_CLOSED,
                hooks.reconnectDisposition(PersonalVlessReconnectOrigin.AUTONOMOUS),
            )
            assertEquals(
                PersonalVlessReconnectDisposition.ALLOW_USER_SAME_PROFILE,
                hooks.reconnectDisposition(PersonalVlessReconnectOrigin.USER_EXPLICIT),
            )
            hooks.observe(
                PersonalVlessAuthorityFact.TRANSPORT_FAILURE,
                "device-controlled-failure",
                200L,
            )
            val failed = hooks.snapshot()!!
            assertEquals("DEGRADED", failed.healthState)
            assertEquals("UNKNOWN", failed.lastFailure)
            assertNull(failed.qualifiedSwitchTarget)
        } finally {
            hooks.clearRoute()
        }
    }

    @Test(timeout = 120_000L)
    fun realPersonalServiceStopsAfterBridgeLoss() = runBlocking {
        val ep = entryPoint
        val profiles = ep.profileRepository()
        val prefs = ep.preferencesDataStore()
        val manager = ep.vpnConnectionManager()
        val oldProxyOnly = prefs.proxyOnlyMode.first()
        val oldKillSwitch = prefs.killSwitch.first()
        val oldAutoReconnect = prefs.autoReconnect.first()
        val oldActive = profiles.getActiveProfile().first()
        var labProfileId = -1L

        try {
            prefs.setProxyOnlyMode(true)
            prefs.setKillSwitch(true)
            prefs.setAutoReconnect(true)

            val host = "websocket-template.signalnerve.workers.dev"
            labProfileId = profiles.saveProfile(
                ServerProfile(
                    name = "SlipMesh R6 Device Lab",
                    domain = host,
                    tunnelType = TunnelType.VLESS,
                    vlessUuid = "00000000-0000-4000-8000-000000000000",
                    vlessSecurity = "tls",
                    vlessTransport = "ws",
                    vlessWsPath = "/ws",
                    cdnIp = host,
                    cdnPort = 443,
                    sniFragmentEnabled = false,
                    vlessSni = host,
                    wsHeaderObfuscation = false,
                )
            )
            val labProfile = requireNotNull(profiles.getProfileById(labProfileId))
            manager.connect(labProfile)

            withTimeout(30_000L) {
                while (manager.connectionState.value !is ConnectionState.Connected) {
                    val state = manager.connectionState.value
                    check(state !is ConnectionState.Error) { "service connect failed: $state" }
                    delay(250L)
                }
            }
            val connected = PersonalVlessAuthorityHooksProvider.hooks.snapshot()!!
            assertEquals("profile:$labProfileId", connected.routeId)
            assertEquals("HEALTHY", connected.healthState)
            assertNull(connected.qualifiedSwitchTarget)
            assertTrue("VLESS bridge must be live after service connect", VlessBridge.isRunning())

            VlessBridge.stop()

            withTimeout(45_000L) {
                while (manager.connectionState.value !is ConnectionState.Error) {
                    delay(250L)
                }
            }
            assertFalse("bridge must remain stopped after autonomous failure", VlessBridge.isRunning())

            withTimeout(20_000L) {
                while (PersonalVlessAuthorityHooksProvider.hooks.snapshot() != null) {
                    assertTrue(
                        "service must remain failed instead of autonomously reconnecting",
                        manager.connectionState.value is ConnectionState.Error,
                    )
                    assertFalse("autonomous reconnect restarted the bridge", VlessBridge.isRunning())
                    delay(250L)
                }
            }
            assertTrue(
                "service must remain failed after cleanup",
                manager.connectionState.value is ConnectionState.Error,
            )
            assertFalse("bridge must remain stopped after cleanup", VlessBridge.isRunning())
        } finally {
            try {
                manager.disconnect()
                delay(1_000L)
            } catch (_: Exception) {
            }
            VlessBridge.stop()
            PersonalVlessAuthorityHooksProvider.hooks.clearRoute()
            if (labProfileId != -1L) {
                try {
                    profiles.deleteProfile(labProfileId)
                } catch (_: Exception) {
                }
            }
            if (oldActive != null) {
                profiles.setActiveProfile(oldActive.id)
            } else {
                profiles.clearActiveProfile()
            }
            prefs.setProxyOnlyMode(oldProxyOnly)
            prefs.setKillSwitch(oldKillSwitch)
            prefs.setAutoReconnect(oldAutoReconnect)
        }
    }
}
