package app.slipnet.authority

import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.domain.model.ConnectionState
import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import app.slipnet.testsupport.DeviceTestEntryPoint
import app.slipnet.tunnel.VlessBridge
import dagger.hilt.EntryPoints
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersonalVlessAuthoritySwitchDeviceTest {
    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val entryPoint: DeviceTestEntryPoint
        get() = EntryPoints.get(
            context.applicationContext,
            DeviceTestEntryPoint::class.java,
        )

    @Test(timeout = 180_000L)
    fun localProfilesSwitchOnceThenFailClosedWithoutLegacyLoop() = runBlocking {
        val ep = entryPoint
        val profiles = ep.profileRepository()
        val prefs = ep.preferencesDataStore()
        val manager = ep.vpnConnectionManager()
        val oldProxyOnly = prefs.proxyOnlyMode.first()
        val oldKillSwitch = prefs.killSwitch.first()
        val oldAutoReconnect = prefs.autoReconnect.first()
        val oldActive = profiles.getActiveProfile().first()
        val listenerA = loopbackListener()
        val listenerB = loopbackListener()
        var profileAId = -1L
        var profileBId = -1L

        try {
            prefs.setProxyOnlyMode(true)
            prefs.setKillSwitch(true)
            prefs.setAutoReconnect(true)

            profileAId = profiles.saveProfile(
                labProfile(
                    name = "SlipNet EA R3 Local A",
                    port = listenerA.localPort,
                    provider = "r3-provider-a",
                    account = "r3-account-a",
                    failureHost = "r3-a.local",
                )
            )
            profileBId = profiles.saveProfile(
                labProfile(
                    name = "SlipNet EA R3 Local B",
                    port = listenerB.localPort,
                    provider = "r3-provider-b",
                    account = "r3-account-b",
                    failureHost = "r3-b.local",
                )
            )

            val profileA = requireNotNull(profiles.getProfileById(profileAId))
            manager.connect(profileA)
            awaitConnected(manager, profileAId, profiles)
            assertEquals("profile:$profileAId", PersonalVlessAuthorityHooksProvider.hooks.snapshot()!!.routeId)
            assertTrue(VlessBridge.isRunning())

            // Make A unavailable, then stop the local bridge so the service observes a real failure.
            listenerA.close()
            VlessBridge.stop()

            // First failure is authority-owned PROBE_CURRENT. The retry of A fails locally,
            // second failure reaches the canonical threshold and must switch to B.
            withTimeout(60_000L) {
                while (true) {
                    val active = profiles.getActiveProfile().first()
                    val state = manager.connectionState.value
                    if (active?.id == profileBId && state is ConnectionState.Connected) break
                    check(state !is ConnectionState.Error) { "authority switch failed before B: $state" }
                    delay(250L)
                }
            }
            assertEquals("profile:$profileBId", PersonalVlessAuthorityHooksProvider.hooks.snapshot()!!.routeId)
            assertTrue(VlessBridge.isRunning())

            // Make B unavailable too. A is already in the attempted-route set, so the
            // authority must fail closed instead of bouncing B -> A through legacy reconnect.
            listenerB.close()
            VlessBridge.stop()
            withTimeout(60_000L) {
                while (manager.connectionState.value !is ConnectionState.Error) {
                    delay(250L)
                }
            }
            delay(8_000L) // longer than legacy 3s reconnect cadence
            assertTrue(manager.connectionState.value is ConnectionState.Error)
            assertFalse("legacy reconnect or switch loop restarted VLESS", VlessBridge.isRunning())
        } finally {
            try { listenerA.close() } catch (_: Exception) {}
            try { listenerB.close() } catch (_: Exception) {}
            try {
                manager.disconnect()
                delay(1_000L)
            } catch (_: Exception) {}
            VlessBridge.stop()
            PersonalVlessAuthorityHooksProvider.hooks.clearRoute()
            if (profileAId != -1L) try { profiles.deleteProfile(profileAId) } catch (_: Exception) {}
            if (profileBId != -1L) try { profiles.deleteProfile(profileBId) } catch (_: Exception) {}
            if (oldActive != null) profiles.setActiveProfile(oldActive.id) else profiles.clearActiveProfile()
            prefs.setProxyOnlyMode(oldProxyOnly)
            prefs.setKillSwitch(oldKillSwitch)
            prefs.setAutoReconnect(oldAutoReconnect)
        }
    }

    private suspend fun awaitConnected(
        manager: app.slipnet.service.VpnConnectionManager,
        profileId: Long,
        profiles: app.slipnet.domain.repository.ProfileRepository,
    ) {
        withTimeout(30_000L) {
            while (true) {
                val state = manager.connectionState.value
                val active = profiles.getActiveProfile().first()
                if (state is ConnectionState.Connected && active?.id == profileId) break
                check(state !is ConnectionState.Error) { "local lab connect failed: $state" }
                delay(200L)
            }
        }
    }

    private fun loopbackListener(): ServerSocket =
        ServerSocket().apply {
            reuseAddress = true
            bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        }

    private fun labProfile(
        name: String,
        port: Int,
        provider: String,
        account: String,
        failureHost: String,
    ) = ServerProfile(
        name = name,
        domain = "localhost",
        tunnelType = TunnelType.VLESS,
        vlessUuid = "00000000-0000-4000-8000-000000000000",
        vlessSecurity = "none",
        vlessTransport = "tcp",
        vlessWsPath = "/",
        cdnIp = "127.0.0.1",
        cdnPort = port,
        sniFragmentEnabled = false,
        wsHeaderObfuscation = false,
        vlessFailureProviderId = provider,
        vlessFailureAccountId = account,
        vlessFailureHostname = failureHost,
    )
}
