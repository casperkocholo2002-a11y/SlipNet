package app.slipnet.tunnel

import android.content.Context
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.domain.model.TunnelType
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthenticatedEchSeedRenewalInstrumentedTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() =
        EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test(timeout = 120_000L)
    fun staleSeedRetriesPersistsAndNextConnectionUsesFreshSeedDirectly() {
        runBlocking {
        val repository = entryPoint.profileRepository()
        val manager = entryPoint.vpnConnectionManager()
        val source = repository.getActiveProfile().first() ?: error("active profile required")
        require(source.tunnelType == TunnelType.VLESS) { "active VLESS profile required" }
        require(source.vlessSecurity.equals("tls", ignoreCase = true)) { "TLS VLESS profile required" }
        require(DomainRouter.isIpAddress(source.cdnIp)) { "literal CDN IP required for DNS-free bootstrap" }
        val staleSeed = EchConfigResolver.decodeStoredSeed(source.vlessEchConfigSeed)
        assertNotNull("stored ECH seed required", staleSeed)

        var labId = -1L
        try {
            labId = repository.saveProfile(
                source.copy(
                    id = 0L,
                    name = "SlipNet EA Authenticated ECH Renewal Lab",
                    isActive = false,
                    vlessFailureProviderId = "renewal-lab-provider",
                    vlessFailureAccountId = "renewal-lab-account",
                    vlessFailureHostname = "renewal-lab.invalid",
                    vlessEchConfigUpdatedAt = 23L,
                )
            )
            val before = requireNotNull(repository.getProfileById(labId))
            val firstCallbacks = AtomicInteger(0)
            val persisted = AtomicBoolean(false)
            val acceptedBytes = AtomicReference<ByteArray?>(null)
            val renewalTimestamp = 1_789_550_000_456L

            val firstPort = freeLoopbackPort()
            val firstStarted = startBridge(
                profile = before,
                listenPort = firstPort,
                config = staleSeed!!,
                onAccepted = { fresh ->
                    firstCallbacks.incrementAndGet()
                    acceptedBytes.set(fresh.copyOf())
                    val ok = runBlocking {
                        manager.persistAuthenticatedVlessEchSeed(labId, fresh, renewalTimestamp)
                    }
                    persisted.set(ok)
                },
            )
            assertTrue("first VLESS bridge start failed", firstStarted.isSuccess)
            try {
                val probe = VlessBridge.probe(timeoutMs = 15_000)
                assertTrue(
                    "stale-seed authenticated retry probe failed: ${probe.exceptionOrNull()?.javaClass?.simpleName}",
                    probe.isSuccess,
                )
                val liveFollowUp = VlessBridge.probe(timeoutMs = 15_000)
                assertTrue(
                    "live renewed-seed follow-up probe failed: ${liveFollowUp.exceptionOrNull()?.javaClass?.simpleName}",
                    liveFollowUp.isSuccess,
                )
            } finally {
                VlessBridge.stop()
            }

            assertEquals("authenticated retry callback count", 1, firstCallbacks.get())
            assertTrue("retry-derived seed was not persisted", persisted.get())
            val accepted = acceptedBytes.get()
            assertNotNull("accepted retry config missing", accepted)

            val renewed = requireNotNull(repository.getProfileById(labId))
            assertNotEquals("seed did not change after authenticated retry", before.vlessEchConfigSeed, renewed.vlessEchConfigSeed)
            assertEquals(renewalTimestamp, renewed.vlessEchConfigUpdatedAt)
            assertEquals(
                before.copy(
                    vlessEchConfigSeed = renewed.vlessEchConfigSeed,
                    vlessEchConfigUpdatedAt = renewalTimestamp,
                ),
                renewed,
            )
            val persistedBytes = EchConfigResolver.decodeStoredSeed(renewed.vlessEchConfigSeed)
            assertNotNull("persisted renewed seed cannot be decoded", persistedBytes)
            assertTrue("persisted seed differs from accepted retry material", persistedBytes!!.contentEquals(accepted!!))

            val secondCallbacks = AtomicInteger(0)
            val secondPort = freeLoopbackPort()
            val secondStarted = startBridge(
                profile = renewed,
                listenPort = secondPort,
                config = persistedBytes,
                onAccepted = { secondCallbacks.incrementAndGet() },
            )
            assertTrue("second VLESS bridge start failed", secondStarted.isSuccess)
            try {
                val probe = VlessBridge.probe(timeoutMs = 15_000)
                assertTrue(
                    "renewed-seed direct probe failed: ${probe.exceptionOrNull()?.javaClass?.simpleName}",
                    probe.isSuccess,
                )
            } finally {
                VlessBridge.stop()
            }
            assertEquals("fresh persisted seed unexpectedly required another retry", 0, secondCallbacks.get())
            assertFalse("lab profile must never become active", requireNotNull(repository.getProfileById(labId)).isActive)
            Log.i(TAG, "renewal=pass;firstRetryCallbacks=1;liveFollowUpRetryCallbacks=0;secondRetryCallbacks=0;dnsBootstrap=literal-ip")
        } finally {
            VlessBridge.stop()
            if (labId > 0) try { repository.deleteProfile(labId) } catch (_: Exception) {}
        }
        }
    }

    private fun startBridge(
        profile: app.slipnet.domain.model.ServerProfile,
        listenPort: Int,
        config: ByteArray,
        onAccepted: (ByteArray) -> Unit,
    ): Result<Unit> {
        VlessBridge.debugLogging = false
        return VlessBridge.start(
            listenPort = listenPort,
            listenHost = "127.0.0.1",
            cdnIp = profile.cdnIp,
            cdnPort = profile.cdnPort,
            serverDomain = profile.domain,
            vlessUuid = profile.vlessUuid,
            security = profile.vlessSecurity,
            transport = profile.vlessTransport,
            wsPath = profile.vlessWsPath,
            fragmentEnabled = false,
            fragmentStrategy = profile.sniFragmentStrategy,
            fragmentDelayMs = profile.sniFragmentDelayMs,
            sniSpoofTtl = profile.sniSpoofTtl,
            fakeDecoyHost = "",
            tcpMaxSeg = profile.tcpMaxSeg,
            vlessSni = profile.vlessSni,
            chPaddingEnabled = profile.chPaddingEnabled,
            wsHeaderObfuscation = profile.wsHeaderObfuscation,
            wsPaddingEnabled = false,
            echMode = EchMode.REQUIRED,
            echConfigList = config,
            onAuthenticatedEchConfigAccepted = onAccepted,
        )
    }

    private fun freeLoopbackPort(): Int = ServerSocket(0).use { it.localPort }

    private companion object { const val TAG = "SlipNetEAEchRenewal" }
}
