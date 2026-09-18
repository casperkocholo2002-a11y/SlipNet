package app.slipnet.tunnel

import android.content.Context
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StoredEchVlessStructuralProfileTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() = EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun activeProfileWebSocketProbeWorksFromStoredEchSeed() {
        runBlocking {
        val profile = entryPoint.profileRepository().getActiveProfile().first()
        assertNotNull("active profile required", profile)
        val p = profile!!
        val config = EchConfigResolver.decodeStoredSeed(p.vlessEchConfigSeed)
        assertNotNull("stored ECH seed required", config)
        VlessBridge.debugLogging = false
        val started = VlessBridge.start(
            listenPort = 11991,
            listenHost = "127.0.0.1",
            cdnIp = p.cdnIp,
            cdnPort = p.cdnPort,
            serverDomain = p.domain,
            vlessUuid = p.vlessUuid,
            security = p.vlessSecurity,
            transport = p.vlessTransport,
            wsPath = p.vlessWsPath,
            fragmentEnabled = false,
            fragmentStrategy = p.sniFragmentStrategy,
            fragmentDelayMs = p.sniFragmentDelayMs,
            sniSpoofTtl = p.sniSpoofTtl,
            fakeDecoyHost = "",
            tcpMaxSeg = p.tcpMaxSeg,
            vlessSni = p.vlessSni,
            chPaddingEnabled = p.chPaddingEnabled,
            wsHeaderObfuscation = p.wsHeaderObfuscation,
            wsPaddingEnabled = false,
            echMode = EchMode.REQUIRED,
            echConfigList = config,
        )
        assertTrue("VlessBridge start failed", started.isSuccess)
        try {
            val probe = VlessBridge.probe(timeoutMs = 10_000)
            assertTrue("stored-ECH structural probe failed: ${probe.exceptionOrNull()?.javaClass?.simpleName}", probe.isSuccess)
            Log.i("SlipNetEAStoredVless", "probe=success;ech=required")
        } finally {
            VlessBridge.stop()
        }
        }
    }
}
