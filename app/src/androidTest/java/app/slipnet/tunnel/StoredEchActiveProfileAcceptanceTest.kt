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
import java.lang.reflect.Field
import javax.net.ssl.SSLSocket

class StoredEchActiveProfileAcceptanceTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() = EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun storedSeedProducesNativeAcceptedEchOnActiveProfile() = runBlocking {
        val profile = entryPoint.profileRepository().getActiveProfile().first()
        assertNotNull("active profile required", profile)
        val p = profile!!
        assertTrue("ECH route must connect to a literal CDN IP", DomainRouter.isIpAddress(p.cdnIp))
        assertTrue("ECH route must not enable SNI fragmentation", !p.sniFragmentEnabled)
        val config = EchConfigResolver.decodeStoredSeed(p.vlessEchConfigSeed)
        assertNotNull("stored ECH seed required", config)
        val serverName = p.vlessSni.ifBlank { p.domain }
        val result = EchTlsCoordinator(EchBackends.current()).connect(
            EchMode.REQUIRED,
            EchConnectRequest(connectHost = p.cdnIp, port = p.cdnPort, serverName = serverName, configList = config),
        )
        assertTrue("ECH handshake failed: $result", result is EchConnectResult.Connected)
        val socket = (result as EchConnectResult.Connected).socket
        try {
            val accepted = nativeEchAccepted(socket)
            Log.i("SlipNetEAStoredEch", "nativeAccepted=$accepted")
            assertTrue("native ECH was not accepted", accepted)
        } finally {
            socket.close()
        }
    }

    private fun nativeEchAccepted(socket: SSLSocket): Boolean {
        val engine = findField(socket.javaClass, "engine").get(socket)
        val nativeSsl = findField(engine.javaClass, "ssl").get(engine)
        val handle = findField(nativeSsl.javaClass, "ssl").getLong(nativeSsl)
        check(handle != 0L)
        val nativeCrypto = Class.forName("org.conscrypt.NativeCrypto")
        val method = nativeCrypto.getDeclaredMethod("SSL_ech_accepted", java.lang.Long.TYPE, nativeSsl.javaClass)
            .apply { isAccessible = true }
        return method.invoke(null, handle, nativeSsl) as Boolean
    }

    private fun findField(type: Class<*>, name: String): Field {
        var current: Class<*>? = type
        while (current != null) {
            try {
                return current.getDeclaredField(name).apply { isAccessible = true }
            } catch (_: NoSuchFieldException) {
                current = current.superclass
            }
        }
        error("field unavailable")
    }
}
