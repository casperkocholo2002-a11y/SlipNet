package app.slipnet.tunnel

import android.content.Context
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import app.slipnet.testsupport.DeviceTestEntryPoint
import dagger.hilt.EntryPoints
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.conscrypt.Conscrypt
import org.conscrypt.EchRejectedException
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Field
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class ConscryptEchRetryDiagnosticTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val entryPoint: DeviceTestEntryPoint get() = EntryPoints.get(context.applicationContext, DeviceTestEntryPoint::class.java)

    @Test
    fun rejectedSeedCarriesAuthenticatedRetryConfig() = runBlocking {
        val p = entryPoint.profileRepository().getActiveProfile().first()!!
        val stale = EchConfigResolver.decodeStoredSeed(p.vlessEchConfigSeed)!!
        val serverName = p.vlessSni.ifBlank { p.domain }
        val provider = Conscrypt.newProvider()
        val sslContext = SSLContext.getInstance("TLS", provider)
        sslContext.init(null, arrayOf(ConscryptRequiredEchTrustManager(TlsIdentity.systemTrustManager())), SecureRandom())
        val raw = Socket().apply {
            connect(InetSocketAddress(p.cdnIp, p.cdnPort), 5_000)
            soTimeout = 10_000
        }
        val ssl = sslContext.socketFactory.createSocket(raw, serverName, p.cdnPort, true) as SSLSocket
        TlsIdentity.configure(ssl, serverName)
        Conscrypt.setHostname(ssl, serverName)
        Conscrypt.setEchConfigList(ssl, stale)
        try {
            ssl.startHandshake()
            error("expected stale ECH config to be rejected")
        } catch (rejected: EchRejectedException) {
            val engine = findField(ssl.javaClass, "engine").get(ssl)
            val nativeSsl = findField(engine.javaClass, "ssl").get(engine)
            val builderMethod = nativeSsl.javaClass.getDeclaredMethod("getEchHandshakeMetricsBuilder")
                .apply { isAccessible = true }
            val builder = builderMethod.invoke(nativeSsl)
            val retry = findField(builder.javaClass, "retryConfigs").get(builder) as? ByteArray
            val publicName = retry?.let(::firstEchPublicName)
            val verified = !publicName.isNullOrBlank() &&
                HttpsURLConnection.getDefaultHostnameVerifier().verify(publicName, ssl.session)
            Log.i(TAG, "retryBytes=${retry?.size ?: 0};publicNamePresent=${!publicName.isNullOrBlank()};verified=$verified")
            assertTrue("missing ECH retry config", retry != null && retry.isNotEmpty())
            assertTrue("retry ECH public name missing", !publicName.isNullOrBlank())
            assertTrue("ECH rejection public identity not authenticated", verified)
        } finally {
            try { ssl.close() } catch (_: Exception) {}
        }
    }

    private fun firstEchPublicName(list: ByteArray): String {
        fun u8(i: Int) = list[i].toInt() and 0xff
        fun u16(i: Int) = (u8(i) shl 8) or u8(i + 1)
        var p = 2
        require(list.size >= 6 && u16(0) <= list.size - 2)
        require(u16(p) == 0xfe0d)
        val configEnd = p + 4 + u16(p + 2)
        p += 4
        p += 1
        p += 2
        val publicKeyLen = u16(p); p += 2 + publicKeyLen
        val suitesLen = u16(p); p += 2 + suitesLen
        p += 1
        val nameLen = u8(p); p += 1
        require(nameLen > 0 && p + nameLen <= configEnd)
        return list.copyOfRange(p, p + nameLen).toString(Charsets.US_ASCII)
    }

    private fun findField(type: Class<*>, name: String): Field {
        var current: Class<*>? = type
        while (current != null) {
            try { return current.getDeclaredField(name).apply { isAccessible = true } }
            catch (_: NoSuchFieldException) { current = current.superclass }
        }
        error("field $name unavailable")
    }

    private companion object { const val TAG = "SlipNetEAEchRetryDiag" }
}
