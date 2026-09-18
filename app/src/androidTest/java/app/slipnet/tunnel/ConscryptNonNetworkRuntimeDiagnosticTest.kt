package app.slipnet.tunnel

import android.util.Log
import org.conscrypt.Conscrypt
import org.conscrypt.DomainEncryptionMode
import org.conscrypt.NetworkSecurityPolicy
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import javax.net.ssl.SSLContext

class ConscryptNonNetworkRuntimeDiagnosticTest {
    private val host = "crypto.cloudflare.com"
    private val fixedConfig = hexToBytes(
        "0045fe0d0041c30020002046c11e13cfc9a45ca2e3f71a65ade13d5024690b36" +
            "e950cb507232c040014b310004000100010012636c6f7564666c6172652d656368" +
            "2e636f6d0000"
    )

    @Test
    fun requiredPolicyOptionsAndNativeParseAreVisibleWithoutNetwork() {
        assertTrue("Conscrypt unavailable", Conscrypt.isAvailable())
        val provider = Conscrypt.newProvider()
        val context = SSLContext.getInstance("TLS", provider)
        val trustManager = ConscryptRequiredEchTrustManager(TlsIdentity.systemTrustManager())
        context.init(null, arrayOf(trustManager), SecureRandom())

        val engine = context.createSSLEngine(host, 443)
        assertTrue("Expected app-local Conscrypt engine", Conscrypt.isConscrypt(engine))
        engine.useClientMode = true
        Conscrypt.setHostname(engine, host)
        Conscrypt.setEchConfigList(engine, fixedConfig)

        val parametersField = engine.javaClass.getDeclaredField("sslParameters").apply {
            isAccessible = true
        }
        val parameters = parametersField.get(engine)

        val getPolicy = parameters.javaClass.getDeclaredMethod("getPolicy").apply {
            isAccessible = true
        }
        val policy = getPolicy.invoke(parameters) as NetworkSecurityPolicy
        val policyMode = policy.getDomainEncryptionMode(host)

        val getEchOptions = parameters.javaClass
            .getDeclaredMethod("getEchOptions", String::class.java)
            .apply { isAccessible = true }
        val options = getEchOptions.invoke(parameters, host)
        assertNotNull("ECH options missing", options)
        val optionsClass = options!!.javaClass
        val grease = optionsClass.getMethod("isGreaseEnabled").invoke(options) as Boolean
        val optionsConfig = optionsClass.getMethod("getConfigList").invoke(options) as ByteArray

        val nativeSslField = engine.javaClass.getDeclaredField("ssl").apply {
            isAccessible = true
        }
        val nativeSsl = nativeSslField.get(engine)
        val sslHandleField = nativeSsl.javaClass.getDeclaredField("ssl").apply {
            isAccessible = true
        }
        val sslHandle = sslHandleField.getLong(nativeSsl)

        val nativeCryptoClass = Class.forName("org.conscrypt.NativeCrypto")
        val nativeSetter = nativeCryptoClass.getDeclaredMethod(
            "SSL_set1_ech_config_list",
            java.lang.Long.TYPE,
            nativeSsl.javaClass,
            ByteArray::class.java,
        ).apply { isAccessible = true }
        val nativeAccepted = nativeSetter.invoke(null, sslHandle, nativeSsl, fixedConfig) as Boolean

        Log.i(TAG, "POLICY_MODE=$policyMode")
        Log.i(TAG, "OPTIONS_PRESENT=true GREASE=$grease CONFIG_MATCH=${fixedConfig.contentEquals(optionsConfig)}")
        Log.i(TAG, "NATIVE_SSL_HANDLE_NONZERO=${sslHandle != 0L} NATIVE_CONFIG_ACCEPTED=$nativeAccepted")
        assertEquals("Policy did not resolve REQUIRED", DomainEncryptionMode.REQUIRED, policyMode)
        assertFalse("REQUIRED unexpectedly enabled GREASE", grease)
        assertArrayEquals("ECHConfigList changed before native path", fixedConfig, optionsConfig)
        assertTrue("Native SSL handle was zero", sslHandle != 0L)
        assertTrue("Native SSL_set1_ech_config_list rejected fixed config", nativeAccepted)
    }

    private fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0)
        return ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private companion object {
        const val TAG = "ConscryptNonetDiag"
    }
}
