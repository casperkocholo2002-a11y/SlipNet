package app.slipnet.tunnel

import org.conscrypt.Conscrypt
import org.conscrypt.DomainEncryptionMode
import org.conscrypt.NetworkSecurityPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class ConscryptEngineSocketPolicyDiagnosticTest {
    @Test
    fun realEngineSocketRetainsRequiredPolicy() {
        val context = SSLContext.getInstance("TLS", Conscrypt.newProvider())
        val trustManager = ConscryptRequiredEchTrustManager(TlsIdentity.systemTrustManager())
        context.init(null, arrayOf(trustManager), SecureRandom())
        val socket = context.socketFactory.createSocket() as SSLSocket
        try {
            val engine = findField(socket.javaClass, "engine").get(socket)
            val parameters = findField(engine.javaClass, "sslParameters").get(engine)
            val policy = parameters.javaClass.getDeclaredMethod("getPolicy").apply {
                isAccessible = true
            }.invoke(parameters) as NetworkSecurityPolicy
            assertEquals(DomainEncryptionMode.REQUIRED, policy.getDomainEncryptionMode("crypto.cloudflare.com"))
            val tm = findField(parameters.javaClass, "x509TrustManager").get(parameters)
            assertTrue(tm is ConscryptRequiredEchTrustManager)
        } finally {
            socket.close()
        }
    }

    private fun findField(type: Class<*>, name: String): java.lang.reflect.Field {
        var current: Class<*>? = type
        while (current != null) {
            try {
                return current.getDeclaredField(name).apply { isAccessible = true }
            } catch (_: NoSuchFieldException) {
                current = current.superclass
            }
        }
        error("Field $name not found from ${type.name}")
    }
}
