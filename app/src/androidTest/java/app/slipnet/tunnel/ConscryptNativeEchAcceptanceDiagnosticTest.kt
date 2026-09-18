package app.slipnet.tunnel

import android.util.Log
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Field
import javax.net.ssl.SSLSocket

class ConscryptNativeEchAcceptanceDiagnosticTest {
    private val host = "crypto.cloudflare.com"

    @Test
    fun nativeAcceptanceIsTrueAfterRequiredHandshake() = runBlocking {
        val config = EchConfigResolver.resolve(host, 10_000)
        assertTrue("ECHConfigList missing", config != null && config.isNotEmpty())

        val result = EchTlsCoordinator(EchBackends.current()).connect(
            EchMode.REQUIRED,
            EchConnectRequest(
                connectHost = host,
                port = 443,
                serverName = host,
                configList = config,
            )
        )
        assertTrue("ECH handshake failed: $result", result is EchConnectResult.Connected)
        val socket = (result as EchConnectResult.Connected).socket
        try {
            val accepted = nativeEchAccepted(socket)
            Log.i(TAG, "NATIVE_ECH_ACCEPTED=$accepted")

            val trace = fetchTrace(socket)
            val sniLine = trace.lineSequence().firstOrNull { it.startsWith("sni=") }
            Log.i(TAG, "CLOUDFLARE_TRACE_SNI=${sniLine ?: "missing"}")

            assertTrue(
                "Native SSL_ech_accepted=false; Cloudflare ${sniLine ?: "sni marker missing"}",
                accepted,
            )
        } finally {
            socket.close()
        }
    }

    private fun nativeEchAccepted(socket: SSLSocket): Boolean {
        val engineField = findField(socket.javaClass, "engine")
        val engine = engineField.get(socket)
        val nativeSslField = findField(engine.javaClass, "ssl")
        val nativeSsl = nativeSslField.get(engine)
        val handleField = findField(nativeSsl.javaClass, "ssl")
        val handle = handleField.getLong(nativeSsl)
        check(handle != 0L) { "Native SSL handle is zero" }
        val nativeCrypto = Class.forName("org.conscrypt.NativeCrypto")
        val method = nativeCrypto.getDeclaredMethod(
            "SSL_ech_accepted",
            java.lang.Long.TYPE,
            nativeSsl.javaClass,
        ).apply { isAccessible = true }
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
        error("Field $name not found from ${type.name}")
    }

    private fun fetchTrace(socket: SSLSocket): String {
        val request = buildString {
            append("GET /cdn-cgi/trace HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("Connection: close\r\n")
            append("User-Agent: SlipMesh-ECH-Native-Acceptance-Lab\r\n\r\n")
        }
        socket.outputStream.write(request.toByteArray(Charsets.US_ASCII))
        socket.outputStream.flush()
        return socket.inputStream.bufferedReader(Charsets.US_ASCII).use { it.readText() }
    }

    private companion object {
        const val TAG = "ConscryptEchAcceptDiag"
    }
}
