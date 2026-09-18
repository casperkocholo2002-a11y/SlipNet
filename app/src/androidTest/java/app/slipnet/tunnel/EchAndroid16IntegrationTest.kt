package app.slipnet.tunnel

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLSocket

class EchAndroid16IntegrationTest {
    private val host = "crypto.cloudflare.com"

    @Test
    fun requiredEchReportsEncryptedSni() = runBlocking {
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
            val trace = fetchTrace(socket)
            assertTrue("Expected encrypted SNI marker:\n$trace", trace.contains("sni=encrypted"))
        } finally {
            socket.close()
        }
    }
    @Test
    fun requiredModeNeedsConfig() {
        val request = EchConnectRequest(
            connectHost = host,
            port = 443,
            serverName = host,
            configList = null,
        )
        val required = EchTlsCoordinator(EchBackends.current())
            .connect(EchMode.REQUIRED, request)
        assertTrue(required is EchConnectResult.Failed)

        val plain = StandardTlsConnector().connect(request)
        assertTrue("Control TLS failed: $plain", plain is EchConnectResult.Connected)
        val plainSocket = (plain as EchConnectResult.Connected).socket
        plainSocket.close()
    }
    private fun fetchTrace(socket: SSLSocket): String {
        val request = buildString {
            append("GET /cdn-cgi/trace HTTP/1.1\r\n")
            append("Host: $host\r\n")
            append("Connection: close\r\n")
            append("User-Agent: SlipMesh-ECH-Lab\r\n\r\n")
        }
        socket.outputStream.write(request.toByteArray(Charsets.US_ASCII))
        socket.outputStream.flush()
        return socket.inputStream.bufferedReader(Charsets.US_ASCII).use { it.readText() }
    }
}
