package app.slipnet.tunnel

import android.util.Base64
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test

class SeededEchTraceInstrumentedTest {
    @Test
    fun literalIpSeededEchReportsEncryptedSni() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        val host = args.getString("ech_host") ?: error("ech_host missing")
        val ip = args.getString("ech_ip") ?: error("ech_ip missing")
        val encoded = args.getString("ech_seed_b64") ?: error("ech_seed_b64 missing")
        assertTrue("connect target must be literal IP", DomainRouter.isIpAddress(ip))
        val seed = Base64.decode(encoded, Base64.DEFAULT)
        assertTrue(seed.isNotEmpty())

        val result = EchTlsCoordinator(EchBackends.current()).connect(
            EchMode.REQUIRED,
            EchConnectRequest(ip, 443, host, seed),
        )
        assertTrue("ECH connection failed: $result", result is EchConnectResult.Connected)
        val socket = (result as EchConnectResult.Connected).socket
        try {
            val request = buildString {
                append("GET /cdn-cgi/trace HTTP/1.1\r\n")
                append("Host: $host\r\n")
                append("Connection: close\r\n")
                append("User-Agent: SlipNet-EA-ECH-Trace\r\n\r\n")
            }
            socket.outputStream.write(request.toByteArray(Charsets.US_ASCII))
            socket.outputStream.flush()
            val body = socket.inputStream.bufferedReader(Charsets.US_ASCII).use { it.readText() }
            val sni = body.lineSequence().firstOrNull { it.startsWith("sni=") }
            Log.i("SlipNetEAEchTrace", sni ?: "sni=missing")
            assertTrue("Cloudflare did not report encrypted SNI: $sni", sni == "sni=encrypted")
        } finally {
            socket.close()
        }
    }
}
