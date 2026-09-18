package app.slipnet.tunnel

import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import org.junit.Assert.assertTrue
import org.junit.Test

class LiteralIpDohTlsDiagnosticTest {
    @Test
    fun directIpTlsWithoutDnsHostnameSni() {
        testEndpoint("1.1.1.1", byteArrayOf(1, 1, 1, 1))
        testEndpoint("8.8.8.8", byteArrayOf(8, 8, 8, 8))
    }

    private fun testEndpoint(ip: String, bytes: ByteArray) {
        val raw = Socket()
        raw.connect(InetSocketAddress(InetAddress.getByAddress(bytes), 443), 5000)
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(TlsIdentity.systemTrustManager()), null)
        val ssl = context.socketFactory.createSocket(raw, ip, 443, true) as SSLSocket
        ssl.use { socket ->
            socket.soTimeout = 5000
            val params = socket.sslParameters
            params.endpointIdentificationAlgorithm = "HTTPS"
            socket.sslParameters = params
            socket.startHandshake()
            assertTrue("IP certificate verification failed for $ip", HttpsURLConnection.getDefaultHostnameVerifier().verify(ip, socket.session))
            Log.i("SlipNetEADohDiag", "ip=$ip;tls=ok;protocol=${socket.session.protocol}")
        }
    }
}
