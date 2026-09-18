package app.slipnet.tunnel

import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import org.junit.Assert.assertTrue
import org.junit.Test

class LiteralIpDotTlsDiagnosticTest {
    private data class Candidate(val id: String, val ip: ByteArray, val host: String)

    @Test
    fun atLeastTwoIndependentDotProvidersHandshake() {
        val candidates = listOf(
            Candidate("adguard", byteArrayOf(94, 140.toByte(), 14, 14), "dns.adguard-dns.com"),
            Candidate("cleanbrowsing", byteArrayOf(185.toByte(), 228.toByte(), 168.toByte(), 9), "security-filter-dns.cleanbrowsing.org"),
            Candidate("mullvad", byteArrayOf(194.toByte(), 242.toByte(), 2, 2), "dns.mullvad.net"),
        )
        var ok = 0
        for (candidate in candidates) {
            try {
                handshake(candidate)
                Log.i("SlipNetEADotDiag", "provider=${candidate.id};tls=ok")
                ok++
            } catch (t: Throwable) {
                Log.i("SlipNetEADotDiag", "provider=${candidate.id};tls=fail;type=${t.javaClass.simpleName};msg=${t.message}")
            }
        }
        assertTrue("need >=2 independent encrypted DNS providers, got $ok", ok >= 2)
    }

    private fun handshake(candidate: Candidate) {
        val raw = Socket()
        raw.connect(InetSocketAddress(InetAddress.getByAddress(candidate.ip), 853), 5000)
        val context = SSLContext.getInstance("TLS")
        context.init(null, arrayOf<TrustManager>(TlsIdentity.systemTrustManager()), null)
        val ssl = context.socketFactory.createSocket(raw, candidate.host, 853, true) as SSLSocket
        ssl.use { socket ->
            socket.soTimeout = 5000
            TlsIdentity.configure(socket, candidate.host)
            socket.startHandshake()
            TlsIdentity.verify(socket, candidate.host)
        }
    }
}
