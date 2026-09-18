package app.slipnet.tunnel

import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal object TlsIdentity {
    fun systemTrustManager(): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().single()
    }

    fun configure(socket: SSLSocket, serverName: String) {
        val parameters: SSLParameters = socket.sslParameters
        parameters.serverNames = listOf(SNIHostName(serverName))
        parameters.endpointIdentificationAlgorithm = "HTTPS"
        socket.sslParameters = parameters
    }

    fun verify(socket: SSLSocket, serverName: String) {
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(serverName, socket.session)) {
            throw SSLHandshakeException("TLS hostname verification failed")
        }
    }
}
