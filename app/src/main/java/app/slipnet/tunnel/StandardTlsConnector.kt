package app.slipnet.tunnel

import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class StandardTlsConnector {
    fun connect(request: EchConnectRequest): EchConnectResult {
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        try {
            val context = SSLContext.getInstance("TLS")
            context.init(null, null, SecureRandom())
            raw = Socket().apply {
                connect(InetSocketAddress(request.connectHost, request.port), request.connectTimeoutMs)
                soTimeout = request.readTimeoutMs
            }
            ssl = context.socketFactory.createSocket(raw, request.serverName, request.port, true) as SSLSocket
            TlsIdentity.configure(ssl, request.serverName)
            ssl.startHandshake()
            TlsIdentity.verify(ssl, request.serverName)
            return EchConnectResult.Connected(ssl)
        } catch (error: Throwable) {
            try { ssl?.close() ?: raw?.close() } catch (_: Exception) {}
            return EchConnectResult.Failed(error)
        }
    }
}
