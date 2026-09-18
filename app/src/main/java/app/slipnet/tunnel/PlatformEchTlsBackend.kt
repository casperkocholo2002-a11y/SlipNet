package app.slipnet.tunnel

import android.annotation.TargetApi
import android.net.ssl.EchConfigList
import android.net.ssl.EchConfigMismatchException
import android.net.ssl.SSLSockets
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

@TargetApi(37)
class PlatformEchTlsBackend : EchTlsBackend {
    override val capability: EchCapability = EchCapability.PLATFORM

    override fun connect(request: EchConnectRequest): EchConnectResult {
        val config = request.configList
            ?: return EchConnectResult.Failed(IllegalArgumentException("ECH config missing"))
        if (config.isEmpty()) return EchConnectResult.Failed(IllegalArgumentException("ECH config empty"))

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
            SSLSockets.setEchConfigList(ssl, EchConfigList.fromBytes(config))
            ssl.startHandshake()
            TlsIdentity.verify(ssl, request.serverName)
            return EchConnectResult.Connected(ssl)
        } catch (mismatch: EchConfigMismatchException) {
            val publicName = mismatch.publicHostname
            val verified = publicName != null && ssl != null &&
                HttpsURLConnection.getDefaultHostnameVerifier().verify(publicName, ssl.session)
            val retry = if (verified) mismatch.retryConfigList else null
            try { ssl?.close() ?: raw?.close() } catch (_: Exception) {}
            return if (retry != null) EchConnectResult.Retry(retry.toBytes()) else EchConnectResult.Failed(mismatch)
        } catch (error: Throwable) {
            try { ssl?.close() ?: raw?.close() } catch (_: Exception) {}
            return EchConnectResult.Failed(error)
        }
    }
}
