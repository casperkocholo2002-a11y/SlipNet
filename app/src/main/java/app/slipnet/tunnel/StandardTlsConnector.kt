package app.slipnet.tunnel

import android.os.SystemClock
import app.slipnet.util.AppLog
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class StandardTlsConnector {
    fun connect(request: EchConnectRequest): EchConnectResult {
        var raw: Socket? = null
        var ssl: SSLSocket? = null
        val startedNs = SystemClock.elapsedRealtimeNanos()
        try {
            val context = SSLContext.getInstance("TLS")
            context.init(null, null, SecureRandom())
            raw = Socket().apply {
                connect(InetSocketAddress(request.connectHost, request.port), request.connectTimeoutMs)
                soTimeout = request.readTimeoutMs
            }
            if (request.telemetryFlowId > 0L) {
                AppLog.operational(
                    "STD_TLS_TCP_CONNECTED",
                    "flow" to request.telemetryFlowId,
                    "ms" to ((SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L),
                )
            }
            ssl = context.socketFactory.createSocket(raw, request.serverName, request.port, true) as SSLSocket
            TlsIdentity.configure(ssl, request.serverName)
            if (request.telemetryFlowId > 0L) {
                AppLog.operational("STD_TLS_HANDSHAKE_STARTED", "flow" to request.telemetryFlowId)
            }
            ssl.startHandshake()
            TlsIdentity.verify(ssl, request.serverName)
            if (request.telemetryFlowId > 0L) {
                AppLog.operational(
                    "STD_TLS_HANDSHAKE_OK",
                    "flow" to request.telemetryFlowId,
                    "ms" to ((SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L),
                )
            }
            return EchConnectResult.Connected(ssl)
        } catch (error: Throwable) {
            if (request.telemetryFlowId > 0L) {
                AppLog.operational(
                    "STD_TLS_FAILED_" + error.javaClass.simpleName.uppercase(),
                    "flow" to request.telemetryFlowId,
                    "ms" to ((SystemClock.elapsedRealtimeNanos() - startedNs) / 1_000_000L),
                )
            }
            try { ssl?.close() ?: raw?.close() } catch (_: Exception) {}
            return EchConnectResult.Failed(error)
        }
    }
}
