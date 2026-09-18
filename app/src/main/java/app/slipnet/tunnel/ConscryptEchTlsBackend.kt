package app.slipnet.tunnel

import android.os.SystemClock
import app.slipnet.util.AppLog
import org.conscrypt.Conscrypt
import org.conscrypt.EchRejectedException
import java.lang.reflect.Field
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class ConscryptEchTlsBackend : EchTlsBackend {
    override val capability: EchCapability = EchCapability.CONSCRYPT

    companion object {
        // Reuse one Conscrypt SSLContext across flows so TLS 1.3 session caching/resumption
        // can work and we avoid rebuilding provider/trust/PRNG state for every SOCKS flow.
        // ECH remains configured per socket below and REQUIRED policy is unchanged.
        private val sharedContext: SSLContext by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
            if (!Conscrypt.isAvailable()) error("Conscrypt unavailable")
            val provider = Conscrypt.newProvider()
            val context = SSLContext.getInstance("TLS", provider)
            val trustManager = ConscryptRequiredEchTrustManager(TlsIdentity.systemTrustManager())
            context.init(null, arrayOf(trustManager), SecureRandom())
            context.clientSessionContext.sessionCacheSize = 64
            context.clientSessionContext.sessionTimeout = 300
            context
        }
    }

    override fun connect(request: EchConnectRequest): EchConnectResult {
        val config = request.configList
            ?: return EchConnectResult.Failed(IllegalArgumentException("ECH config missing"))
        if (config.isEmpty()) {
            return EchConnectResult.Failed(IllegalArgumentException("ECH config empty"))
        }

        var raw: Socket? = null
        var ssl: SSLSocket? = null
        var tcpConnected = false
        val attemptStartNs = SystemClock.elapsedRealtimeNanos()
        try {
            val context = sharedContext
            raw = Socket().apply {
                connect(InetSocketAddress(request.connectHost, request.port), request.connectTimeoutMs)
                soTimeout = request.readTimeoutMs
            }
            tcpConnected = true
            if (request.telemetryFlowId > 0L) {
                AppLog.operational(
                    "TCP_CONNECTED",
                    "flow" to request.telemetryFlowId,
                    "attempt" to request.telemetryAttempt.toLong(),
                    "ms" to ((SystemClock.elapsedRealtimeNanos() - attemptStartNs) / 1_000_000L),
                )
            }
            val tlsStartNs = SystemClock.elapsedRealtimeNanos()
            ssl = context.socketFactory.createSocket(
                raw, request.serverName, request.port, true
            ) as SSLSocket
            TlsIdentity.configure(ssl, request.serverName)
            Conscrypt.setHostname(ssl, request.serverName)
            Conscrypt.setEchConfigList(ssl, config)
            ssl.startHandshake()
            TlsIdentity.verify(ssl, request.serverName)
            if (request.telemetryFlowId > 0L) {
                AppLog.operational(
                    "ECH_ACCEPTED",
                    "flow" to request.telemetryFlowId,
                    "attempt" to request.telemetryAttempt.toLong(),
                    "tls_ms" to ((SystemClock.elapsedRealtimeNanos() - tlsStartNs) / 1_000_000L),
                )
            }
            return EchConnectResult.Connected(ssl)
        } catch (rejected: EchRejectedException) {
            val retry = ssl?.let(::authenticatedRetryConfig)
            if (retry != null && request.telemetryFlowId > 0L) {
                AppLog.operational(
                    "ECH_AUTHENTICATED_RETRY",
                    "flow" to request.telemetryFlowId,
                    "attempt" to request.telemetryAttempt.toLong(),
                )
            }
            try { ssl?.close() ?: raw?.close() } catch (_: Exception) {}
            return if (retry != null) EchConnectResult.Retry(retry)
            else EchConnectResult.Failed(rejected)
        } catch (error: Throwable) {
            if (request.telemetryFlowId > 0L) {
                AppLog.operational(
                    if (tcpConnected) "FLOW_FAILED_TLS_ECH" else "FLOW_FAILED_TCP",
                    "flow" to request.telemetryFlowId,
                    "attempt" to request.telemetryAttempt.toLong(),
                )
            }
            try { ssl?.close() ?: raw?.close() } catch (_: Exception) {}
            return EchConnectResult.Failed(error)
        }
    }

    private fun authenticatedRetryConfig(socket: SSLSocket): ByteArray? {
        return try {
        val engine = findField(socket.javaClass, "engine").get(socket)
        val nativeSsl = findField(engine.javaClass, "ssl").get(engine)
        val builderMethod = nativeSsl.javaClass.getDeclaredMethod("getEchHandshakeMetricsBuilder")
            .apply { isAccessible = true }
        val builder = builderMethod.invoke(nativeSsl)
        val retry = (findField(builder.javaClass, "retryConfigs").get(builder) as? ByteArray)
            ?.takeIf { it.isNotEmpty() }
            ?: return null
        val publicName = EchConfigListInspector.publicName(retry) ?: return null
        if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(publicName, socket.session)) {
            return null
        }
        retry.copyOf()
        } catch (_: Throwable) {
            null
        }
    }

    private fun findField(type: Class<*>, name: String): Field {
        var current: Class<*>? = type
        while (current != null) {
            try { return current.getDeclaredField(name).apply { isAccessible = true } }
            catch (_: NoSuchFieldException) { current = current.superclass }
        }
        throw NoSuchFieldException(name)
    }
}
