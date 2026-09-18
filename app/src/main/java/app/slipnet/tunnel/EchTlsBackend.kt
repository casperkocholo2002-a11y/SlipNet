package app.slipnet.tunnel

import javax.net.ssl.SSLSocket

data class EchConnectRequest(
    val connectHost: String,
    val port: Int,
    val serverName: String,
    val configList: ByteArray? = null,
    val connectTimeoutMs: Int = 10_000,
    val readTimeoutMs: Int = 15_000,
    val telemetryFlowId: Long = 0L,
    val telemetryAttempt: Int = 0,
)

sealed interface EchConnectResult {
    data class Connected(val socket: SSLSocket) : EchConnectResult
    data class Retry(val configList: ByteArray) : EchConnectResult
    data class Failed(val error: Throwable) : EchConnectResult
}

interface EchTlsBackend {
    val capability: EchCapability
    fun connect(request: EchConnectRequest): EchConnectResult
}
