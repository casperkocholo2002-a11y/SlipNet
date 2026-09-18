package app.slipnet.tunnel

import javax.net.ssl.SSLHandshakeException

class EchTlsCoordinator(
    private val backend: EchTlsBackend,
    private val onAuthenticatedRetryAccepted: (ByteArray) -> Unit = {},
    private val standardConnect: (EchConnectRequest) -> EchConnectResult = StandardTlsConnector()::connect,
) {
    fun connect(mode: EchMode, request: EchConnectRequest): EchConnectResult {
        val hasConfig = request.configList?.isNotEmpty() == true
        return when (val decision = EchPolicy.initial(mode, backend.capability, hasConfig)) {
            EchDecision.UseStandardTls -> standardConnect(request.copy(configList = null))
            EchDecision.StartEch -> connectEch(mode, request, retried = false, retryConfig = null)
            is EchDecision.FailClosed -> EchConnectResult.Failed(SSLHandshakeException(decision.reason))
        }
    }

    private fun connectEch(
        mode: EchMode,
        request: EchConnectRequest,
        retried: Boolean,
        retryConfig: ByteArray?,
    ): EchConnectResult {
        return when (val result = backend.connect(request)) {
            is EchConnectResult.Connected -> {
                if (retried && retryConfig?.isNotEmpty() == true) {
                    try { onAuthenticatedRetryAccepted(retryConfig.copyOf()) } catch (_: Throwable) {}
                }
                result
            }
            is EchConnectResult.Failed -> onEchFailure(mode, request, result.error)
            is EchConnectResult.Retry -> {
                if (retried || result.configList.isEmpty()) {
                    onEchFailure(mode, request, SSLHandshakeException("ECH retry exhausted or unsupported"))
                } else {
                    val acceptedCandidate = result.configList.copyOf()
                    connectEch(
                        mode,
                        request.copy(
                            configList = acceptedCandidate,
                            telemetryAttempt = request.telemetryAttempt + 1,
                        ),
                        retried = true,
                        retryConfig = acceptedCandidate,
                    )
                }
            }
        }
    }

    private fun onEchFailure(mode: EchMode, request: EchConnectRequest, error: Throwable): EchConnectResult =
        if (mode == EchMode.PREFERRED) standardConnect(request.copy(configList = null))
        else EchConnectResult.Failed(error)
}
