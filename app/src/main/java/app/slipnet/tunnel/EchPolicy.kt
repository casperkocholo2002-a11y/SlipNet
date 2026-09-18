package app.slipnet.tunnel

enum class EchMode {
    DISABLED,
    PREFERRED,
    REQUIRED,
}

enum class EchCapability {
    PLATFORM,
    CONSCRYPT,
    UNAVAILABLE,
}

sealed interface EchDecision {
    data object UseStandardTls : EchDecision
    data object StartEch : EchDecision
    data class FailClosed(val reason: String) : EchDecision
}

object EchPolicy {
    fun initial(mode: EchMode, capability: EchCapability, hasConfig: Boolean): EchDecision = when (mode) {
        EchMode.DISABLED -> EchDecision.UseStandardTls
        EchMode.PREFERRED -> if (capability != EchCapability.UNAVAILABLE && hasConfig) EchDecision.StartEch else EchDecision.UseStandardTls
        EchMode.REQUIRED -> if (capability != EchCapability.UNAVAILABLE && hasConfig) EchDecision.StartEch else EchDecision.FailClosed("ECH required but unavailable")
    }

    fun afterFailure(mode: EchMode): EchDecision = when (mode) {
        EchMode.DISABLED, EchMode.PREFERRED -> EchDecision.UseStandardTls
        EchMode.REQUIRED -> EchDecision.FailClosed("ECH required but failed")
    }
}
