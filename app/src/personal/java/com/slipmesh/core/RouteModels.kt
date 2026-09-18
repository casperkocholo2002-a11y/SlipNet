package com.slipmesh.core

/**
 * Transport implementations supported by the SlipMesh architecture.
 *
 * Only LEGACY_VLESS_WS_TLS is expected to be usable in Phase 1.
 * The others reserve stable architectural seams for later phases.
 */
enum class TransportKind {
    LEGACY_VLESS_WS_TLS,
    HTTPS_ECH,
    HTTP3_QUIC,
    SLIPSTREAM_BLACKOUT
}

/**
 * Health is deliberately separate from transport type.
 * A route can become unhealthy without implying that the entire
 * transport implementation is broken.
 */
enum class HealthState {
    UNKNOWN,
    HEALTHY,
    DEGRADED,
    SUSPECTED_BLOCK,
    UNREACHABLE,
    COOLDOWN
}

enum class FailureReason {
    NONE,

    DNS_FAILURE,

    TCP_TIMEOUT,
    TCP_REFUSED,

    TLS_TIMEOUT,
    TLS_ALERT,

    HTTP_FAILURE,
    WEBSOCKET_UPGRADE_FAILURE,

    TRANSPORT_STALL,

    NETWORK_CHANGE,

    UNKNOWN
}

/**
 * Routes sharing any of these values may share a common failure domain.
 */
data class FailureDomain(
    val providerId: String,
    val accountId: String,
    val hostname: String
) {
    init {
        require(providerId.isNotBlank())
        require(accountId.isNotBlank())
        require(hostname.isNotBlank())
    }
}

data class RouteCandidate(
    val id: String,

    val transport: TransportKind,

    val failureDomain: FailureDomain,

    /**
     * Higher value means the operator generally prefers this route.
     *
     * Runtime health and failure-domain diversity may override it.
     */
    val basePriority: Int = 100,

    val enabled: Boolean = true
) {
    init {
        require(id.isNotBlank())
        require(basePriority in 0..1000)
    }
}

data class RouteHealth(
    val state: HealthState = HealthState.UNKNOWN,

    val lastFailure: FailureReason = FailureReason.NONE,

    val consecutiveFailures: Int = 0,

    val lastSuccessEpochMs: Long? = null,

    val lastFailureEpochMs: Long? = null
) {
    init {
        require(consecutiveFailures >= 0)
    }
}
