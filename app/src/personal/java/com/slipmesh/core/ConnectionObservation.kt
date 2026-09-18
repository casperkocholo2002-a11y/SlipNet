package com.slipmesh.core

enum class ObservationLayer {
    DNS,
    TCP,
    TLS,
    HTTP,
    WEBSOCKET,
    TRANSPORT,
    NETWORK
}

enum class ObservationOutcome {
    SUCCESS,
    TIMEOUT,
    REFUSED,
    ALERT,
    FAILURE,
    STALL,
    CHANGED
}

/**
 * A raw fact observed by the connectivity layer.
 *
 * This model deliberately contains no censorship inference.
 */
data class ConnectionObservation(
    val layer: ObservationLayer,
    val outcome: ObservationOutcome,
    val responseCode: Int? = null,
    val timestampEpochMs: Long,
    val detail: String? = null,

    /**
     * True only when this successful observation represents completion
     * of the route's connectivity path.
     *
     * Intermediate successes such as DNS resolution or TCP connect must
     * not reset route health.
     */
    val terminal: Boolean = false
) {
    init {
        require(timestampEpochMs >= 0)
    }
}
