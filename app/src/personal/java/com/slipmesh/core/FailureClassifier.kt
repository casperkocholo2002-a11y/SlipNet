package com.slipmesh.core

/**
 * Deterministic mapping from observed network facts to failure categories.
 *
 * Important:
 * This classifier does NOT decide whether censorship occurred.
 * It only classifies the observed failure.
 */
object FailureClassifier {

    fun classify(
        observation: ConnectionObservation
    ): FailureReason {

        if (observation.outcome == ObservationOutcome.SUCCESS) {

            if (
                observation.layer == ObservationLayer.WEBSOCKET &&
                observation.responseCode != null &&
                observation.responseCode != 101
            ) {
                return FailureReason.WEBSOCKET_UPGRADE_FAILURE
            }

            if (
                observation.layer == ObservationLayer.HTTP &&
                observation.responseCode != null &&
                observation.responseCode !in 200..399
            ) {
                return FailureReason.HTTP_FAILURE
            }

            return FailureReason.NONE
        }

        return when (
            observation.layer to observation.outcome
        ) {

            ObservationLayer.DNS to
                ObservationOutcome.TIMEOUT,

            ObservationLayer.DNS to
                ObservationOutcome.FAILURE ->
                FailureReason.DNS_FAILURE


            ObservationLayer.TCP to
                ObservationOutcome.TIMEOUT ->
                FailureReason.TCP_TIMEOUT

            ObservationLayer.TCP to
                ObservationOutcome.REFUSED ->
                FailureReason.TCP_REFUSED


            ObservationLayer.TLS to
                ObservationOutcome.TIMEOUT ->
                FailureReason.TLS_TIMEOUT

            ObservationLayer.TLS to
                ObservationOutcome.ALERT ->
                FailureReason.TLS_ALERT


            ObservationLayer.HTTP to
                ObservationOutcome.FAILURE,

            ObservationLayer.HTTP to
                ObservationOutcome.TIMEOUT ->
                FailureReason.HTTP_FAILURE


            ObservationLayer.WEBSOCKET to
                ObservationOutcome.FAILURE,

            ObservationLayer.WEBSOCKET to
                ObservationOutcome.TIMEOUT ->
                FailureReason.WEBSOCKET_UPGRADE_FAILURE


            ObservationLayer.TRANSPORT to
                ObservationOutcome.STALL ->
                FailureReason.TRANSPORT_STALL


            ObservationLayer.NETWORK to
                ObservationOutcome.CHANGED ->
                FailureReason.NETWORK_CHANGE


            else ->
                FailureReason.UNKNOWN
        }
    }
}
