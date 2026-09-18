package app.slipnet.authority

import com.slipmesh.core.ConnectionObservation
import com.slipmesh.core.FailoverAction
import com.slipmesh.core.FailoverOrchestrator
import com.slipmesh.core.FailoverSnapshot
import com.slipmesh.core.FailureClassifier
import com.slipmesh.core.FailureDomain
import com.slipmesh.core.FailureReason
import com.slipmesh.core.HealthStore
import com.slipmesh.core.ObservationLayer
import com.slipmesh.core.ObservationOutcome
import com.slipmesh.core.RouteCandidate
import com.slipmesh.core.RouteHealth
import com.slipmesh.core.TransportKind

enum class RouteSelectionReadiness {
    READY,
    BLOCKED_MISSING_FAILURE_DOMAIN_METADATA,
}

data class PersonalVlessAuthorityState(
    val routeId: String,
    val health: RouteHealth,
    val lastClassifiedFailure: FailureReason,
    val routeSelectionReadiness: RouteSelectionReadiness,
    val authorityAction: FailoverAction,
    val qualifiedSwitchTarget: String?,
)

class PersonalVlessAuthorityFoundation(
    private val activeRoute: PersonalVlessRouteDescriptor,
    private val routeDescriptors: List<PersonalVlessRouteDescriptor>,
) {
    private val healthStore = HealthStore()
    private val metadataComplete =
        activeRoute.hasCompleteFailureDomain &&
            routeDescriptors.isNotEmpty() &&
            routeDescriptors.all { !it.enabled || it.hasCompleteFailureDomain }
    private val routes: List<RouteCandidate> =
        if (!metadataComplete) emptyList() else routeDescriptors
            .filter { it.enabled }
            .map { descriptor ->
                RouteCandidate(
                    id = descriptor.routeId,
                    transport = TransportKind.LEGACY_VLESS_WS_TLS,
                    failureDomain = FailureDomain(
                        providerId = descriptor.providerId,
                        accountId = descriptor.accountId,
                        hostname = descriptor.hostname,
                    ),
                    basePriority = descriptor.basePriority,
                    enabled = true,
                )
            }
    private val orchestrator =
        if (metadataComplete) {
            FailoverOrchestrator(
                healthStore = healthStore,
                initialSnapshot = FailoverSnapshot(activeRouteId = activeRoute.routeId),
            )
        } else null
    private var lastClassifiedFailure = FailureReason.NONE
    private var lastAction = FailoverAction.NONE
    private var qualifiedTarget: String? = null

    init {
        require(activeRoute.routeId.isNotBlank())
        require(routeDescriptors.any { it.routeId == activeRoute.routeId })
        require(routeDescriptors.map { it.routeId }.distinct().size == routeDescriptors.size)
    }

    @Synchronized
    fun observe(observation: ConnectionObservation): PersonalVlessAuthorityState {
        lastClassifiedFailure = FailureClassifier.classify(observation)
        if (!metadataComplete) {
            healthStore.recordObservation(activeRoute.routeId, observation)
            return state()
        }

        val transition = if (
            observation.terminal && observation.outcome == ObservationOutcome.SUCCESS
        ) {
            orchestrator!!.terminalSuccess(activeRoute.routeId, observation.timestampEpochMs)
        } else {
            healthStore.recordObservation(activeRoute.routeId, observation)
            orchestrator!!.evaluate(
                routes = routes,
                timestampEpochMs = observation.timestampEpochMs,
                networkChanged = observation.layer == ObservationLayer.NETWORK &&
                    observation.outcome == ObservationOutcome.CHANGED,
            )
        }

        lastAction = transition.action
        qualifiedTarget = if (transition.action == FailoverAction.SWITCH_TO_TARGET) {
            transition.snapshot.targetRouteId
        } else null
        return state()
    }

    @Synchronized
    fun snapshot(): PersonalVlessAuthorityState = state()

    @Synchronized
    fun qualifiedSwitchTargetOrNull(): String? = qualifiedTarget

    @Synchronized
    fun qualifiedSwitchTargetDescriptorOrNull(): PersonalVlessRouteDescriptor? =
        qualifiedTarget?.let { target -> routeDescriptors.firstOrNull { it.routeId == target } }

    private fun state(): PersonalVlessAuthorityState =
        PersonalVlessAuthorityState(
            routeId = activeRoute.routeId,
            health = healthStore.get(activeRoute.routeId),
            lastClassifiedFailure = lastClassifiedFailure,
            routeSelectionReadiness = if (metadataComplete) {
                RouteSelectionReadiness.READY
            } else {
                RouteSelectionReadiness.BLOCKED_MISSING_FAILURE_DOMAIN_METADATA
            },
            authorityAction = lastAction,
            qualifiedSwitchTarget = qualifiedTarget,
        )
}
