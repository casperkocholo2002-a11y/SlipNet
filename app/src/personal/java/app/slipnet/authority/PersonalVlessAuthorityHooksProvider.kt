package app.slipnet.authority

import com.slipmesh.core.ConnectionObservation
import com.slipmesh.core.ObservationLayer
import com.slipmesh.core.ObservationOutcome

object PersonalVlessAuthorityHooksProvider {
    val hooks: PersonalVlessAuthorityHooks =
        PersonalPhase1VlessAuthorityHooks()
}

private class PersonalPhase1VlessAuthorityHooks :
    PersonalVlessAuthorityHooks {

    private var foundation:
        PersonalVlessAuthorityFoundation? = null

    @Synchronized
    override fun selectRoute(
        activeRoute: PersonalVlessRouteDescriptor,
        routes: List<PersonalVlessRouteDescriptor>,
    ) {
        foundation = PersonalVlessAuthorityFoundation(activeRoute, routes)
    }

    @Synchronized
    override fun clearRoute() {
        foundation = null
    }

    @Synchronized
    override fun observe(
        fact: PersonalVlessAuthorityFact,
        detail: String?,
        timestampEpochMs: Long,
    ) {
        val current = foundation ?: return
        val observation = when (fact) {
            PersonalVlessAuthorityFact.STRUCTURAL_SUCCESS ->
                ConnectionObservation(
                    layer = ObservationLayer.WEBSOCKET,
                    outcome = ObservationOutcome.SUCCESS,
                    responseCode = 101,
                    timestampEpochMs = timestampEpochMs,
                    detail = detail,
                    terminal = false,
                )

            PersonalVlessAuthorityFact.STRUCTURAL_FAILURE ->
                ConnectionObservation(
                    layer = ObservationLayer.WEBSOCKET,
                    outcome = ObservationOutcome.FAILURE,
                    timestampEpochMs = timestampEpochMs,
                    detail = detail,
                    terminal = false,
                )

            PersonalVlessAuthorityFact.TERMINAL_SUCCESS ->
                ConnectionObservation(
                    layer = ObservationLayer.TRANSPORT,
                    outcome = ObservationOutcome.SUCCESS,
                    timestampEpochMs = timestampEpochMs,
                    detail = detail,
                    terminal = true,
                )

            PersonalVlessAuthorityFact.TRANSPORT_FAILURE ->
                ConnectionObservation(
                    layer = ObservationLayer.TRANSPORT,
                    outcome = ObservationOutcome.FAILURE,
                    timestampEpochMs = timestampEpochMs,
                    detail = detail,
                    terminal = false,
                )

            PersonalVlessAuthorityFact.TRANSPORT_STALL ->
                ConnectionObservation(
                    layer = ObservationLayer.TRANSPORT,
                    outcome = ObservationOutcome.STALL,
                    timestampEpochMs = timestampEpochMs,
                    detail = detail,
                    terminal = false,
                )

            PersonalVlessAuthorityFact.NETWORK_CHANGED ->
                ConnectionObservation(
                    layer = ObservationLayer.NETWORK,
                    outcome = ObservationOutcome.CHANGED,
                    timestampEpochMs = timestampEpochMs,
                    detail = detail,
                    terminal = false,
                )
        }
        current.observe(observation)
    }

    override fun reconnectDisposition(
        origin: PersonalVlessReconnectOrigin,
    ): PersonalVlessReconnectDisposition =
        when (origin) {
            PersonalVlessReconnectOrigin.USER_EXPLICIT ->
                PersonalVlessReconnectDisposition.ALLOW_USER_SAME_PROFILE

            PersonalVlessReconnectOrigin.AUTONOMOUS ->
                PersonalVlessReconnectDisposition.BLOCK_FAIL_CLOSED
        }

    @Synchronized
    override fun qualifiedSwitchTargetDescriptorOrNull(): PersonalVlessRouteDescriptor? =
        foundation?.qualifiedSwitchTargetDescriptorOrNull()

    @Synchronized
    override fun snapshot(): PersonalVlessAuthorityHookSnapshot? {
        val current = foundation ?: return null
        val state = current.snapshot()
        return PersonalVlessAuthorityHookSnapshot(
            routeId = state.routeId,
            healthState = state.health.state.name,
            lastFailure = state.lastClassifiedFailure.name,
            authorityAction = state.authorityAction.name,
            qualifiedSwitchTarget = current.qualifiedSwitchTargetOrNull(),
        )
    }
}
