package app.slipnet.emergencydns

import app.slipnet.domain.model.ResolverScanResult
import app.slipnet.domain.model.ResolverStatus

fun ResolverScanResult.toEmergencyObservation(
    source: ResolverCandidateSource,
): ResolverObservation = ResolverObservation(
    candidate = ResolverCandidate(host = host, port = port, source = source),
    prismVerified = prismVerified,
    e2eSuccess = e2eTestResult?.success == true,
    tunnelRealism = tunnelTestResult?.tunnelRealism == true,
    nxdomainCorrect = tunnelTestResult?.nxdomainCorrect == true,
    ednsMaxPayload = tunnelTestResult?.ednsMaxPayload ?: 0,
    udpWorking = udpWorking,
    tcpWorking = tcpWorking,
    responseTimeMs = responseTimeMs,
)

fun ResolverScanResult.isEmergencyDiscoverySuccess(): Boolean =
    status == ResolverStatus.WORKING && prismVerified == true && e2eTestResult?.success == true
