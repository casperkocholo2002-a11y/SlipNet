package app.slipnet.authority

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class PersonalVlessServiceAuthorityStaticGuardTest {
    private fun serviceSource(): String {
        val candidates = listOf(
            File("src/main/java/app/slipnet/service/SlipNetVpnService.kt"),
            File("app/src/main/java/app/slipnet/service/SlipNetVpnService.kt"),
        )
        val file = candidates.firstOrNull { it.isFile }
            ?: error("SlipNetVpnService.kt not found from ${System.getProperty("user.dir")}")
        return file.readText()
    }

    @Test
    fun personalVlessAutonomousRecoveryIsBypassed() {
        val source = serviceSource()
        assertTrue(source.contains("if (failClosedPersonalVless(reason, personalFact)) return"))
        assertTrue(source.contains("Personal VLESS authority blocks autonomous service-restart reconnect"))
        assertTrue(source.contains("Personal VLESS authority blocks task-removed reconnect redelivery"))
    }

    @Test
    fun explicitReconnectRemainsSeparateUserCommand() {
        val source = serviceSource()
        assertTrue(source.contains("if (!reconnectPersonalVlessFromUser())"))
        assertTrue(source.contains("PersonalVlessReconnectOrigin.USER_EXPLICIT"))
    }

    @Test
    fun networkChangesAreFactsNotPersonalReconnectPolicy() {
        val source = serviceSource()
        assertTrue(source.contains("observePersonalVless(PersonalVlessAuthorityFact.NETWORK_CHANGED, reason)"))
        assertTrue(source.contains("if (isPersonalVlessAuthorityPath())"))
    }


    @Test
    fun r3QualifiedTargetUsesOneGuardedAuthoritySwitchPath() {
        val source = serviceSource()
        assertTrue(source.contains("PersonalVlessSwitchGuard.decide"))
        assertTrue(source.contains("qualifiedSwitchTargetDescriptorOrNull"))
        assertTrue(source.contains("connect(targetProfile.id, authoritySwitch = true)"))
        assertTrue(source.contains("personalVlessAttemptedProfileIds += sourceProfileId"))
        assertTrue(source.contains("vpnRepository.setAutoReconnect(false)"))
    }

    @Test
    fun r3AuthoritySwitchDoesNotUseLegacyReconnectEntryPoints() {
        val source = serviceSource()
        val guardedBlock = source.substring(
            source.indexOf("private suspend fun failClosedPersonalVless"),
            source.indexOf("private fun reconnectPersonalVlessFromUser"),
        )
        assertTrue(!guardedBlock.contains("handleNetworkChange("))
        assertTrue(!guardedBlock.contains("enterAutoReconnectMode("))
        assertTrue(!guardedBlock.contains("enterKillSwitchMode("))
    }

    @Test
    fun r3FirstFailureUsesAuthorityOwnedProbeNotLegacyReconnect() {
        val source = serviceSource()
        assertTrue(source.contains("authoritySnapshot?.authorityAction == \"PROBE_CURRENT\""))
        assertTrue(source.contains("cleanupConnection(preservePersonalVlessAuthority = true)"))
        assertTrue(source.contains("preservePersonalAuthority = true"))
        assertTrue(source.contains("personalVlessProbeRetriedProfileIds += sourceProfileId"))
    }

    @Test
    fun nonTlsPersonalVlessDoesNotRequireEch() {
        val source = serviceSource()
        assertTrue(source.contains("profile.vlessSecurity.equals(\"none\", ignoreCase = true)"))
    }


    @Test
    fun personalEchBootstrapIsStoredSeedOnlyBeforeTunnel() {
        val source = serviceSource()
        val start = source.indexOf("private suspend fun resolvePersonalEch")
        val end = source.indexOf("private suspend fun connectVless", start)
        val block = source.substring(start, end)
        assertTrue(block.contains("EchConfigResolver.decodeStoredSeed(profile.vlessEchConfigSeed)"))
        assertTrue(block.contains("ECH_REQUIRED stored config unavailable"))
        assertTrue(!block.contains("EchConfigResolver.resolve("))
        assertTrue(!block.contains("DnsResolver"))
        assertTrue(!block.contains("resolveHost("))
    }

    @Test
    fun personalVlessNetworkChangeNeverEntersGenericDnsReconnectPath() {
        val source = serviceSource()
        val start = source.indexOf("private fun handleNetworkChange")
        val guard = source.substring(start, source.indexOf("serviceScope.launch", start))
        assertTrue(guard.contains("if (isPersonalVlessAuthorityPath())"))
        assertTrue(guard.contains("observePersonalVless(PersonalVlessAuthorityFact.NETWORK_CHANGED, reason)"))
        assertTrue(guard.contains("return"))
    }

    @Test
    fun authenticatedEchRenewalIsWiredIntoBothVlessRuntimePathsOnly() {
        val source = serviceSource()
        val callback = "onAuthenticatedEchConfigAccepted = authenticatedEchSeedPersistence(profile.id)"
        assertTrue(source.windowed(callback.length).count { it == callback } == 2)
        val start = source.indexOf("private fun authenticatedEchSeedPersistence")
        val end = source.indexOf("private suspend fun connectVless", start)
        val block = source.substring(start, end)
        assertTrue(block.contains("persistAuthenticatedVlessEchSeed(profileId, configCopy)"))
        assertTrue(!block.contains("EchConfigResolver.resolve("))
        assertTrue(!block.contains("handleNetworkChange("))
        assertTrue(!block.contains("enterAutoReconnectMode("))
        assertTrue(!block.contains("qualifiedSwitchTarget"))
    }



    @Test
    fun managedVlessFailoverIsScopedToSameSubscriptionIdentity() {
        val source = serviceSource()
        assertTrue(source.contains("managedIdentity = activeProfile?.lockPasswordHash.orEmpty()"))
        assertTrue(source.contains("candidateProfile?.isLocked == true"))
        assertTrue(source.contains("candidateProfile.lockPasswordHash == managedIdentity"))
    }

    @Test
    fun cleanupClearsAuthorityRoute() {
        val source = serviceSource()
        val marker = "PersonalVlessAuthorityHooksProvider.hooks.clearRoute()"
        assertTrue(source.windowed(marker.length).count { it == marker } >= 2)
    }
}
