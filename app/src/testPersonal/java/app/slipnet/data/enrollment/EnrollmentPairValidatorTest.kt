package app.slipnet.data.enrollment

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentPairValidatorTest {
    private val deviceId = "0123456789abcdef"
    private val uuid = "00000000-0000-0000-0000-000000000001"

    private fun profile(
        route: String,
        domain: String,
        account: String,
        boundDeviceId: String = deviceId,
        vlessUuid: String = uuid,
        isLocked: Boolean = true,
        allowSharing: Boolean = false,
        echSeed: String = "AQIDBA==",
        echUpdatedAt: Long = 123456789L,
    ) = ServerProfile(
        name = "CF-alice-$route",
        domain = domain,
        tunnelType = TunnelType.VLESS,
        isLocked = isLocked,
        allowSharing = allowSharing,
        boundDeviceId = boundDeviceId,
        vlessUuid = vlessUuid,
        vlessSecurity = "tls",
        vlessTransport = "ws",
        vlessFailureProviderId = "cloudflare-workers",
        vlessFailureAccountId = account,
        vlessFailureHostname = domain,
        vlessEchConfigSeed = echSeed,
        vlessEchConfigUpdatedAt = echUpdatedAt,
    )

    private fun validPair() = listOf(
        profile(
            route = "Primary",
            domain = "primary.example.workers.dev",
            account = "primary-account",
        ),
        profile(
            route = "Backup",
            domain = "backup.example.workers.dev",
            account = "backup-account",
        ),
    )

    @Test
    fun acceptsExactlyOneIndependentPrimaryBackupPair() {
        val result = EnrollmentPairValidator.validate(
            validPair().reversed(),
            deviceId,
        )

        assertTrue(result.isSuccess)
        val pair = result.getOrThrow()
        assertEquals("CF-alice-Primary", pair.primary.name)
        assertEquals("CF-alice-Backup", pair.backup.name)
    }

    @Test
    fun rejectsSingleProfileBundle() {
        val result = EnrollmentPairValidator.validate(
            listOf(validPair().first()),
            deviceId,
        )
        assertTrue(result.isFailure)
    }

    @Test
    fun rejectsCredentialMismatch() {
        val profiles = validPair().toMutableList()
        profiles[1] = profiles[1].copy(
            vlessUuid = "00000000-0000-0000-0000-000000000002"
        )
        assertTrue(
            EnrollmentPairValidator.validate(profiles, deviceId).isFailure
        )
    }

    @Test
    fun rejectsDifferentDeviceBinding() {
        val profiles = validPair().map {
            it.copy(boundDeviceId = "fedcba9876543210")
        }
        assertTrue(
            EnrollmentPairValidator.validate(profiles, deviceId).isFailure
        )
    }

    @Test
    fun rejectsSharedRouteOrFailureAccount() {
        val sameRoute = validPair().let { profiles ->
            listOf(
                profiles[0],
                profiles[1].copy(
                    domain = profiles[0].domain,
                    vlessFailureHostname = profiles[0].domain,
                ),
            )
        }
        assertTrue(
            EnrollmentPairValidator.validate(sameRoute, deviceId).isFailure
        )

        val sameAccount = validPair().let { profiles ->
            listOf(
                profiles[0],
                profiles[1].copy(
                    vlessFailureAccountId = profiles[0].vlessFailureAccountId
                ),
            )
        }
        assertTrue(
            EnrollmentPairValidator.validate(sameAccount, deviceId).isFailure
        )
    }

    @Test
    fun rejectsMissingEchBootstrap() {
        val profiles = validPair().toMutableList()
        profiles[1] = profiles[1].copy(vlessEchConfigSeed = "")
        assertTrue(
            EnrollmentPairValidator.validate(profiles, deviceId).isFailure
        )
    }

    @Test
    fun rejectsUnlockedOrShareableManagedProfile() {
        val unlocked = validPair().toMutableList()
        unlocked[0] = unlocked[0].copy(isLocked = false)
        assertTrue(
            EnrollmentPairValidator.validate(unlocked, deviceId).isFailure
        )

        val shareable = validPair().toMutableList()
        shareable[1] = shareable[1].copy(allowSharing = true)
        assertTrue(
            EnrollmentPairValidator.validate(shareable, deviceId).isFailure
        )
    }
}
