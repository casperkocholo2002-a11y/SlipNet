package app.slipnet.data.enrollment

import app.slipnet.domain.model.ServerProfile
import app.slipnet.domain.model.TunnelType

data class ManagedEnrollmentPair(
    val primary: ServerProfile,
    val backup: ServerProfile,
)

object EnrollmentPairValidator {
    fun validate(
        profiles: List<ServerProfile>,
        localDeviceId: String,
    ): Result<ManagedEnrollmentPair> = runCatching {
        require(localDeviceId.isNotBlank()) {
            "Device identity is unavailable"
        }
        require(profiles.size == 2) {
            "Enrollment must contain exactly one Primary and one Backup profile"
        }

        val primary = profiles.singleOrNull { it.name.endsWith("-Primary") }
            ?: error("Enrollment Primary profile is missing or duplicated")
        val backup = profiles.singleOrNull { it.name.endsWith("-Backup") }
            ?: error("Enrollment Backup profile is missing or duplicated")

        val primaryBase = primary.name.removeSuffix("-Primary")
        val backupBase = backup.name.removeSuffix("-Backup")
        require(primaryBase.isNotBlank() && primaryBase == backupBase) {
            "Enrollment Primary/Backup identities do not match"
        }

        val pair = listOf(primary, backup)
        require(pair.all { it.tunnelType == TunnelType.VLESS }) {
            "Enrollment contains a non-VLESS profile"
        }
        require(pair.all { it.isLocked && !it.allowSharing }) {
            "Enrollment profiles must be locked and non-shareable"
        }
        require(pair.all {
            it.boundDeviceId.isNotBlank() &&
                it.boundDeviceId == localDeviceId
        }) {
            "Enrollment profiles are not bound to this device"
        }

        require(primary.vlessUuid.isNotBlank()) {
            "Enrollment VLESS credential is missing"
        }
        require(primary.vlessUuid == backup.vlessUuid) {
            "Enrollment Primary/Backup credentials do not match"
        }

        require(primary.domain.isNotBlank() && backup.domain.isNotBlank()) {
            "Enrollment route hostname is missing"
        }
        require(primary.domain != backup.domain) {
            "Enrollment Primary/Backup routes are not independent"
        }

        require(pair.all {
            it.vlessFailureProviderId.isNotBlank() &&
                it.vlessFailureAccountId.isNotBlank() &&
                it.vlessFailureHostname.isNotBlank()
        }) {
            "Enrollment failure-domain metadata is incomplete"
        }
        require(primary.vlessFailureAccountId != backup.vlessFailureAccountId) {
            "Enrollment Primary/Backup failure accounts are not independent"
        }
        require(pair.all { it.vlessFailureHostname == it.domain }) {
            "Enrollment failure hostname does not match its route"
        }

        require(pair.all {
            it.vlessEchConfigSeed.isNotBlank() &&
                it.vlessEchConfigUpdatedAt > 0L
        }) {
            "Enrollment ECH bootstrap material is missing"
        }

        ManagedEnrollmentPair(primary = primary, backup = backup)
    }
}
