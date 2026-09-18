package app.slipnet.data

import app.slipnet.data.mapper.ProfileMapper
import app.slipnet.domain.model.ServerProfile
import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileFailureDomainMetadataTest {
    private val mapper = ProfileMapper(Gson())

    @Test fun defaultsRemainBlankAndFailClosed() {
        val profile = ServerProfile(name = "route")
        assertTrue(profile.vlessFailureProviderId.isBlank())
        assertTrue(profile.vlessFailureAccountId.isBlank())
        assertTrue(profile.vlessFailureHostname.isBlank())
    }

    @Test fun mapperRoundTripPreservesExplicitFailureDomainMetadata() {
        val original = ServerProfile(
            id = 7, name = "route",
            vlessFailureProviderId = "provider-a",
            vlessFailureAccountId = "account-a",
            vlessFailureHostname = "front-a.example",
        )
        val roundTrip = mapper.toDomain(mapper.toEntity(original))
        assertEquals(original.vlessFailureProviderId, roundTrip.vlessFailureProviderId)
        assertEquals(original.vlessFailureAccountId, roundTrip.vlessFailureAccountId)
        assertEquals(original.vlessFailureHostname, roundTrip.vlessFailureHostname)
    }
}
