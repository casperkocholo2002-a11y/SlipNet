package app.slipnet.data.enrollment

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentDescriptorProtocolTest {
    private fun descriptor(version: Int) = EnrollmentDescriptor(
        version = version,
        name = "alice",
        endpoint = "https://primary.workers.dev/api/enrollment/redeem",
        backupEndpoint = "https://backup.workers.dev/api/enrollment/redeem",
        token = "x".repeat(43),
    )

    @Test
    fun legacyV1DoesNotRequireCompletion() {
        assertFalse(descriptor(1).requiresCompletion)
    }

    @Test
    fun v2RequiresCompletion() {
        assertTrue(descriptor(2).requiresCompletion)
    }
}
