package app.slipnet.util

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckerVersionTest {
    @Test
    fun sameNumericPersonalVersionIsNotTreatedAsOlderPrerelease() {
        assertFalse(UpdateChecker.isNewer("2.5.5", "2.5.5-personal"))
    }

    @Test
    fun newerNumericReleaseStillWinsAcrossEditionSuffix() {
        assertTrue(UpdateChecker.isNewer("2.5.6", "2.5.5-personal"))
    }

    @Test
    fun editionSuffixesAreNotReleaseMaturityMarkers() {
        assertFalse(UpdateChecker.isNewer("2.5.5", "2.5.5-lite"))
        assertFalse(UpdateChecker.isNewer("2.5.5", "2.5.5-dns-lab"))
    }

    @Test
    fun realPrereleaseOrderingStillWorks() {
        assertTrue(UpdateChecker.isNewer("2.6.0", "2.6.0-rc1"))
        assertFalse(UpdateChecker.isNewer("2.6.0-rc1", "2.6.0"))
    }
}
