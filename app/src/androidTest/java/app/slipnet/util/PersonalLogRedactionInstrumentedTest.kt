package app.slipnet.util

import app.slipnet.BuildConfig
import org.junit.Assert.assertTrue
import org.junit.Test

class PersonalLogRedactionInstrumentedTest {
    @Test
    fun personalBuildRedactsSensitiveLogcatPayloads() {
        assertTrue(BuildConfig.PERSONAL_BUILD)
        AppLog.redactSensitive = true
        AppLog.i("VlessBridge", PRIVATE_CANARY)
        AppLog.i("SniFragment[test]", FRAGMENT_CANARY)
        android.util.Log.i(TAG, "redaction-call-complete")
    }

    private companion object {
        const val TAG = "SlipNetEALogRedaction"
        const val PRIVATE_CANARY = "SLIPNET_PRIVATE_DOMAIN_CANARY_4c92f1"
        const val FRAGMENT_CANARY = "SLIPNET_FRAGMENT_LOG_CANARY_2a81d0"
    }
}
