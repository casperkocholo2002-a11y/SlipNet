package app.slipnet.tunnel

import org.junit.Assert.assertTrue
import org.junit.Test

class EchPolicyTest {
    @Test fun requiredWithoutConfigFailsClosed() {
        assertTrue(EchPolicy.initial(EchMode.REQUIRED, EchCapability.CONSCRYPT, false) is EchDecision.FailClosed)
    }

    @Test fun preferredWithoutConfigUsesStandardTls() {
        assertTrue(EchPolicy.initial(EchMode.PREFERRED, EchCapability.CONSCRYPT, false) is EchDecision.UseStandardTls)
    }

    @Test fun requiredWithConfigStartsEch() {
        assertTrue(EchPolicy.initial(EchMode.REQUIRED, EchCapability.PLATFORM, true) is EchDecision.StartEch)
    }

    @Test fun disabledAlwaysUsesStandardTls() {
        assertTrue(EchPolicy.initial(EchMode.DISABLED, EchCapability.UNAVAILABLE, true) is EchDecision.UseStandardTls)
    }
}
