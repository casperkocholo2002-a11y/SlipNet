package app.slipnet.tunnel

import android.os.Build

object EchBackends {
    fun current(): EchTlsBackend =
        if (Build.VERSION.SDK_INT >= 37) PlatformEchTlsBackend()
        else ConscryptEchTlsBackend()
}
