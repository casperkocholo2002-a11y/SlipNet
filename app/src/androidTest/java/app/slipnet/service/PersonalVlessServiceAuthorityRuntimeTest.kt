package app.slipnet.service

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import app.slipnet.authority.PersonalVlessAuthorityFact
import app.slipnet.authority.PersonalVlessAuthorityHookSnapshot
import app.slipnet.authority.PersonalVlessAuthorityHooksProvider
import app.slipnet.data.local.database.ProfileEntity
import app.slipnet.data.local.database.SlipNetDatabase
import app.slipnet.data.local.datastore.PreferencesDataStore
import app.slipnet.tunnel.VlessBridge
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
class PersonalVlessServiceAuthorityRuntimeTest {
    private val host = "websocket-template.signalnerve.workers.dev"
    private val hooks = PersonalVlessAuthorityHooksProvider.hooks

    private lateinit var context: Context
    private lateinit var database: SlipNetDatabase
    private lateinit var preferences: PreferencesDataStore
    private var profileId: Long = -1L

    private var oldProxyOnly = false
    private var oldAutoReconnect = false
    private var oldKillSwitch = false
    private var oldHttpProxy = false
    private var oldProxyPort = 1080
    private var oldProxyAddress = "127.0.0.1"
    private var oldServiceWasConnected = false
    private var oldServiceLastProfileId = -1L
    private var labServiceStarted = false

    @Before
    fun setUp() = runBlocking {
        context = ApplicationProvider.getApplicationContext()
        oldServiceWasConnected = servicePrefs().getBoolean("was_connected", false)
        oldServiceLastProfileId = servicePrefs().getLong("last_profile_id", -1L)
        assertFalse("Precondition: SlipNet service was already connected", oldServiceWasConnected)
        assertFalse("Precondition: VLESS bridge already running", VlessBridge.isRunning())
        database = Room.databaseBuilder(
            context,
            SlipNetDatabase::class.java,
            SlipNetDatabase.DATABASE_NAME,
        ).build()
        preferences = PreferencesDataStore(context)
        capturePreferences()
        configureLabPreferences()
        hooks.clearRoute()
        profileId = createLabProfile()
    }
    private suspend fun capturePreferences() {
        oldProxyOnly = preferences.proxyOnlyMode.first()
        oldAutoReconnect = preferences.autoReconnect.first()
        oldKillSwitch = preferences.killSwitch.first()
        oldHttpProxy = preferences.httpProxyEnabled.first()
        oldProxyPort = preferences.proxyListenPort.first()
        oldProxyAddress = preferences.proxyListenAddress.first()
    }

    private suspend fun configureLabPreferences() {
        val freePort = ServerSocket(0).use { it.localPort }
        preferences.setProxyOnlyMode(true)
        preferences.setAutoReconnect(true)
        preferences.setKillSwitch(true)
        preferences.setHttpProxyEnabled(false)
        preferences.setProxyListenAddress("127.0.0.1")
        preferences.setProxyListenPort(freePort)
    }

    private suspend fun createLabProfile(): Long {
        val now = System.currentTimeMillis()
        return database.profileDao().insertProfile(
            ProfileEntity(
                name = "SlipMesh R6 authority lab",
                domain = host,
                createdAt = now,
                updatedAt = now,
                tunnelType = "vless",
                vlessUuid = "00000000-0000-4000-8000-000000000000",
                vlessSecurity = "tls",
                vlessTransport = "ws",
                vlessWsPath = "/ws",
                cdnIp = host,
                cdnPort = 443,
                sniFragmentEnabled = false,
                vlessSni = host,
                wsHeaderObfuscation = false,
                wsPaddingEnabled = false,
            )
        )
    }

    private fun startLabService(action: String = SlipNetVpnService.ACTION_CONNECT) {
        val intent = Intent(context, SlipNetVpnService::class.java).apply {
            this.action = action
            if (action == SlipNetVpnService.ACTION_CONNECT) {
                putExtra(SlipNetVpnService.EXTRA_PROFILE_ID, profileId)
            }
        }
        ContextCompat.startForegroundService(context, intent)
        labServiceStarted = true
    }

    private fun servicePrefs() =
        context.getSharedPreferences("vpn_service_state", Context.MODE_PRIVATE)

    private suspend fun awaitHealthy(): PersonalVlessAuthorityHookSnapshot =
        withTimeout(20_000) {
            while (true) {
                val snapshot = hooks.snapshot()
                val connected = servicePrefs().getBoolean("was_connected", false)
                val sameProfile = servicePrefs().getLong("last_profile_id", -1L) == profileId
                if (
                    snapshot?.routeId == "profile:$profileId" &&
                    snapshot.healthState == "HEALTHY" &&
                    snapshot.qualifiedSwitchTarget == null &&
                    connected && sameProfile && VlessBridge.isRunning()
                ) {
                    return@withTimeout snapshot
                }
                delay(50)
            }
            error("unreachable")
        }

    private suspend fun awaitAuthorityReset() = withTimeout(12_000) {
        while (true) {
            if (hooks.snapshot() == null) return@withTimeout
            delay(25)
        }
    }

    private suspend fun awaitServiceDisconnected() = withTimeout(40_000) {
        while (true) {
            if (!servicePrefs().getBoolean("was_connected", false)) return@withTimeout
            delay(50)
        }
    }

    @Test
    fun successfulRequiredEchPathAndExplicitReconnectStaySameProfile() = runBlocking {
        startLabService()
        val first = awaitHealthy()
        assertEquals("profile:$profileId", first.routeId)
        assertEquals("HEALTHY", first.healthState)
        assertNull(first.qualifiedSwitchTarget)

        startLabService(SlipNetVpnService.ACTION_RECONNECT)
        awaitAuthorityReset()
        val second = awaitHealthy()
        assertEquals("profile:$profileId", second.routeId)
        assertEquals("HEALTHY", second.healthState)
        assertEquals(profileId, servicePrefs().getLong("last_profile_id", -1L))
    }

    @Test
    fun controlledAutonomousFailureIsObservedThenFailsClosedWithoutRetry() = runBlocking {
        startLabService()
        awaitHealthy()

        val capturedFailure = AtomicReference<PersonalVlessAuthorityHookSnapshot?>(null)
        val monitor: Job = launch(Dispatchers.Default) {
            while (true) {
                val snapshot = hooks.snapshot()
                if (snapshot != null && snapshot.lastFailure == "TRANSPORT_FAILURE") {
                    capturedFailure.compareAndSet(null, snapshot)
                }
                delay(10)
            }
        }

        VlessBridge.stop()
        awaitServiceDisconnected()
        delay(6_000)
        monitor.cancel()

        val failure = capturedFailure.get()
        assertNotNull("Phase-1 transport failure was not observed", failure)
        assertNull(failure!!.qualifiedSwitchTarget)
        assertFalse("Legacy reconnect restarted VLESS", VlessBridge.isRunning())
        assertFalse(servicePrefs().getBoolean("was_connected", false))
        assertNull("Authority route should clear after cleanup", hooks.snapshot())
    }
    @Test
    fun networkChangeIsAuthorityFactWithoutReconnectOwnership() = runBlocking {
        startLabService()
        awaitHealthy()

        hooks.observe(
            PersonalVlessAuthorityFact.NETWORK_CHANGED,
            "instrumented handoff",
            System.currentTimeMillis(),
        )
        val snapshot = hooks.snapshot()
        assertNotNull(snapshot)
        assertEquals("NETWORK_CHANGE", snapshot!!.lastFailure)
        assertEquals("UNKNOWN", snapshot.healthState)
        assertNull(snapshot.qualifiedSwitchTarget)

        delay(2_000)
        assertTrue("Network fact restarted/stopped VLESS unexpectedly", VlessBridge.isRunning())
        assertTrue(servicePrefs().getBoolean("was_connected", false))
        assertEquals(profileId, servicePrefs().getLong("last_profile_id", -1L))
    }

    @After
    fun tearDown() = runBlocking {
        if (labServiceStarted && this@PersonalVlessServiceAuthorityRuntimeTest::context.isInitialized) {
            val stop = Intent(context, SlipNetVpnService::class.java).apply {
                action = SlipNetVpnService.ACTION_DISCONNECT
            }
            runCatching { context.startService(stop) }
            delay(750)
        }
        VlessBridge.stop()
        hooks.clearRoute()

        if (this@PersonalVlessServiceAuthorityRuntimeTest::database.isInitialized) {
            if (profileId != -1L) {
                runCatching { database.profileDao().deleteProfile(profileId) }
            }
            database.close()
        }

        if (this@PersonalVlessServiceAuthorityRuntimeTest::preferences.isInitialized) {
            preferences.setProxyOnlyMode(oldProxyOnly)
            preferences.setAutoReconnect(oldAutoReconnect)
            preferences.setKillSwitch(oldKillSwitch)
            preferences.setHttpProxyEnabled(oldHttpProxy)
            preferences.setProxyListenPort(oldProxyPort)
            preferences.setProxyListenAddress(oldProxyAddress)
        }

        if (this@PersonalVlessServiceAuthorityRuntimeTest::context.isInitialized) {
            servicePrefs().edit()
                .putBoolean("was_connected", oldServiceWasConnected)
                .putLong("last_profile_id", oldServiceLastProfileId)
                .commit()
        }
    }
}
