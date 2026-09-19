package app.slipnet.data.enrollment

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.slipnet.BuildConfig
import app.slipnet.util.DeviceIdUtil
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.URI
import java.net.URL
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.inject.Inject
import javax.inject.Singleton
import javax.net.ssl.HttpsURLConnection

data class EnrollmentDescriptor(
    val name: String,
    val endpoint: String,
    val backupEndpoint: String?,
    val token: String,
) {
    val endpoints: List<String>
        get() = listOfNotNull(endpoint, backupEndpoint).distinct()
}

@Singleton
class EnrollmentManager @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    companion object {
        const val SCHEME = "slipnet-enroll://"
        private const val KEY_ALIAS = "slipnet_enrollment_device_v1"
        private const val CLAIM_VERSION = "slipnet-enroll-challenge-v1"
        private const val MAX_RESPONSE_BYTES = 64 * 1024
    }

    fun isEnrollmentUri(input: String): Boolean =
        input.trim().startsWith(SCHEME, ignoreCase = true)

    fun describe(input: String): Result<EnrollmentDescriptor> = runCatching {
        parseDescriptor(input)
    }

    suspend fun redeem(input: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val descriptor = parseDescriptor(input)
            val deviceId = DeviceIdUtil.getScrambledDeviceId(context)
            require(deviceId.matches(Regex("[0-9a-f]{16}"))) { "Device identity is unavailable" }

            val keyPair = getOrCreateDeviceKeyPair()
            val publicKey = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            var lastError: Exception? = null

            for (endpoint in descriptor.endpoints) {
                try {
                    return@runCatching redeemWithEndpoint(
                        descriptor = descriptor,
                        endpoint = endpoint,
                        deviceId = deviceId,
                        keyPair = keyPair,
                        publicKey = publicKey,
                    )
                } catch (error: Exception) {
                    lastError = error
                }
            }

            throw lastError ?: IllegalStateException("No trusted enrollment endpoint is available")
        }
    }

    private fun redeemWithEndpoint(
        descriptor: EnrollmentDescriptor,
        endpoint: String,
        deviceId: String,
        keyPair: KeyPair,
        publicKey: String,
    ): String {
        val challengeEndpoint = endpoint.removeSuffix("/redeem") + "/challenge"
        val challengeJson = postJson(
            challengeEndpoint,
            JSONObject().apply {
                put("token", descriptor.token)
                put("device_id", deviceId)
                put("public_key", publicKey)
            },
        )
        val challenge = challengeJson.getString("challenge").trim()
        require(challenge.length in 32..256) { "Invalid enrollment challenge" }

        val claim = listOf(
            CLAIM_VERSION,
            descriptor.token,
            deviceId,
            challenge,
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(claim)
            sign()
        }

        val redeemPayload = JSONObject().apply {
            put("token", descriptor.token)
            put("device_id", deviceId)
            put("public_key", publicKey)
            put("challenge", challenge)
            put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
        }

        var lastRedeemError: Exception? = null
        val redeemEndpoints = listOf(endpoint) + descriptor.endpoints.filterNot { it == endpoint }
        for (redeemEndpoint in redeemEndpoints.distinct()) {
            try {
                val redeemJson = postJson(redeemEndpoint, redeemPayload)
                return redeemJson.getString("bundle").also { bundle ->
                    require(bundle.contains("slipnet://")) {
                        "Enrollment returned no profiles"
                    }
                }
            } catch (error: Exception) {
                lastRedeemError = error
            }
        }
        throw lastRedeemError ?: IllegalStateException("Enrollment redeem failed")
    }

    private fun postJson(endpoint: String, payload: JSONObject): JSONObject {
        require(isTrustedEnrollmentEndpoint(endpoint)) { "Untrusted enrollment endpoint" }
        val request = payload.toString().toByteArray(Charsets.UTF_8)
        val connection = (URL(endpoint).openConnection() as HttpsURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = 15_000
            instanceFollowRedirects = false
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "SlipNet-EA/${BuildConfig.VERSION_NAME}")
            setFixedLengthStreamingMode(request.size)
        }

        try {
            connection.outputStream.use { it.write(request) }
            val code = connection.responseCode
            val declaredLength = connection.contentLengthLong
            if (declaredLength > MAX_RESPONSE_BYTES) {
                error("Enrollment response is too large")
            }
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { reader ->
                val text = reader.readText()
                if (text.toByteArray(Charsets.UTF_8).size > MAX_RESPONSE_BYTES) {
                    error("Enrollment response is too large")
                }
                text
            }.orEmpty()
            val json = runCatching { JSONObject(body) }.getOrNull()
            if (code !in 200..299) {
                val message = json?.optString("error")?.takeIf { it.isNotBlank() }
                    ?: "Enrollment failed (HTTP $code)"
                error(message)
            }
            if (json?.optBoolean("success") != true) {
                error(json?.optString("error")?.takeIf { it.isNotBlank() } ?: "Enrollment failed")
            }
            return json
        } finally {
            connection.disconnect()
        }
    }

    private fun parseDescriptor(input: String): EnrollmentDescriptor {
        val trimmed = input.trim()
        require(trimmed.startsWith(SCHEME, ignoreCase = true)) { "Invalid enrollment format" }
        val encoded = trimmed.substring(SCHEME.length)
        require(encoded.isNotBlank() && encoded.length <= 4096) { "Invalid enrollment payload" }
        val padded = encoded + "=".repeat((4 - encoded.length % 4) % 4)
        val decoded = String(
            Base64.decode(padded, Base64.URL_SAFE or Base64.NO_WRAP),
            Charsets.UTF_8,
        )
        val json = JSONObject(decoded)
        require(json.optInt("v") == 1) { "Unsupported enrollment version" }
        val endpoint = json.getString("url").trim()
        val backupEndpoint = json.optString("backup_url").trim().takeIf { it.isNotEmpty() }
        val trustedSuffixes = BuildConfig.ENROLLMENT_TRUSTED_WORKER_SUFFIXES
            .split(",")
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() }
        require(
            BuildConfig.PERSONAL_BUILD &&
                (BuildConfig.ENROLLMENT_API_URL.isNotBlank() || trustedSuffixes.isNotEmpty())
        ) {
            "Enrollment is unavailable in this build"
        }
        require(isTrustedEnrollmentEndpoint(endpoint)) { "Untrusted enrollment endpoint" }
        if (backupEndpoint != null) {
            require(isTrustedEnrollmentEndpoint(backupEndpoint)) {
                "Untrusted backup enrollment endpoint"
            }
        }
        val token = json.getString("token").trim()
        require(token.length in 32..256) { "Invalid enrollment token" }
        val name = json.optString("name").trim().take(64)
        return EnrollmentDescriptor(
            name = name,
            endpoint = endpoint,
            backupEndpoint = backupEndpoint,
            token = token,
        )
    }

    private fun isTrustedEnrollmentEndpoint(endpoint: String): Boolean = runCatching {
        val uri = URI(endpoint)
        if (!uri.scheme.equals("https", ignoreCase = true)) return@runCatching false
        if (uri.userInfo != null || uri.query != null || uri.fragment != null) {
            return@runCatching false
        }
        if (uri.port != -1 && uri.port != 443) return@runCatching false
        if (uri.path != "/api/enrollment/redeem" && uri.path != "/api/enrollment/challenge") {
            return@runCatching false
        }

        val host = uri.host?.trim()?.lowercase() ?: return@runCatching false
        val pinned = BuildConfig.ENROLLMENT_API_URL.trim()
        if (endpoint == pinned || endpoint == pinned.removeSuffix("/redeem") + "/challenge") {
            return@runCatching true
        }

        BuildConfig.ENROLLMENT_TRUSTED_WORKER_SUFFIXES
            .split(",")
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() }
            .any { suffix -> host == suffix || host.endsWith(".$suffix") }
    }.getOrDefault(false)

    private fun getOrCreateDeviceKeyPair(): KeyPair {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existingPrivate = keyStore.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
        val existingPublic = keyStore.getCertificate(KEY_ALIAS)?.publicKey
        if (existingPrivate != null && existingPublic != null) {
            return KeyPair(existingPublic, existingPrivate)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN,
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        generator.initialize(spec)
        return generator.generateKeyPair()
    }
}
