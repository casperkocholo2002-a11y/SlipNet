package app.slipnet.util

import app.slipnet.BuildConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class LogEntry(val id: Long, val raw: String, val level: Char)

/**
 * In-memory log buffer that wraps [android.util.Log].
 *
 * Every call forwards to the real Android logger AND appends to a ring buffer
 * that the debug-log UI can observe without spawning a `logcat` process
 * (which triggers Google Play Protect).
 *
 * Usage: replace `import android.util.Log` with
 *        `import app.slipnet.util.AppLog as Log`
 * — no other code changes needed.
 */
object AppLog {
    private const val MAX_LINES = 500
    private val nextId = AtomicLong(0)
    private val buffer = ArrayDeque<LogEntry>()

    /** When true, sensitive config details are redacted from the in-app log buffer. */
    @Volatile var redactSensitive = BuildConfig.PERSONAL_BUILD

    // Lazy snapshot — only rebuilt when the debug sheet is open (observerCount > 0).
    private val _lines = MutableStateFlow<List<LogEntry>>(emptyList())
    val lines: StateFlow<List<LogEntry>> = _lines.asStateFlow()

    // Track whether anyone is observing so we skip work when not needed.
    @Volatile var observerCount = 0
        private set

    // Dirty flag: set by append(), cleared by flush().
    // Avoids creating an ArrayList copy on every single log call — instead
    // the UI polls via flushIfDirty() on each collection (every frame).
    private val dirty = AtomicBoolean(false)

    // Privacy-safe operational telemetry. This channel intentionally accepts
    // only fixed-format event/key tokens plus numeric values, so callers cannot
    // accidentally place hostnames, SNI, UUIDs, credentials or ECH material in
    // the in-app ring buffer.
    private const val OPERATIONAL_TAG = "SlipNetOps"
    private val OP_EVENT_TOKEN = Regex("^[A-Z][A-Z0-9_]{0,47}$")
    private val OP_METRIC_KEY = Regex("^[a-z][a-z0-9_]{0,31}$")

    fun operational(event: String, vararg metrics: Pair<String, Long>): Int {
        if (!OP_EVENT_TOKEN.matches(event) || metrics.any { !OP_METRIC_KEY.matches(it.first) }) {
            return android.util.Log.w(OPERATIONAL_TAG, "OP_EVENT_REJECTED")
        }
        val message = buildString {
            append(event)
            metrics.forEach { (key, value) ->
                append(';').append(key).append('=').append(value)
            }
        }
        append('I', OPERATIONAL_TAG, message)
        return android.util.Log.i(OPERATIONAL_TAG, message)
    }

    private val dateFormat = object : ThreadLocal<SimpleDateFormat>() {
        override fun initialValue() = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
    }

    private fun append(level: Char, tag: String, msg: String) {
        val id = nextId.getAndIncrement()
        val entry = if (observerCount > 0) {
            val ts = dateFormat.get()!!.format(Date())
            LogEntry(id, "$ts $level/$tag: $msg", level)
        } else {
            // Lightweight entry — no timestamp formatting when nobody is watching
            LogEntry(id, "$level/$tag: $msg", level)
        }
        synchronized(buffer) {
            buffer.addLast(entry)
            while (buffer.size > MAX_LINES) buffer.removeFirst()
        }
        if (observerCount > 0) {
            dirty.set(true)
        }
    }

    /**
     * Copy the buffer to the StateFlow if anything changed since the last flush.
     * Called by the debug sheet on a periodic timer (~100ms) so we batch many
     * rapid log calls into a single ArrayList copy + recomposition.
     */
    fun flushIfDirty() {
        if (dirty.compareAndSet(true, false)) {
            synchronized(buffer) {
                _lines.value = ArrayList(buffer)
            }
        }
    }

    /** Call from debug sheet onStart/onStop to enable/disable snapshots. */
    fun addObserver() {
        observerCount++
        // Immediately snapshot current buffer for new observer
        synchronized(buffer) {
            _lines.value = ArrayList(buffer)
        }
    }

    fun removeObserver() {
        observerCount = (observerCount - 1).coerceAtLeast(0)
    }

    /** Tags whose messages contain sensitive config details (hosts, ports, credentials). */
    private val SENSITIVE_TAGS = setOf(
        "HevSocks5Tunnel",
        "SlipstreamSocksBridge",
        "DnsttSocksBridge",
        "SshTunnelBridge",
        "SlipNetVpnService",
        "KotlinTunnelManager",
        "NaiveSocksBridge",
        "TorSocksBridge",
        "SlipstreamBridge",
        "DnsttBridge",
        "NaiveBridge",
        "VpnRepositoryImpl",
        "VaydnsBridge",
        "VlessBridge",
        "DnsResolverProber",
        "DohBridge",
        "HttpProxyServer",
        "ProxyHttpConnect",
        "ProxyWebSocket",
        "TlsSocketFactory",
        "NaiveSocksProxy",
        "PayloadSocketFactory",
        "DomainRouter",
        "DnsDoHProxy"
    )

    /** Tag prefixes for dynamic tags (e.g. SshTunnel[default], Socks5Proxy[0]). */
    private val SENSITIVE_TAG_PREFIXES = arrayOf("SshTunnel[", "Socks5Proxy[", "SniFragment[")

    /**
     * Check if this log line should be redacted from the in-app buffer.
     * For locked profiles, all messages from sensitive tags are suppressed
     * (still forwarded to Android logcat which requires ADB access).
     */
    private fun shouldRedact(tag: String): Boolean {
        if (!redactSensitive) return false
        if (tag in SENSITIVE_TAGS) return true
        return SENSITIVE_TAG_PREFIXES.any { tag.startsWith(it) }
    }

    private fun logcatMessage(tag: String, msg: String): String =
        if (shouldRedact(tag)) "[redacted-personal]" else msg

    fun v(tag: String, msg: String): Int {
        if (!shouldRedact(tag)) append('V', tag, msg)
        return android.util.Log.v(tag, logcatMessage(tag, msg))
    }

    fun d(tag: String, msg: String): Int {
        if (!shouldRedact(tag)) append('D', tag, msg)
        return android.util.Log.d(tag, logcatMessage(tag, msg))
    }

    fun i(tag: String, msg: String): Int {
        if (!shouldRedact(tag)) append('I', tag, msg)
        return android.util.Log.i(tag, logcatMessage(tag, msg))
    }

    fun w(tag: String, msg: String): Int {
        if (!shouldRedact(tag)) append('W', tag, msg)
        return android.util.Log.w(tag, logcatMessage(tag, msg))
    }

    @JvmStatic
    fun w(tag: String, msg: String, tr: Throwable?): Int {
        val redact = shouldRedact(tag)
        if (!redact) append('W', tag, if (tr != null) "$msg\n${tr.stackTraceToString()}" else msg)
        return if (redact) android.util.Log.w(tag, "[redacted-personal]") else android.util.Log.w(tag, msg, tr)
    }

    fun e(tag: String, msg: String): Int {
        if (!shouldRedact(tag)) append('E', tag, msg)
        return android.util.Log.e(tag, logcatMessage(tag, msg))
    }

    @JvmStatic
    fun e(tag: String, msg: String, tr: Throwable?): Int {
        val redact = shouldRedact(tag)
        if (!redact) append('E', tag, if (tr != null) "$msg\n${tr.stackTraceToString()}" else msg)
        return if (redact) android.util.Log.e(tag, "[redacted-personal]") else android.util.Log.e(tag, msg, tr)
    }

    fun clear() {
        synchronized(buffer) {
            buffer.clear()
            _lines.value = emptyList()
        }
    }
}
