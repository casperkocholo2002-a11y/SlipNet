package app.slipnet.emergencydns

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AndroidNetworkScopeProvider @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    fun currentScopeId(): String {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = cm.activeNetwork ?: return ResolverNetworkScope.fingerprint(listOf("offline"))
        val caps = cm.getNetworkCapabilities(network)
        val link = cm.getLinkProperties(network)
        val transport = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "ethernet"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true -> "vpn"
            else -> "other"
        }
        val facts = buildList {
            add("transport:$transport")
            link?.interfaceName?.takeIf { it.isNotBlank() }?.let { add("iface:$it") }
            link?.dnsServers
                ?.map { it.hostAddress ?: "" }
                ?.filter { it.isNotBlank() }
                ?.sorted()
                ?.forEach { add("dns:$it") }
        }
        return ResolverNetworkScope.fingerprint(facts)
    }

    fun currentNetworkResolvers(): List<Pair<String, Int>> {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = cm.activeNetwork ?: return emptyList()
        return cm.getLinkProperties(network)?.dnsServers
            ?.mapNotNull { address -> address.hostAddress?.takeIf { it.isNotBlank() }?.let { it to 53 } }
            ?.distinct()
            ?: emptyList()
    }
}
