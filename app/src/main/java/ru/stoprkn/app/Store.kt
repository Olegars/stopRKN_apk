package ru.stoprkn.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

data class ProxyEntry(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val user: String,
    val password: String
)

data class SocialRule(
    val id: String,
    var enabled: Boolean,
    var proxyId: String
)

data class CustomRule(
    val id: String,
    var enabled: Boolean,
    var name: String,
    var target: String,
    var ports: String,
    var action: String,
    var proxyId: String
)

data class AppConfig(
    val proxies: MutableList<ProxyEntry>,
    val social: MutableList<SocialRule>,
    val rules: MutableList<CustomRule>
) {
    fun proxy(id: String) = proxies.firstOrNull { it.id == id }
}

object Store {
    private const val FILE = "config.json"

    fun load(context: Context): AppConfig {
        val text = context.filesDir.resolve(FILE).takeIf { it.exists() }?.readText()
        val proxies = mutableListOf<ProxyEntry>()
        val social = mutableListOf<SocialRule>()
        val rules = mutableListOf<CustomRule>()
        if (!text.isNullOrBlank()) {
            val root = JSONObject(text)
            val proxyArray = root.optJSONArray("proxies") ?: JSONArray()
            for (i in 0 until proxyArray.length()) {
                val item = proxyArray.getJSONObject(i)
                proxies += ProxyEntry(
                    id = item.optString("id").ifBlank { UUID.randomUUID().toString() },
                    name = item.optString("name"),
                    host = item.optString("host"),
                    port = item.optInt("port"),
                    user = item.optString("user"),
                    password = item.optString("password")
                )
            }
            val socialArray = root.optJSONArray("social") ?: JSONArray()
            for (i in 0 until socialArray.length()) {
                val item = socialArray.getJSONObject(i)
                social += SocialRule(
                    id = item.optString("id"),
                    enabled = item.optBoolean("enabled"),
                    proxyId = item.optString("proxyId")
                )
            }
            val ruleArray = root.optJSONArray("rules") ?: JSONArray()
            for (i in 0 until ruleArray.length()) {
                val item = ruleArray.getJSONObject(i)
                val action = item.optString("action", "proxy")
                rules += CustomRule(
                    id = item.optString("id").ifBlank { UUID.randomUUID().toString() },
                    enabled = item.optBoolean("enabled"),
                    name = item.optString("name"),
                    target = item.optString("target"),
                    ports = item.optString("ports"),
                    action = if (action == "direct" || action == "block") action else "proxy",
                    proxyId = item.optString("proxyId")
                )
            }
        }
        for (net in SocialCatalog.all) {
            if (social.none { it.id == net.id }) {
                social += SocialRule(net.id, false, "")
            }
        }
        social.retainAll { rule -> SocialCatalog.byId(rule.id) != null }
        val order = SocialCatalog.all.map { it.id }
        social.sortBy { order.indexOf(it.id) }
        return AppConfig(proxies, social, rules)
    }

    fun save(context: Context, config: AppConfig) {
        val root = JSONObject()
        val proxies = JSONArray()
        for (proxy in config.proxies) {
            proxies.put(JSONObject()
                .put("id", proxy.id)
                .put("name", proxy.name)
                .put("host", proxy.host)
                .put("port", proxy.port)
                .put("user", proxy.user)
                .put("password", proxy.password)
                .put("type", "http"))
        }
        val social = JSONArray()
        for (rule in config.social) {
            social.put(JSONObject()
                .put("id", rule.id)
                .put("enabled", rule.enabled)
                .put("proxyId", rule.proxyId))
        }
        val rules = JSONArray()
        for (rule in config.rules) {
            rules.put(JSONObject()
                .put("id", rule.id)
                .put("enabled", rule.enabled)
                .put("name", rule.name)
                .put("target", rule.target)
                .put("ports", rule.ports)
                .put("action", rule.action)
                .put("proxyId", rule.proxyId))
        }
        root.put("proxies", proxies)
        root.put("social", social)
        root.put("rules", rules)
        context.filesDir.resolve(FILE).writeText(root.toString(2))
    }

    fun loadNets(context: Context): Map<String, List<Cidr>> {
        val map = HashMap<String, List<Cidr>>()
        for (net in SocialCatalog.all) {
            val file = net.netsFile ?: continue
            val text = context.assets.open(file).bufferedReader().readText()
            map[net.id] = text.split(',').mapNotNull { token ->
                val trimmed = token.trim()
                if (trimmed.isEmpty()) null else parseCidr(trimmed)
            }
        }
        return map
    }
}
