package ru.stoprkn.app

data class Cidr(val base: Int, val bits: Int) {
    fun contains(ip: Int): Boolean {
        val mask = if (bits == 0) 0 else -1 shl (32 - bits)
        return (ip and mask) == base
    }
}

fun ipv4(text: String): Int? {
    val parts = text.split('.')
    if (parts.size != 4) return null
    var value = 0
    for (part in parts) {
        val octet = part.toIntOrNull() ?: return null
        if (octet !in 0..255) return null
        value = (value shl 8) or octet
    }
    return value
}

fun parseCidr(text: String): Cidr? {
    val parts = text.trim().split('/')
    if (parts.size != 2) return null
    val ip = ipv4(parts[0]) ?: return null
    val bits = parts[1].toIntOrNull() ?: return null
    if (bits !in 0..32) return null
    val mask = if (bits == 0) 0 else -1 shl (32 - bits)
    return Cidr(ip and mask, bits)
}

fun hostMatches(host: String, domain: String): Boolean {
    val name = host.trim().trim('.').lowercase()
    val root = domain.lowercase()
    return name == root || name.endsWith(".$root")
}

data class SocialNet(
    val id: String,
    val title: String,
    val domains: List<String>,
    val netsFile: String?
)

object SocialCatalog {
    val all = listOf(
        SocialNet("youtube", "YouTube", listOf(
            "youtube.com", "youtu.be", "youtube-nocookie.com", "youtubekids.com",
            "googlevideo.com", "ytimg.com", "ggpht.com", "gstatic.com",
            "googleusercontent.com", "googleapis.com"
        ), "nets/google.txt"),
        SocialNet("instagram", "Instagram", listOf(
            "instagram.com", "cdninstagram.com", "instagram.net", "ig.me", "igsonar.com"
        ), "nets/meta.txt"),
        SocialNet("facebook", "Facebook", listOf(
            "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "messenger.com", "facebook.net"
        ), null),
        SocialNet("tiktok", "TikTok", listOf(
            "tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com",
            "musical.ly", "byteoversea.com", "ibyteimg.com"
        ), null),
        SocialNet("discord", "Discord", listOf(
            "discord.com", "discordapp.com", "discord.gg", "discordapp.net",
            "discord.media", "discordcdn.com"
        ), null),
        SocialNet("whatsapp", "WhatsApp", listOf(
            "whatsapp.com", "whatsapp.net", "wa.me"
        ), null),
        SocialNet("x", "X (Twitter)", listOf(
            "x.com", "twitter.com", "twimg.com", "t.co", "pscp.tv"
        ), null),
        SocialNet("telegram", "Telegram", listOf(
            "telegram.org", "t.me", "telegram.me", "telesco.pe",
            "cdn-telegram.org", "web.telegram.org"
        ), "nets/telegram.txt"),
        SocialNet("crypto", "Крипта", listOf(
            "binance.com", "bnbstatic.com", "bybit.com", "okx.com", "htx.com", "huobi.com",
            "kucoin.com", "gate.io", "gate.com", "bitget.com", "mexc.com", "bingx.com",
            "whitebit.com", "bitfinex.com", "kraken.com", "coinbase.com", "poloniex.com",
            "phemex.com", "bitmart.com", "lbank.com", "coinex.com", "bitstamp.net",
            "tradingview.com", "coingecko.com", "coinmarketcap.com", "metamask.io",
            "trustwallet.com", "infura.io", "alchemy.com", "ankr.com", "publicnode.com",
            "drpc.org", "1rpc.io", "nodereal.io", "getblock.io", "quicknode.com",
            "tonapi.io", "toncenter.com", "tonkeeper.com", "ton.org", "phantom.app",
            "exodus.com", "exodus.io", "tronlink.org", "trongrid.io", "tronscan.org",
            "safepal.com", "safepal.io", "walletconnect.com", "walletconnect.org", "reown.com",
            "myetherwallet.com", "atomicwallet.io", "rabby.io"
        ), null)
    )

    fun byId(id: String) = all.firstOrNull { it.id == id }
}

enum class RouteKind { PROXY, DIRECT, BLOCK }

data class RouteDecision(val kind: RouteKind, val proxy: ProxyEntry?, val summary: String)

fun targetTokens(target: String) = target.split(',', ';', '\n')
    .map { it.trim() }
    .filter { it.isNotEmpty() }

fun targetTokenOk(token: String): Boolean {
    if (token == "*") return true
    if ('/' in token) return parseCidr(token) != null
    if (ipv4(token) != null) return true
    val domain = token.removePrefix("*.")
    if (domain.isEmpty() || domain.any { it.isWhitespace() || it == '/' || it == '*' }) return false
    return domain.all { it.isLetterOrDigit() || it == '.' || it == '-' }
}

fun portsSpecValid(spec: String): Boolean {
    val text = spec.trim()
    if (text.isEmpty()) return true
    for (part in text.split(',')) {
        val token = part.trim()
        if (token.isEmpty()) return false
        if ('-' in token) {
            val ends = token.split('-')
            if (ends.size != 2) return false
            val start = ends[0].trim().toIntOrNull() ?: return false
            val end = ends[1].trim().toIntOrNull() ?: return false
            if (start !in 1..65535 || end !in 1..65535 || start > end) return false
        } else {
            val port = token.toIntOrNull() ?: return false
            if (port !in 1..65535) return false
        }
    }
    return true
}

fun portsMatch(spec: String, port: Int): Boolean {
    if (spec.isBlank()) return true
    if (!portsSpecValid(spec)) return false
    for (part in spec.split(',')) {
        val token = part.trim()
        if ('-' in token) {
            val ends = token.split('-')
            val start = ends[0].trim().toInt()
            val end = ends[1].trim().toInt()
            if (port in start..end) return true
        } else if (token.toInt() == port) {
            return true
        }
    }
    return false
}

fun targetMatches(target: String, host: String?, ip: Int): Boolean {
    val tokens = targetTokens(target)
    if (tokens.isEmpty()) return true
    for (token in tokens) {
        if (token == "*") return true
        if ('/' in token) {
            val cidr = parseCidr(token)
            if (cidr != null && cidr.contains(ip)) return true
            continue
        }
        val asIp = ipv4(token)
        if (asIp != null) {
            if (asIp == ip) return true
            continue
        }
        if (host != null && hostMatches(host, token.removePrefix("*."))) return true
    }
    return false
}

fun decideRoute(host: String?, ip: Int, port: Int, config: AppConfig, nets: Map<String, List<Cidr>>): RouteDecision {
    for (rule in config.social) {
        if (!rule.enabled) continue
        val net = SocialCatalog.byId(rule.id) ?: continue
        if (host != null && net.domains.any { hostMatches(host, it) }) {
            val proxy = config.proxy(rule.proxyId) ?: continue
            return RouteDecision(RouteKind.PROXY, proxy, net.title)
        }
    }
    for (rule in config.social) {
        if (!rule.enabled) continue
        val net = SocialCatalog.byId(rule.id) ?: continue
        val cidrs = nets[net.id].orEmpty()
        if (cidrs.any { it.contains(ip) }) {
            val proxy = config.proxy(rule.proxyId) ?: continue
            return RouteDecision(RouteKind.PROXY, proxy, net.title)
        }
    }
    for (rule in config.rules) {
        if (!rule.enabled) continue
        if (!portsMatch(rule.ports, port)) continue
        if (!targetMatches(rule.target, host, ip)) continue
        val title = rule.name.ifBlank { "правило" }
        when (rule.action) {
            "direct" -> return RouteDecision(RouteKind.DIRECT, null, title)
            "block" -> return RouteDecision(RouteKind.BLOCK, null, title)
            else -> {
                val proxy = config.proxy(rule.proxyId) ?: continue
                return RouteDecision(RouteKind.PROXY, proxy, title)
            }
        }
    }
    return RouteDecision(RouteKind.DIRECT, null, "напрямую")
}
