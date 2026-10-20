package ru.stoprkn.app

import android.app.AlarmManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.SystemClock
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.random.Random

class StopVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var output: FileOutputStream? = null
    private val flows = ConcurrentHashMap<String, Flow>()
    private val udpNoted = LinkedHashSet<String>()
    private val proxyIps = HashSet<Long>()
    private val detachWarned = AtomicBoolean(false)
    private val workers = Executors.newCachedThreadPool()
    private val outLock = Any()
    private var ipId = 1
    private lateinit var nets: Map<String, List<Cidr>>

    override fun onCreate() {
        super.onCreate()
        ConnLog.attach(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        instance = this
        ConnLog.attach(this)
        if (intent?.action == ACTION_TEST) {
            runProxyTest(intent, startId)
            return if (running.get()) START_STICKY else START_NOT_STICKY
        }
        if (intent?.action == ACTION_STOP) {
            KeepAlive.set(this, false)
            shutdown()
            return START_NOT_STICKY
        }
        if (intent == null && !KeepAlive.wanted(this)) {
            showForeground()
            shutdown()
            return START_NOT_STICKY
        }
        KeepAlive.set(this, true)
        if (running.get()) return START_STICKY
        nets = Store.loadNets(this)
        rememberProxies(Store.load(this))
        ConnLog.clear()
        showForeground()
        val fd = try {
            establishTun()
        } catch (error: Exception) {
            lastError = error.message ?: "туннель не создан"
            ConnLog.add("Маршрутизация не включилась: $lastError")
            VpnState.setError(this, lastError)
            KeepAlive.set(this, false)
            shutdown()
            return START_NOT_STICKY
        }
        if (fd == null) {
            lastError = "система не разрешила VPN"
            ConnLog.add("Маршрутизация не включилась: $lastError")
            VpnState.setError(this, lastError)
            KeepAlive.set(this, false)
            shutdown()
            return START_NOT_STICKY
        }
        lastError = null
        VpnState.setError(this, null)
        tun = fd
        output = FileOutputStream(fd.fileDescriptor)
        running.set(true)
        active = true
        VpnState.beat(this)
        startBeat()
        Thread({ pump(FileInputStream(fd.fileDescriptor)) }, "stopRKN-tun").start()
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        if (KeepAlive.wanted(this)) scheduleRestart()
        super.onTaskRemoved(rootIntent)
    }

    override fun onRevoke() {
        shutdown()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun establishTun(): ParcelFileDescriptor? {
        return try {
            openTun(excludeProxies = Build.VERSION.SDK_INT >= 33)
        } catch (error: Exception) {
            ConnLog.add("исключение прокси не принято: ${error.message ?: "ошибка"}")
            openTun(excludeProxies = false)
        }
    }

    private fun openTun(excludeProxies: Boolean): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("stopRKN")
            .setMtu(1280)
            .addAddress("10.10.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setBlocking(true)
        if (excludeProxies) {
            val holes = synchronized(proxyIps) { proxyIps.toList() }
            for (ip in holes) {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(ipText(ip)), 32))
            }
            if (holes.isNotEmpty()) {
                ConnLog.add("прокси вне туннеля: ${holes.joinToString { ipText(it) }}")
            }
        }
        return builder.establish()
    }

    fun detach(socket: Socket) {
        bindOutside(socket)
        if (!protect(socket)) warnDetach("protect не сработал")
    }

    fun detach(socket: DatagramSocket) {
        bindOutside(socket)
        if (!protect(socket)) warnDetach("protect DNS не сработал")
    }

    private fun bindOutside(socket: Socket) {
        val network = physicalNetwork()
        if (network == null) {
            warnDetach("нет сети вне VPN")
            return
        }
        try {
            network.bindSocket(socket)
        } catch (error: Exception) {
            warnDetach("привязка сокета: ${error.message ?: "ошибка"}")
        }
    }

    private fun bindOutside(socket: DatagramSocket) {
        val network = physicalNetwork()
        if (network == null) {
            warnDetach("нет сети вне VPN")
            return
        }
        try {
            network.bindSocket(socket)
        } catch (error: Exception) {
            warnDetach("привязка DNS: ${error.message ?: "ошибка"}")
        }
    }

    private fun warnDetach(text: String) {
        if (detachWarned.compareAndSet(false, true)) ConnLog.add(text)
    }

    private fun physicalNetwork(): Network? {
        return try {
            val manager = getSystemService(ConnectivityManager::class.java) ?: return null
            var fallback: Network? = null
            for (network in manager.allNetworks) {
                val caps = manager.getNetworkCapabilities(network) ?: continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                ) return network
                fallback = network
            }
            fallback
        } catch (error: Exception) {
            warnDetach(error.message ?: "нет доступа к сетям")
            null
        }
    }

    private fun rememberProxies(config: AppConfig) {
        val next = HashSet<Long>()
        for (proxy in config.proxies) {
            val ip = ipv4(proxy.host) ?: continue
            next.add(ip.toLong() and 0xffffffffL)
        }
        synchronized(proxyIps) {
            proxyIps.clear()
            proxyIps.addAll(next)
        }
    }

    private fun isProxyAddress(ip: Long): Boolean = synchronized(proxyIps) { ip in proxyIps }

    private fun pump(input: FileInputStream) {
        val buf = ByteArray(32767)
        try {
            while (running.get()) {
                val n = input.read(buf)
                if (n <= 0) continue
                try {
                    onPacket(buf, n)
                } catch (error: Exception) {
                    Log.w(TAG, "пакет: ${error.message}")
                }
            }
        } catch (_: Exception) {
        } finally {
            shutdown()
        }
    }

    private fun onPacket(buf: ByteArray, length: Int) {
        if (length < 20 || (buf[0].toInt() ushr 4) != 4) return
        val ihl = (buf[0].toInt() and 0x0f) * 4
        if (ihl < 20 || length < ihl) return
        val total = u16(buf, 2).let { if (it == 0 || it > length) length else it }
        val proto = buf[9].toInt() and 0xff
        val srcIp = u32(buf, 12)
        val dstIp = u32(buf, 16)
        when (proto) {
            6 -> onTcp(buf, ihl, total, srcIp, dstIp)
            17 -> onUdp(buf, ihl, total, srcIp, dstIp)
        }
    }

    private fun onUdp(buf: ByteArray, ihl: Int, total: Int, srcIp: Long, dstIp: Long) {
        if (total < ihl + 8) return
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        val udpLen = u16(buf, ihl + 4)
        val payloadLen = (udpLen - 8).coerceAtMost(total - ihl - 8)
        if (dstPort != 53 || payloadLen <= 0) {
            if (dstPort != 53 && payloadLen > 0) noteUdp(dstIp, dstPort)
            return
        }
        val payload = buf.copyOfRange(ihl + 8, ihl + 8 + payloadLen)
        workers.execute {
            try {
                val socket = DatagramSocket()
                detach(socket)
                socket.soTimeout = 4000
                socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName("1.1.1.1"), 53))
                val reply = ByteArray(1500)
                val packet = DatagramPacket(reply, reply.size)
                socket.receive(packet)
                socket.close()
                sendUdp(dstIp, srcIp, 53, srcPort, reply, packet.length)
            } catch (error: Exception) {
                Log.w(TAG, "dns: ${error.message}")
                ConnLog.add("DNS ${ipText(dstIp)} — ${error.message ?: "ошибка"}")
            }
        }
    }

    private fun onTcp(buf: ByteArray, ihl: Int, total: Int, srcIp: Long, dstIp: Long) {
        if (total < ihl + 20) return
        val srcPort = u16(buf, ihl)
        val dstPort = u16(buf, ihl + 2)
        val seq = u32(buf, ihl + 4)
        val flags = buf[ihl + 13].toInt() and 0xff
        val dataOff = ((buf[ihl + 12].toInt() and 0xff) ushr 4) * 4
        if (dataOff < 20 || ihl + dataOff > total) return
        val payloadLen = total - ihl - dataOff
        val key = "$srcIp:$srcPort:$dstIp:$dstPort"
        if (flags and RST != 0) {
            val flow = flows.remove(key) ?: return
            if (flow.label.isNotEmpty()) {
                ConnLog.add("${flow.label} — сброс, от приложения ${flow.up} байт, обратно ${flow.down}")
            }
            flow.close()
            return
        }
        if (flags and SYN != 0 && flags and ACK == 0) {
            if (isProxyAddress(dstIp)) {
                noteProxy(dstIp, dstPort)
                return
            }
            if (flows.size > 300) return
            val flow = Flow(srcIp, dstIp, srcPort, dstPort, (seq + 1) and MASK, Random.nextLong() and MASK, android.os.SystemClock.elapsedRealtime())
            flows[key] = flow
            sendTcp(flow, SYN or ACK, null, 0)
            return
        }
        val flow = flows[key] ?: return
        if (flow.closed) return
        if (payloadLen > 0) {
            if (seq != flow.expect) {
                if (seq < flow.expect) sendTcp(flow, ACK, null, 0)
                return
            }
            val payload = buf.copyOfRange(ihl + dataOff, ihl + dataOff + payloadLen)
            flow.expect = (flow.expect + payloadLen) and MASK
            flow.up += payloadLen
            sendTcp(flow, ACK, null, 0)
            var direct = false
            synchronized(flow) {
                val socket = flow.upstream
                if (socket != null) {
                    try {
                        socket.getOutputStream().write(payload)
                    } catch (error: Exception) {
                        ConnLog.add("${flow.label} — запись: ${error.message ?: "ошибка"}")
                        flow.close()
                    }
                } else {
                    flow.buffered.write(payload)
                    direct = true
                }
            }
            if (direct) dial(flow, false)
        }
        if (flags and FIN != 0) {
            flow.expect = (flow.expect + 1) and MASK
            sendTcp(flow, ACK or FIN, null, 0)
            flow.close()
            flows.remove(key)
            return
        }
        if (payloadLen == 0 && flags and ACK != 0 && flow.upstream == null && dstPort != 443 && dstPort != 80) {
            dial(flow, true)
        }
    }

    private fun dial(flow: Flow, force: Boolean) {
        synchronized(flow) {
            if (flow.closed || flow.upstream != null || flow.dialing) return
            if (!force && !payloadReady(flow)) return
            flow.dialing = true
        }
        workers.execute {
            try {
                openUpstream(flow)
            } catch (error: Exception) {
                val where = flow.label.ifBlank { "${ipText(flow.dstIp)}:${flow.dstPort}" }
                Log.w(TAG, "соединение $where: ${error.message}")
                ConnLog.add("$where — ${error.message ?: "ошибка"}")
                sendTcp(flow, RST or ACK, null, 0)
                flow.close()
                flows.remove(flow.key())
            }
        }
    }

    private fun openUpstream(flow: Flow) {
        val buffered = synchronized(flow) { flow.buffered.toByteArray() }
        val host = when (flow.dstPort) {
            443 -> tlsServerName(buffered, buffered.size)
            80 -> httpHost(buffered)
            else -> null
        }
        val config = Store.load(this)
        rememberProxies(config)
        val decision = decideRoute(host, flow.dstIp.toInt(), flow.dstPort, config, nets)
        val dest = "${host ?: ipText(flow.dstIp)}:${flow.dstPort}"
        flow.label = dest
        if (decision.kind == RouteKind.BLOCK) {
            Log.i(TAG, "$dest → блок (${decision.summary})")
            ConnLog.add("$dest → блок (${decision.summary})")
            sendTcp(flow, RST or ACK, null, 0)
            flow.close()
            flows.remove(flow.key())
            return
        }
        val socket = Socket()
        detach(socket)
        socket.tcpNoDelay = true
        val proxy = decision.proxy
        val via = if (decision.kind == RouteKind.PROXY && proxy != null) {
            "${proxy.name} (${decision.summary})"
        } else if (host == null && (flow.dstPort == 443 || flow.dstPort == 80)) {
            "напрямую, имя не видно"
        } else {
            "напрямую"
        }
        Log.i(TAG, "$dest → $via")
        ConnLog.add("$dest → $via")
        if (decision.kind == RouteKind.PROXY && proxy != null) {
            socket.connect(InetSocketAddress(proxy.host, proxy.port), 15000)
            httpConnect(socket, host ?: ipText(flow.dstIp), flow.dstPort, proxy)
        } else {
            socket.connect(InetSocketAddress(ipText(flow.dstIp), flow.dstPort), 15000)
        }
        ConnLog.add("$dest — открыто с ${socket.localAddress?.hostAddress ?: "?"}")
        synchronized(flow) {
            if (flow.closed) {
                socket.close()
                return
            }
            socket.getOutputStream().write(flow.buffered.toByteArray())
            flow.buffered.reset()
            flow.upstream = socket
            flow.dialing = false
        }
        val remote = socket.getInputStream()
        val chunk = ByteArray(1200)
        while (running.get() && !flow.closed) {
            val n = remote.read(chunk)
            if (n < 0) break
            if (n == 0) continue
            flow.down += n
            sendTcp(flow, ACK or PSH, chunk, n)
        }
        if (!flow.closed) sendTcp(flow, ACK or FIN, null, 0)
        ConnLog.add("$dest — конец, от приложения ${flow.up} байт, обратно ${flow.down}")
        flow.close()
    }

    private fun payloadReady(flow: Flow): Boolean {
        val size = flow.buffered.size()
        val age = android.os.SystemClock.elapsedRealtime() - flow.born
        if (flow.dstPort == 443) {
            if (size < 5) return age >= 700
            val data = flow.buffered.toByteArray()
            if ((data[0].toInt() and 0xff) != 0x16) return true
            val record = u16(data, 3)
            if (record <= 0 || record > 17000) return true
            return size >= 5 + record || age >= 700
        }
        if (flow.dstPort == 80) {
            if (size < 4) return age >= 700
            return flow.buffered.toByteArray().toString(Charsets.ISO_8859_1).contains("\r\n\r\n") || age >= 700
        }
        return true
    }

    private fun httpConnect(socket: Socket, host: String, port: Int, proxy: ProxyEntry) {
        val target = "$host:$port"
        val request = StringBuilder()
        request.append("CONNECT $target HTTP/1.1\r\n")
        request.append("Host: $target\r\n")
        request.append("Proxy-Connection: keep-alive\r\n")
        if (proxy.user.isNotEmpty()) {
            val token = Base64.encodeToString(
                "${proxy.user}:${proxy.password}".toByteArray(Charsets.UTF_8),
                Base64.NO_WRAP
            )
            request.append("Proxy-Authorization: Basic $token\r\n")
        }
        request.append("\r\n")
        val out = socket.getOutputStream()
        out.write(request.toString().toByteArray(Charsets.US_ASCII))
        out.flush()
        val header = readHeader(socket.getInputStream())
        val status = header.lineSequence().firstOrNull().orEmpty()
        if (!status.contains(" 200 ")) {
            throw IllegalStateException(status.ifBlank { "прокси не открыл соединение" })
        }
    }

    private fun readHeader(input: InputStream): String {
        val acc = ByteArrayOutputStream()
        val one = ByteArray(1)
        while (acc.size() < 8192) {
            val n = input.read(one)
            if (n < 0) break
            acc.write(one, 0, 1)
            val text = acc.toString(Charsets.ISO_8859_1.name())
            if (text.endsWith("\r\n\r\n")) return text
        }
        return acc.toString(Charsets.ISO_8859_1.name())
    }

    private fun sendTcp(flow: Flow, flags: Int, payload: ByteArray?, payloadLen: Int) {
        if (!running.get()) return
        synchronized(flow.sendLock) {
        val tcpHdr = if (flags and SYN != 0) 24 else 20
        val total = 20 + tcpHdr + payloadLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        put16(pkt, 2, total)
        put16(pkt, 4, nextIpId())
        pkt[8] = 64
        pkt[9] = 6
        put32(pkt, 12, flow.dstIp)
        put32(pkt, 16, flow.srcIp)
        put16(pkt, 10, inetChecksum(pkt, 0, 20))
        val tcp = 20
        put16(pkt, tcp, flow.dstPort)
        put16(pkt, tcp + 2, flow.srcPort)
        put32(pkt, tcp + 4, flow.sendSeq)
        put32(pkt, tcp + 8, flow.expect)
        pkt[tcp + 12] = ((tcpHdr / 4) shl 4).toByte()
        pkt[tcp + 13] = flags.toByte()
        put16(pkt, tcp + 14, 65535)
        if (tcpHdr == 24) {
            pkt[tcp + 20] = 2
            pkt[tcp + 21] = 4
            put16(pkt, tcp + 22, 1200)
        }
        if (payload != null && payloadLen > 0) payload.copyInto(pkt, tcp + tcpHdr, 0, payloadLen)
        put16(pkt, tcp + 16, 0)
        put16(pkt, tcp + 16, tcpChecksum(flow.dstIp, flow.srcIp, pkt, tcp, tcpHdr + payloadLen))
        writeTun(pkt, total)
        var advance = payloadLen
        if (flags and (SYN or FIN) != 0) advance += 1
        flow.sendSeq = (flow.sendSeq + advance) and MASK
        }
    }

    private fun sendUdp(srcIp: Long, dstIp: Long, srcPort: Int, dstPort: Int, payload: ByteArray, payloadLen: Int) {
        val total = 20 + 8 + payloadLen
        val pkt = ByteArray(total)
        pkt[0] = 0x45
        put16(pkt, 2, total)
        put16(pkt, 4, nextIpId())
        pkt[8] = 64
        pkt[9] = 17
        put32(pkt, 12, srcIp)
        put32(pkt, 16, dstIp)
        put16(pkt, 10, inetChecksum(pkt, 0, 20))
        put16(pkt, 20, srcPort)
        put16(pkt, 22, dstPort)
        put16(pkt, 24, 8 + payloadLen)
        payload.copyInto(pkt, 28, 0, payloadLen)
        put16(pkt, 26, udpChecksum(srcIp, dstIp, pkt, 20, 8 + payloadLen))
        writeTun(pkt, total)
    }

    private fun tcpChecksum(src: Long, dst: Long, pkt: ByteArray, off: Int, len: Int): Int {
        val seed = pseudo(src, dst, 6, len)
        return inetChecksum(pkt, off, len, seed)
    }

    private fun udpChecksum(src: Long, dst: Long, pkt: ByteArray, off: Int, len: Int): Int {
        val seed = pseudo(src, dst, 17, len)
        val sum = inetChecksum(pkt, off, len, seed)
        return if (sum == 0) 0xffff else sum
    }

    private fun pseudo(src: Long, dst: Long, proto: Int, len: Int): Int {
        var sum = 0
        sum += ((src shr 16) and 0xffff).toInt()
        sum += (src and 0xffff).toInt()
        sum += ((dst shr 16) and 0xffff).toInt()
        sum += (dst and 0xffff).toInt()
        sum += proto
        sum += len
        return sum
    }

    private fun writeTun(packet: ByteArray, len: Int) {
        val out = output ?: return
        synchronized(outLock) {
            out.write(packet, 0, len)
            out.flush()
        }
    }

    private fun nextIpId(): Int = synchronized(this) { ipId = (ipId + 1) and 0xffff; ipId }

    private fun scheduleRestart() {
        val restart = PendingIntent.getForegroundService(
            this,
            8,
            Intent(this, StopVpnService::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val alarm = getSystemService(AlarmManager::class.java) ?: return
        val at = SystemClock.elapsedRealtime() + 800
        try {
            alarm.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, restart)
        } catch (_: Exception) {
            alarm.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, restart)
        }
    }

    private fun runProxyTest(intent: Intent, startId: Int) {
        val id = intent.getStringExtra("id").orEmpty()
        val wasRunning = running.get()
        val proxy = ProxyEntry(
            "",
            "",
            intent.getStringExtra("host").orEmpty(),
            intent.getIntExtra("port", 0),
            intent.getStringExtra("user").orEmpty(),
            intent.getStringExtra("password").orEmpty()
        )
        workers.execute {
            val result = ProxyTest.run(proxy)
            if (id.isNotEmpty()) {
                try {
                    filesDir.resolve("proxy-test-$id.txt").writeText(result)
                } catch (_: Exception) {
                }
            }
            if (!wasRunning && !running.get()) stopSelf(startId)
        }
    }

    private fun startBeat() {
        Thread({
            val fileBeat = filesDir.resolve("vpn-beat")
            while (running.get()) {
                try {
                    fileBeat.writeText(System.currentTimeMillis().toString())
                } catch (_: Exception) {
                }
                try {
                    Thread.sleep(1000)
                } catch (_: InterruptedException) {
                    break
                }
            }
            try {
                fileBeat.delete()
            } catch (_: Exception) {
            }
        }, "stopRKN-beat").start()
    }

    private fun showForeground() {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(
                NOTIFICATION_ID,
                notification(),
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification())
        }
    }

    private fun notification() = NotificationCompat.Builder(this, channel()).run {
        val open = PendingIntent.getActivity(
            this@StopVpnService, 0,
            Intent(this@StopVpnService, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        setSmallIcon(android.R.drawable.ic_lock_lock)
        setContentTitle("stopRKN")
        setContentText("Маршрутизация включена")
        setContentIntent(open)
        setOngoing(true)
        build()
    }

    private fun channel(): String {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "stopRKN", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return CHANNEL
    }

    private fun shutdown() {
        if (instance === this) instance = null
        synchronized(udpNoted) { udpNoted.clear() }
        active = false
        VpnState.clear(this)
        if (!running.getAndSet(false) && tun == null) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        flows.values.forEach { it.close() }
        flows.clear()
        try { output?.close() } catch (_: Exception) {}
        try { tun?.close() } catch (_: Exception) {}
        output = null
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private class Flow(
        val srcIp: Long,
        val dstIp: Long,
        val srcPort: Int,
        val dstPort: Int,
        var expect: Long,
        var sendSeq: Long,
        val born: Long
    ) {
        val sendLock = Any()
        @Volatile var upstream: Socket? = null
        @Volatile var dialing: Boolean = false
        @Volatile var closed: Boolean = false
        @Volatile var label: String = ""
        @Volatile var up: Long = 0
        @Volatile var down: Long = 0
        val buffered = ByteArrayOutputStream()
        fun key() = "$srcIp:$srcPort:$dstIp:$dstPort"
        fun close() {
            closed = true
            try { upstream?.close() } catch (_: Exception) {}
        }
    }

    private fun noteUdp(dstIp: Long, dstPort: Int) {
        val key = "$dstIp:$dstPort"
        synchronized(udpNoted) {
            if (!udpNoted.add(key)) return
            if (udpNoted.size > 200) udpNoted.clear()
        }
        val why = if (dstPort == 443) "QUIC отброшен, нужен TCP" else "UDP не проксируется"
        ConnLog.add("UDP ${ipText(dstIp)}:$dstPort — $why")
    }

    private fun noteProxy(dstIp: Long, dstPort: Int) {
        val key = "proxy:$dstIp:$dstPort"
        synchronized(udpNoted) {
            if (!udpNoted.add(key)) return
        }
        ConnLog.add("TCP ${ipText(dstIp)}:$dstPort — это адрес прокси, в туннель его пускать нельзя")
    }

    companion object {
        const val ACTION_STOP = "stop"
        const val ACTION_TEST = "test"
        const val CHANNEL = "stoprkn"
        const val NOTIFICATION_ID = 7
        const val TAG = "stopRKN"
        const val SYN = 0x02
        const val RST = 0x04
        const val PSH = 0x08
        const val ACK = 0x10
        const val FIN = 0x01
        const val MASK = 0xffffffffL

        @Volatile
        var active: Boolean = false

        @Volatile
        var lastError: String? = null

        @Volatile
        var instance: StopVpnService? = null
    }
}
