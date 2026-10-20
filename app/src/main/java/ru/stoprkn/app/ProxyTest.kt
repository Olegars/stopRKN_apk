package ru.stoprkn.app

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException

object ProxyTest {
    fun run(proxy: ProxyEntry): String {
        val socket = Socket()
        try {
            if (StopVpnService.active) StopVpnService.instance?.detach(socket)
            socket.soTimeout = 12000
            socket.connect(InetSocketAddress(proxy.host, proxy.port), 12000)
            connectTunnel(socket, proxy)
            return "Выход до 1.1.1.1:443 открылся"
        } catch (_: SocketTimeoutException) {
            return "Таймаут проверки"
        } catch (error: UnknownHostException) {
            return "Адрес не найден"
        } catch (error: ConnectException) {
            return error.message?.ifBlank { "Нет соединения" } ?: "Нет соединения"
        } catch (error: Exception) {
            return error.message?.ifBlank { "Ошибка проверки" } ?: "Ошибка проверки"
        } finally {
            try {
                socket.close()
            } catch (_: Exception) {
            }
        }
    }

    private fun connectTunnel(socket: Socket, proxy: ProxyEntry) {
        val target = "1.1.1.1:443"
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
            throw IllegalStateException(status.ifBlank { "Прокси не открыл соединение" })
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
}
