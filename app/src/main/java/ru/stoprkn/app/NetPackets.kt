package ru.stoprkn.app

fun u16(buf: ByteArray, off: Int): Int =
    ((buf[off].toInt() and 0xff) shl 8) or (buf[off + 1].toInt() and 0xff)

fun u32(buf: ByteArray, off: Int): Long {
    var value = 0L
    for (i in 0 until 4) value = (value shl 8) or (buf[off + i].toLong() and 0xff)
    return value
}

fun put16(buf: ByteArray, off: Int, value: Int) {
    buf[off] = (value shr 8).toByte()
    buf[off + 1] = value.toByte()
}

fun put32(buf: ByteArray, off: Int, value: Long) {
    val v = value and 0xffffffffL
    buf[off] = (v shr 24).toByte()
    buf[off + 1] = (v shr 16).toByte()
    buf[off + 2] = (v shr 8).toByte()
    buf[off + 3] = v.toByte()
}

fun inetChecksum(data: ByteArray, off: Int, len: Int, seed: Int = 0): Int {
    var sum = seed
    var i = off
    val end = off + len
    while (i + 1 < end) {
        sum += ((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)
        i += 2
    }
    if (i < end) sum += (data[i].toInt() and 0xff) shl 8
    while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
    return sum.inv() and 0xffff
}

fun tlsServerName(data: ByteArray, length: Int): String? {
    if (length < 43 || (data[0].toInt() and 0xff) != 0x16) return null
    var i = 5
    if (i >= length || (data[i].toInt() and 0xff) != 1) return null
    i += 4
    i += 2 + 32
    if (i >= length) return null
    val session = data[i].toInt() and 0xff
    i += 1 + session
    if (i + 2 > length) return null
    val ciphers = u16(data, i)
    i += 2 + ciphers
    if (i >= length) return null
    val comp = data[i].toInt() and 0xff
    i += 1 + comp
    if (i + 2 > length) return null
    val extEnd = i + 2 + u16(data, i)
    i += 2
    while (i + 4 <= length && i + 4 <= extEnd) {
        val type = u16(data, i)
        val size = u16(data, i + 2)
        i += 4
        if (i + size > length) return null
        if (type == 0 && size >= 5) {
            val nameLen = u16(data, i + 3)
            val start = i + 5
            if (nameLen > 0 && start + nameLen <= length) {
                return data.copyOfRange(start, start + nameLen).toString(Charsets.US_ASCII)
            }
        }
        i += size
    }
    return null
}

fun httpHost(data: ByteArray): String? {
    val text = data.toString(Charsets.ISO_8859_1)
    val line = text.lineSequence().firstOrNull { it.startsWith("Host:", ignoreCase = true) } ?: return null
    return line.substringAfter(':').trim().substringBefore(':').trim().ifBlank { null }
}

fun ipText(ip: Long): String =
    "${(ip shr 24) and 0xff}.${(ip shr 16) and 0xff}.${(ip shr 8) and 0xff}.${ip and 0xff}"
