package ru.stoprkn.app

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ConnLog {
    private val lock = Any()
    @Volatile private var folder: java.io.File? = null

    fun attach(context: Context) {
        folder = context.filesDir
    }

    private fun file(): java.io.File? = folder?.resolve("conn.log")

    fun add(text: String) {
        val clock = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val line = "$clock  $text"
        synchronized(lock) {
            val log = file() ?: return
            val existing = if (log.exists()) log.readLines() else emptyList()
            log.writeText((existing + line).takeLast(250).joinToString("\n"))
        }
    }

    fun text(): String = synchronized(lock) {
        val body = file()?.takeIf { it.exists() }?.readText().orEmpty().trim()
        body.ifBlank { "Пока пусто. Включите маршрутизацию и откройте сайт." }
    }

    fun clear() {
        synchronized(lock) { file()?.writeText("") }
    }

    fun export(context: Context): String {
        val body = text().toByteArray(Charsets.UTF_8)
        val name = "stopRKN-log.txt"
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "text/plain")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            resolver.delete(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                "${MediaStore.MediaColumns.DISPLAY_NAME}=?",
                arrayOf(name)
            )
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: return "Не удалось создать файл в Загрузках"
            resolver.openOutputStream(uri)?.use { it.write(body) }
                ?: return "Не удалось записать файл"
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
            return "Загрузки/$name"
        }
        val dir = context.getExternalFilesDir(null) ?: context.filesDir
        val file = dir.resolve(name)
        file.writeBytes(body)
        return file.absolutePath
    }
}
