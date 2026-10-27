package ru.stoprkn.app

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

object ConnLog {
    private val lock = Any()
    private val lines = ArrayDeque<String>()
    @Volatile private var folder: java.io.File? = null
    private var loaded = false
    private var writerStarted = false
    private var dirty = false

    fun attach(context: Context) {
        folder = context.filesDir
        synchronized(lock) {
            if (!loaded) {
                loaded = true
                val existing = file()?.takeIf { it.exists() }?.readLines().orEmpty()
                existing.takeLast(250).forEach { lines.addLast(it) }
            }
            if (!writerStarted) {
                writerStarted = true
                Thread({
                    while (true) {
                        val body = synchronized(lock) {
                            if (!dirty) {
                                try {
                                    (lock as java.lang.Object).wait(1000)
                                } catch (_: InterruptedException) {
                                }
                            }
                            dirty = false
                            lines.joinToString("\n")
                        }
                        try {
                            file()?.writeText(body)
                        } catch (_: Exception) {
                        }
                    }
                }, "stopRKN-log").apply { isDaemon = true }.start()
            }
        }
    }

    private fun file(): java.io.File? = folder?.resolve("conn.log")

    fun add(text: String) {
        val clock = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val line = "$clock  $text"
        synchronized(lock) {
            lines.addLast(line)
            while (lines.size > 250) lines.removeFirst()
            dirty = true
            (lock as java.lang.Object).notifyAll()
        }
    }

    fun text(): String = synchronized(lock) {
        lines.joinToString("\n").trim().ifBlank {
            "Пока пусто. Включите маршрутизацию и откройте сайт."
        }
    }

    fun clear() {
        synchronized(lock) {
            lines.clear()
            dirty = true
            (lock as java.lang.Object).notifyAll()
        }
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
