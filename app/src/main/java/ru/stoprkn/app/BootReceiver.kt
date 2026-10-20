package ru.stoprkn.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat

object VpnState {
    private const val BEAT = "vpn-beat"
    private const val ERROR = "vpn-error"

    fun beat(context: Context) {
        context.filesDir.resolve(BEAT).writeText(System.currentTimeMillis().toString())
    }

    fun clear(context: Context) {
        context.filesDir.resolve(BEAT).delete()
    }

    fun running(context: Context): Boolean {
        val stamp = context.filesDir.resolve(BEAT).takeIf { it.exists() }?.readText()?.trim()?.toLongOrNull()
            ?: return false
        return System.currentTimeMillis() - stamp < 4000
    }

    fun setError(context: Context, text: String?) {
        val file = context.filesDir.resolve(ERROR)
        if (text.isNullOrBlank()) file.delete() else file.writeText(text)
    }

    fun error(context: Context): String? =
        context.filesDir.resolve(ERROR).takeIf { it.exists() }?.readText()?.trim()?.ifBlank { null }
}

object KeepAlive {
    private const val PREFS = "stoprkn"
    private const val KEY = "routing"

    fun wanted(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, false)

    fun set(context: Context, on: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, on).apply()
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!KeepAlive.wanted(context)) return
        if (VpnService.prepare(context) != null) return
        val start = Intent(context, StopVpnService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                ContextCompat.startForegroundService(context, start)
            } else {
                context.startService(start)
            }
        } catch (_: Exception) {
        }
    }
}
