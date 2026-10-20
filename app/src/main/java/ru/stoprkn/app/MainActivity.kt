package ru.stoprkn.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.net.VpnService
import android.os.PowerManager
import android.provider.Settings
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.util.UUID

class MainActivity : AppCompatActivity() {
    private lateinit var config: AppConfig
    private lateinit var root: LinearLayout
    private lateinit var toggle: Button

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startVpn() else KeepAlive.set(this, false)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ConnLog.attach(this)
        config = Store.load(this)
        val scroll = ScrollView(this)
        root = column()
        root.setPadding(dp(16), dp(16), dp(16), dp(24))
        scroll.addView(root)
        setContentView(scroll)
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        render()
        if (KeepAlive.wanted(this) && !vpnOn() && VpnService.prepare(this) == null) {
            startVpn()
        }
    }

    override fun onResume() {
        super.onResume()
        if (::toggle.isInitialized) {
            toggle.text = if (vpnOn()) "Выключить маршрутизацию" else "Включить маршрутизацию"
        }
    }

    private fun render() {
        root.removeAllViews()
        title("stopRKN")
        hint("Включённые соцсети идут через выбранный прокси. Свои правила проверяются после них. Остальное — напрямую. На Android это VPN, а не системный прокси Windows.")
        toggle = button(if (vpnOn()) "Выключить маршрутизацию" else "Включить маршрутизацию", ::onToggle)
        root.addView(toggle, match())
        hint("Крестик в списке недавних программу не закрывает. После перезагрузки телефона маршрутизация включается сама.")
        root.addView(button("Соединения") { showConnections() }, match())
        title("Прокси")
        if (config.proxies.isEmpty()) hint("Пока нет ни одного прокси.")
        for (proxy in config.proxies) root.addView(proxyLine(proxy), match())
        root.addView(button("Добавить прокси") { addProxy() }, match())
        title("Соцсети")
        hint("Галка включает сервис. Если прокси ещё не выбран, откроется окно выбора. «Проверить» открывает выход через прокси. Долгое нажатие на прокси удаляет его.")
        for (rule in config.social) {
            val net = SocialCatalog.byId(rule.id) ?: continue
            val box = CheckBox(this).apply {
                text = net.title + " — " + proxyLabel(rule.proxyId)
                setTextColor(0xFFF2F5F3.toInt())
                textSize = 16f
                showBox()
                isChecked = rule.enabled
                setOnClickListener {
                    if (isChecked) {
                        if (!enable(rule)) isChecked = false
                    } else {
                        rule.enabled = false
                        persist()
                    }
                    text = net.title + " — " + proxyLabel(rule.proxyId)
                }
            }
            root.addView(box, match())
        }
        title("Свои правила")
        hint("Назначение: домены, IP или сети через запятую. Пустое — весь трафик, который не попал в соцсети. Долгое нажатие: изменить, удалить, порядок.")
        if (config.rules.isEmpty()) hint("Своих правил пока нет.")
        config.rules.forEachIndexed { index, rule ->
            val box = CheckBox(this).apply {
                text = ruleLabel(rule)
                setTextColor(0xFFF2F5F3.toInt())
                textSize = 16f
                isSingleLine = false
                showBox()
                isChecked = rule.enabled
                setOnClickListener {
                    if (isChecked) {
                        if (!enableCustom(rule)) isChecked = false
                    } else {
                        rule.enabled = false
                        persist()
                    }
                    text = ruleLabel(rule)
                }
                setOnLongClickListener {
                    ruleMenu(index)
                    true
                }
            }
            root.addView(box, match())
        }
        root.addView(button("Добавить правило") { editCustom(null) }, match())
    }

    private fun proxyLine(proxy: ProxyEntry): LinearLayout {
        val line = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val label = TextView(this).apply {
            text = "${proxy.name}  ${proxy.host}:${proxy.port}"
            setTextColor(0xFFF2F5F3.toInt())
            textSize = 16f
            setPadding(0, dp(8), dp(8), dp(8))
            setOnLongClickListener {
                removeProxy(proxy)
                true
            }
        }
        val test = button("Проверить") { testProxy(proxy) }
        line.addView(label, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        line.addView(test, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.WRAP_CONTENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ))
        return line
    }

    private fun removeProxy(proxy: ProxyEntry) {
        config.proxies.removeAll { it.id == proxy.id }
        for (rule in config.social) if (rule.proxyId == proxy.id) {
            rule.proxyId = ""
            rule.enabled = false
        }
        for (rule in config.rules) if (rule.action == "proxy" && rule.proxyId == proxy.id) {
            rule.proxyId = ""
            rule.enabled = false
        }
        persist()
    }

    private fun testProxy(proxy: ProxyEntry) {
        val wait = dialog()
            .setTitle(proxy.name)
            .setMessage("Проверяю выход до 1.1.1.1:443…")
            .setCancelable(false)
            .create()
        wait.show()
        Thread {
            val message = if (vpnOn()) askServiceTest(proxy) else ProxyTest.run(proxy)
            runOnUiThread {
                if (isFinishing) return@runOnUiThread
                try {
                    wait.dismiss()
                } catch (_: Exception) {
                }
                dialog()
                    .setTitle(proxy.name)
                    .setMessage(message)
                    .setPositiveButton("Ок", null)
                    .show()
            }
        }.start()
    }

    private fun ruleLabel(rule: CustomRule): String {
        val where = rule.target.trim().ifBlank { "весь трафик" }
        val ports = if (rule.ports.isBlank()) "" else " (${rule.ports})"
        val how = when (rule.action) {
            "direct" -> "напрямую"
            "block" -> "блок"
            else -> proxyLabel(rule.proxyId)
        }
        return "${rule.name.ifBlank { "Правило" }} — $where$ports — $how"
    }

    private fun enableCustom(rule: CustomRule): Boolean {
        if (rule.action != "proxy") {
            rule.enabled = true
            persist()
            return true
        }
        if (config.proxy(rule.proxyId) != null) {
            rule.enabled = true
            persist()
            return true
        }
        if (config.proxies.isEmpty()) {
            toast("Сначала добавьте прокси")
            return false
        }
        val names = config.proxies.map { it.name }.toTypedArray()
        dialog()
            .setTitle("Прокси для ${rule.name.ifBlank { "правила" }}")
            .setItems(names) { _, which ->
                rule.proxyId = config.proxies[which].id
                rule.enabled = true
                persist()
            }
            .setNegativeButton("Отмена", null)
            .show()
        return false
    }

    private fun ruleMenu(index: Int) {
        val rule = config.rules.getOrNull(index) ?: return
        dialog()
            .setTitle(rule.name.ifBlank { "Правило" })
            .setItems(arrayOf("Изменить", "Удалить", "Выше", "Ниже")) { _, which ->
                when (which) {
                    0 -> editCustom(index)
                    1 -> {
                        config.rules.removeAt(index)
                        persist()
                    }
                    2 -> moveRule(index, -1)
                    3 -> moveRule(index, 1)
                }
            }
            .show()
    }

    private fun moveRule(index: Int, delta: Int) {
        val next = index + delta
        if (next !in config.rules.indices) return
        val item = config.rules.removeAt(index)
        config.rules.add(next, item)
        persist()
    }

    private fun editCustom(index: Int?) {
        val existing = index?.let { config.rules.getOrNull(it) }
        val form = column()
        val name = field("Название")
        val target = field("Сайты, IP или сети через запятую")
        val ports = field("Порты, пусто — любые")
        if (existing != null) {
            name.setText(existing.name)
            target.setText(existing.target)
            ports.setText(existing.ports)
        }
        var action = existing?.action ?: "proxy"
        var proxyId = existing?.proxyId.orEmpty()
        val actionButton = button("") {}
        val proxyButton = button("") {}
        fun paint() {
            actionButton.text = "Действие: " + when (action) {
                "direct" -> "напрямую"
                "block" -> "заблокировать"
                else -> "через прокси"
            }
            proxyButton.text = "Прокси: " + proxyLabel(proxyId)
            proxyButton.isEnabled = action == "proxy"
        }
        actionButton.setOnClickListener {
            dialog()
                .setItems(arrayOf("Через прокси", "Напрямую", "Заблокировать")) { _, which ->
                    action = listOf("proxy", "direct", "block")[which]
                    paint()
                }
                .show()
        }
        proxyButton.setOnClickListener {
            if (config.proxies.isEmpty()) {
                toast("Сначала добавьте прокси")
                return@setOnClickListener
            }
            val names = config.proxies.map { it.name }.toTypedArray()
            dialog()
                .setItems(names) { _, which ->
                    proxyId = config.proxies[which].id
                    paint()
                }
                .show()
        }
        paint()
        for (item in listOf(name, target, ports, actionButton, proxyButton)) form.addView(item, match())
        val dialog = dialog()
            .setTitle(if (existing == null) "Новое правило" else "Правило")
            .setMessage("Пустое назначение — весь трафик, который не попал в соцсети.")
            .setView(form)
            .setPositiveButton("Сохранить", null)
            .setNegativeButton("Отмена", null)
            .create()
        dialog.show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val portsText = ports.text.toString().trim()
            val targetText = target.text.toString().trim()
            if (!portsSpecValid(portsText)) {
                toast("Порты: 80,443 или 1000-2000")
                return@setOnClickListener
            }
            val bad = targetTokens(targetText).firstOrNull { !targetTokenOk(it) }
            if (bad != null) {
                toast("Не понял «$bad»")
                return@setOnClickListener
            }
            if (action == "proxy" && config.proxy(proxyId) == null) {
                toast("Выберите прокси")
                return@setOnClickListener
            }
            val rule = existing ?: CustomRule(
                UUID.randomUUID().toString(), true, "", "", "", "proxy", ""
            ).also { config.rules += it }
            rule.name = name.text.toString().trim().ifBlank { targetText.ifBlank { "Правило" } }
            rule.target = targetText
            rule.ports = portsText
            rule.action = action
            if (action == "proxy") rule.proxyId = proxyId
            rule.enabled = action != "proxy" || config.proxy(rule.proxyId) != null
            dialog.dismiss()
            persist()
        }
    }

    private fun showConnections() {
        val text = TextView(this).apply {
            setTextColor(0xFFF2F5F3.toInt())
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }
        val scroll = ScrollView(this).apply {
            setBackgroundColor(0xFF101412.toInt())
            addView(text)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                (resources.displayMetrics.heightPixels * 0.62f).toInt()
            )
        }
        val dialog = dialog()
            .setTitle("Соединения")
            .setView(scroll)
            .setPositiveButton("Закрыть", null)
            .setNegativeButton("В файл", null)
            .setNeutralButton("Очистить", null)
            .create()
        val handler = Handler(Looper.getMainLooper())
        val tick = object : Runnable {
            override fun run() {
                if (!dialog.isShowing) return
                val nearBottom = scroll.getChildAt(0)?.let { child ->
                    child.bottom <= scroll.height + scroll.scrollY + dp(48)
                } ?: true
                text.text = ConnLog.text()
                if (nearBottom) scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
                handler.postDelayed(this, 1000)
            }
        }
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
                ConnLog.clear()
                text.text = ConnLog.text()
            }
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener {
                val path = try {
                    ConnLog.export(this)
                } catch (error: Exception) {
                    error.message ?: "Не удалось сохранить"
                }
                toast(path)
            }
        }
        dialog.setOnDismissListener { handler.removeCallbacksAndMessages(null) }
        dialog.show()
        tick.run()
    }

    private fun onToggle() {
        if (vpnOn()) {
            KeepAlive.set(this, false)
            startService(Intent(this, StopVpnService::class.java).setAction(StopVpnService.ACTION_STOP))
            toggle.text = "Включить маршрутизацию"
            return
        }
        KeepAlive.set(this, true)
        val prepare = VpnService.prepare(this)
        if (prepare != null) vpnPermission.launch(prepare) else startVpn()
    }

    private fun startVpn() {
        ContextCompat.startForegroundService(this, Intent(this, StopVpnService::class.java))
        askBattery()
        toggle.text = "Выключить маршрутизацию"
        toggle.postDelayed({
            if (vpnOn()) return@postDelayed
            KeepAlive.set(this, false)
            toggle.text = "Включить маршрутизацию"
            VpnState.error(this)?.let { toast(it) }
        }, 800)
    }

    private fun enable(rule: SocialRule): Boolean {
        val proxy = config.proxy(rule.proxyId)
        if (proxy != null) {
            rule.enabled = true
            persist()
            return true
        }
        if (config.proxies.isEmpty()) {
            toast("Сначала добавьте прокси")
            return false
        }
        val names = config.proxies.map { it.name }.toTypedArray()
        dialog()
            .setTitle("Прокси для ${SocialCatalog.byId(rule.id)?.title ?: "сервиса"}")
            .setItems(names) { _, which ->
                rule.proxyId = config.proxies[which].id
                rule.enabled = true
                persist()
            }
            .setNegativeButton("Отмена", null)
            .show()
        return false
    }

    private fun addProxy() {
        val form = column()
        val name = field("Имя, например Американский")
        val host = field("Адрес")
        val port = field("Порт").apply { inputType = InputType.TYPE_CLASS_NUMBER }
        val user = field("Логин")
        val password = field("Пароль").apply { inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD }
        for (item in listOf(name, host, port, user, password)) form.addView(item, match())
        dialog()
            .setTitle("Новый прокси")
            .setMessage("Тип HTTP, как в программе для Windows.")
            .setView(form)
            .setPositiveButton("Сохранить") { _, _ ->
                val portValue = port.text.toString().toIntOrNull()
                if (name.text.isNullOrBlank() || host.text.isNullOrBlank() || portValue == null || portValue !in 1..65535) {
                    toast("Нужны имя, адрес и порт")
                    return@setPositiveButton
                }
                config.proxies += ProxyEntry(
                    UUID.randomUUID().toString(),
                    name.text.toString().trim(),
                    host.text.toString().trim(),
                    portValue,
                    user.text.toString(),
                    password.text.toString()
                )
                persist()
            }
            .setNegativeButton("Отмена", null)
            .show()
    }

    private fun persist() {
        Store.save(this, config)
        render()
    }

    private fun proxyLabel(id: String): String {
        val proxy = config.proxy(id) ?: return "не выбран"
        return proxy.name
    }

    private fun CheckBox.showBox() {
        buttonTintList = ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
            intArrayOf(0xFF3DDC97.toInt(), 0xFFF2F5F3.toInt())
        )
    }

    private fun vpnOn() = VpnState.running(this)

    private fun askServiceTest(proxy: ProxyEntry): String {
        val id = UUID.randomUUID().toString()
        val file = filesDir.resolve("proxy-test-$id.txt")
        file.delete()
        startService(Intent(this, StopVpnService::class.java).apply {
            action = StopVpnService.ACTION_TEST
            putExtra("id", id)
            putExtra("host", proxy.host)
            putExtra("port", proxy.port)
            putExtra("user", proxy.user)
            putExtra("password", proxy.password)
        })
        val deadline = System.currentTimeMillis() + 15000
        while (System.currentTimeMillis() < deadline) {
            if (file.exists() && file.length() > 0L) {
                val text = file.readText()
                file.delete()
                return text
            }
            try {
                Thread.sleep(200)
            } catch (_: InterruptedException) {
                break
            }
        }
        return "Таймаут проверки"
    }

    private fun askBattery() {
        val power = getSystemService(PowerManager::class.java) ?: return
        if (power.isIgnoringBatteryOptimizations(packageName)) return
        val prefs = getSharedPreferences("stoprkn", MODE_PRIVATE)
        if (prefs.getBoolean("askedBattery", false)) return
        prefs.edit().putBoolean("askedBattery", true).apply()
        try {
            startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                )
            )
        } catch (_: Exception) {
        }
    }

    private fun dialog() = AlertDialog.Builder(this, R.style.StopRKN_Dialog)

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        setTextColor(0xFF101412.toInt())
        setBackgroundColor(0xFF3DDC97.toInt())
        textSize = 16f
        isAllCaps = false
        setPadding(dp(16), dp(12), dp(16), dp(12))
        setOnClickListener { onClick() }
    }

    private fun title(text: String) {
        root.addView(TextView(this).apply {
            this.text = text
            textSize = 22f
            setTextColor(0xFF3DDC97.toInt())
            setPadding(0, dp(18), 0, dp(6))
        })
    }

    private fun hint(text: String) {
        root.addView(TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(0xFFB7C4BC.toInt())
        })
    }

    private fun field(hint: String) = EditText(this).apply {
        this.hint = hint
        setHintTextColor(0xFF7E8C84.toInt())
        setTextColor(0xFF101412.toInt())
        setBackgroundColor(0xFFF2F5F3.toInt())
        setPadding(dp(8), dp(8), dp(8), dp(8))
    }

    private fun column() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.START
    }

    private fun match() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    ).apply { topMargin = dp(8) }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_SHORT).show()
}
