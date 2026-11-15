package com.kurdo.litevpn

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Bundle
import android.text.InputType
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.LinkedList
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class MainActivity : Activity() {

    // Classic HTTP Custom Palette
    private val colorBgDark = Color.parseColor("#21272B")
    private val colorHeaderDark = Color.parseColor("#1B2024")
    private val colorButtonFill = Color.parseColor("#161B1E")
    private val colorTeal = Color.parseColor("#00B386")
    private val colorTextWhite = Color.parseColor("#ECEFF1")
    private val colorTextMuted = Color.parseColor("#90A4AE")

    // Tabs & Containers
    private lateinit var tabSshText: TextView
    private lateinit var tabSshIndicator: View
    private lateinit var tabLogText: TextView
    private lateinit var tabLogIndicator: View
    private lateinit var sshPageContainer: ScrollView
    private lateinit var logPageContainer: LinearLayout

    // Main SSH Tab Views (matching screenshot)
    private lateinit var serverInput: EditText
    private lateinit var chkUsePayload: CheckBox
    private lateinit var chkSsl: CheckBox
    private lateinit var chkEnableDns: CheckBox
    private lateinit var chkSlowDns: CheckBox
    private lateinit var chkAutoReplace: CheckBox
    private lateinit var chkWakeLock: CheckBox
    private lateinit var chkPsiphon: CheckBox
    private lateinit var chkV2ray: CheckBox
    private lateinit var connectBtn: Button
    private lateinit var statusSubText: TextView
    private lateinit var activeModeHint: TextView

    // Log Tab Views
    private lateinit var logBox: TextView

    // Stored feature parameters (editable via clean dialogs)
    private var payloadText = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]"
    private var proxyHost = ""
    private var proxyPort = 80
    private var sniHost = ""
    private var customDns1 = "1.1.1.1"
    private var customDns2 = "8.8.8.8"
    private var dnsttNs = ""
    private var dnsttPubKey = ""
    private var dnsResolver = "1.1.1.1:53"
    private var dnsttMtu = 1232
    private var v2rayProto = "vless"
    private var v2rayHost = ""
    private var v2rayPort = 443
    private var v2rayUuid = ""
    private var v2rayNet = "ws"
    private var v2rayPath = "/"
    private var v2raySni = ""
    private var v2raySecurity = "tls"
    private var v2rayFlow = ""
    private var v2rayFp = "chrome"
    private var v2rayPbk = ""
    private var v2raySid = ""
    private var v2raySpx = "/"
    private var v2rayTls = true
    private var enableShareNet = false
    private var enableUdpGw = true
    private var udpGwPort = 7300

    private var isScreenVisible = true
    private val logBuffer = LinkedList<String>()
    private var isProfileLocked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildHttpCustomUi())
        loadSavedSettings()
        updateActiveModeSummary()

        LiteVpnService.statusListener = { state, detail ->
            runOnUiThread {
                statusSubText.text = "$state • $detail"
                when (state) {
                    "CONNECTED" -> {
                        statusSubText.setTextColor(colorTeal)
                        connectBtn.text = "DISCONNECT"
                        connectBtn.background = makeButtonDrawable(Color.parseColor("#26161B"), Color.parseColor("#FF5252"))
                    }
                    "CONNECTING", "RECONNECTING" -> {
                        statusSubText.setTextColor(Color.parseColor("#FFD54F"))
                        connectBtn.text = "STOP"
                        connectBtn.background = makeButtonDrawable(colorButtonFill, Color.parseColor("#FFD54F"))
                    }
                    else -> {
                        statusSubText.setTextColor(colorTextMuted)
                        connectBtn.text = "CONNECT"
                        connectBtn.background = makeButtonDrawable(colorButtonFill, colorTeal)
                    }
                }
            }
        }

        LiteVpnService.logListener = { line ->
            val ts = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
            synchronized(logBuffer) {
                if (logBuffer.size >= 120) logBuffer.removeFirst()
                logBuffer.addLast("[$ts] $line")
            }
            if (isScreenVisible) {
                runOnUiThread { refreshLogView() }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        isScreenVisible = true
        refreshLogView()
    }

    override fun onPause() {
        super.onPause()
        isScreenVisible = false
        saveCurrentSettings()
    }

    private fun buildHttpCustomUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(colorBgDark)
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        // Top App Bar (Title + [+] Import/Export + [⋮] Settings Menu)
        val appBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(colorHeaderDark)
            setPadding(dp(16), dp(12), dp(12), dp(10))
        }
        val titleView = TextView(this).apply {
            text = "HTTP Custom"
            textSize = 19f
            setTypeface(null, Typeface.BOLD)
            setTextColor(colorTextWhite)
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        val btnPlus = makeTopActionBtn("＋") { showOpenSaveMenu() }
        val btnMenu = makeTopActionBtn("⚙") { showPluginSettingsMenu() }
        appBar.addView(titleView)
        appBar.addView(btnPlus)
        appBar.addView(btnMenu)
        root.addView(appBar)

        // Two-Tab Bar: SSH | LOG (exact match to screenshot)
        val tabBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(colorHeaderDark)
        }

        val tabSshCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { switchTab(isSsh = true) }
        }
        tabSshText = TextView(this).apply {
            text = "SSH"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(colorTextWhite)
            gravity = Gravity.CENTER
            setPadding(0, dp(12), 0, dp(12))
        }
        tabSshIndicator = View(this).apply {
            setBackgroundColor(colorTeal)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(3))
        }
        tabSshCol.addView(tabSshText)
        tabSshCol.addView(tabSshIndicator)

        val tabLogCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { switchTab(isSsh = false) }
        }
        tabLogText = TextView(this).apply {
            text = "LOG"
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(colorTextMuted)
            gravity = Gravity.CENTER
            setPadding(0, dp(12), 0, dp(12))
        }
        tabLogIndicator = View(this).apply {
            setBackgroundColor(Color.TRANSPARENT)
            layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(3))
        }
        tabLogCol.addView(tabLogText)
        tabLogCol.addView(tabLogIndicator)

        tabBar.addView(tabSshCol)
        tabBar.addView(tabLogCol)
        root.addView(tabBar)

        // ==================== PAGE 1: SSH TAB ====================
        sshPageContainer = ScrollView(this).apply {
            setBackgroundColor(colorBgDark)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        val sshContent = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(26), dp(20), dp(24))
        }

        // Single clean underlined input: ip:port@user:pass (supports multi-port e.g. ip:22,80,443@user:pass)
        serverInput = EditText(this).apply {
            hint = "ip:port@user:pass"
            setHintTextColor(colorTextMuted)
            setTextColor(colorTextWhite)
            textSize = 16f
            setSingleLine(true)
            backgroundTintList = ColorStateList.valueOf(colorTextMuted)
            setPadding(dp(4), dp(8), dp(4), dp(12))
        }
        sshContent.addView(serverInput)

        // 2-Column x 4-Row Checkbox Grid (exact match to screenshot)
        val gridContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(18), 0, dp(14))
        }

        chkUsePayload = makeHcCheckBox("Use Payload", false) {
            updateActiveModeSummary()
        }
        chkSsl = makeHcCheckBox("SSL", false) {
            updateActiveModeSummary()
        }
        chkEnableDns = makeHcCheckBox("Enable DNS", true) {
            updateActiveModeSummary()
        }
        chkSlowDns = makeHcCheckBox("SlowDns", false) {
            updateActiveModeSummary()
        }
        chkAutoReplace = makeHcCheckBox("Auto Replace", true) {
            updateActiveModeSummary()
        }
        chkWakeLock = makeHcCheckBox("WakeLock", true) {
            updateActiveModeSummary()
        }
        chkPsiphon = makeHcCheckBox("Psiphon", false) {
            updateActiveModeSummary()
        }
        chkV2ray = makeHcCheckBox("V2ray", false) {
            updateActiveModeSummary()
        }

        gridContainer.addView(makeCheckboxRow(chkUsePayload, chkSsl))
        gridContainer.addView(makeCheckboxRow(chkEnableDns, chkSlowDns))
        gridContainer.addView(makeCheckboxRow(chkAutoReplace, chkWakeLock))
        gridContainer.addView(makeCheckboxRow(chkPsiphon, chkV2ray))
        sshContent.addView(gridContainer)

        // Full-Width Teal-Bordered CONNECT Button (exact match to screenshot)
        connectBtn = Button(this).apply {
            text = "CONNECT"
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.WHITE)
            background = makeButtonDrawable(colorButtonFill, colorTeal)
            setPadding(0, dp(14), 0, dp(14))
            setOnClickListener { toggleConnection() }
        }
        val connectParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT
        ).apply {
            topMargin = dp(6)
            bottomMargin = dp(14)
        }
        sshContent.addView(connectBtn, connectParams)

        // Status & Active Pipeline Indicator
        statusSubText = TextView(this).apply {
            text = "DISCONNECTED • Ready"
            textSize = 13f
            setTextColor(colorTextMuted)
            gravity = Gravity.CENTER
            setPadding(0, dp(4), 0, dp(4))
        }
        sshContent.addView(statusSubText)

        activeModeHint = TextView(this).apply {
            text = "Mode: Direct SSH (All Ports)"
            textSize = 12f
            setTextColor(colorTeal)
            gravity = Gravity.CENTER
            setPadding(0, dp(2), 0, dp(16))
        }
        sshContent.addView(activeModeHint)

        // Quick Configuration Chips Row (1-tap access to Payload, SSL/SNI, SlowDNS, V2Ray, DNS, Hotspot)
        val quickLabel = TextView(this).apply {
            text = "QUICK SETTINGS (TAP TO CONFIGURE)"
            textSize = 11f
            setTypeface(null, Typeface.BOLD)
            setTextColor(colorTextMuted)
            setPadding(0, dp(6), 0, dp(8))
        }
        sshContent.addView(quickLabel)

        val chipRow1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        chipRow1.addView(makeConfigChip("Payload") { showPayloadDialog() })
        chipRow1.addView(makeConfigChip("SSL / SNI") { showSslSniDialog() })
        chipRow1.addView(makeConfigChip("SlowDNS") { showSlowDnsDialog() })
        sshContent.addView(chipRow1)

        val chipRow2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(8), 0, 0)
        }
        chipRow2.addView(makeConfigChip("V2Ray Config") { showV2RayDialog() })
        chipRow2.addView(makeConfigChip("Custom DNS") { showDnsDialog() })
        chipRow2.addView(makeConfigChip("Hotspot / UDP") { showShareNetDialog() })
        sshContent.addView(chipRow2)

        sshPageContainer.addView(sshContent)
        root.addView(sshPageContainer)

        // ==================== PAGE 2: LOG TAB ====================
        logPageContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
            setBackgroundColor(colorBgDark)
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
        }

        val logToolbar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
            setPadding(dp(12), dp(8), dp(12), dp(4))
        }
        val btnCopyLog = makeConfigChip("Copy Logs") {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("logs", logBox.text))
            Toast.makeText(this, "Logs copied", Toast.LENGTH_SHORT).show()
        }.apply { layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { rightMargin = dp(8) } }

        val btnClearLog = makeConfigChip("Clear") {
            synchronized(logBuffer) { logBuffer.clear() }
            refreshLogView()
        }.apply { layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT) }

        logToolbar.addView(btnCopyLog)
        logToolbar.addView(btnClearLog)
        logPageContainer.addView(logToolbar)

        val logScroll = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                0,
                1f
            )
            setPadding(dp(14), dp(6), dp(14), dp(14))
        }
        logBox = TextView(this).apply {
            text = "HTTP Custom Lite Ready.\nTip: Enable both [V2ray] + [SlowDns] to tunnel V2Ray over SlowDNS.\n"
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(colorTextWhite)
        }
        logScroll.addView(logBox)
        logPageContainer.addView(logScroll)
        root.addView(logPageContainer)

        return root
    }

    private fun switchTab(isSsh: Boolean) {
        if (isSsh) {
            sshPageContainer.visibility = View.VISIBLE
            logPageContainer.visibility = View.GONE
            tabSshText.setTextColor(colorTextWhite)
            tabSshIndicator.setBackgroundColor(colorTeal)
            tabLogText.setTextColor(colorTextMuted)
            tabLogIndicator.setBackgroundColor(Color.TRANSPARENT)
        } else {
            sshPageContainer.visibility = View.GONE
            logPageContainer.visibility = View.VISIBLE
            tabSshText.setTextColor(colorTextMuted)
            tabSshIndicator.setBackgroundColor(Color.TRANSPARENT)
            tabLogText.setTextColor(colorTextWhite)
            tabLogIndicator.setBackgroundColor(colorTeal)
            refreshLogView()
        }
    }

    private fun updateActiveModeSummary() {
        val parts = mutableListOf<String>()
        if (chkV2ray.isChecked && chkSlowDns.isChecked) {
            parts.add("V2Ray over SlowDNS (Chained)")
        } else if (chkV2ray.isChecked) {
            parts.add("V2Ray (${v2rayProto.uppercase()} ${v2rayNet.uppercase()})")
        } else {
            parts.add("SSH (All Ports)")
            if (chkUsePayload.isChecked) parts.add("Payload")
            if (chkSsl.isChecked) parts.add("SSL/SNI")
            if (chkSlowDns.isChecked) parts.add("SlowDNS")
        }
        if (chkEnableDns.isChecked) parts.add("DNS ($customDns1)")
        if (enableShareNet) parts.add("Hotspot Proxy")
        activeModeHint.text = "Active Pipeline: " + parts.joinToString(" + ")
    }

    private fun makeCheckboxRow(left: CheckBox, right: CheckBox): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dp(6), 0, dp(6))
            addView(left, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(right, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
    }

    private fun makeHcCheckBox(label: String, defaultChecked: Boolean, onChanged: () -> Unit): CheckBox {
        return CheckBox(this).apply {
            text = "  $label"
            isChecked = defaultChecked
            textSize = 15f
            setTextColor(colorTextWhite)
            val states = arrayOf(
                intArrayOf(android.R.attr.state_checked),
                intArrayOf(-android.R.attr.state_checked)
            )
            val colors = intArrayOf(colorTeal, colorTextMuted)
            buttonTintList = ColorStateList(states, colors)
            setOnCheckedChangeListener { _, _ -> onChanged() }
        }
    }

    private fun makeButtonDrawable(fillColor: Int, strokeColor: Int): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(4).toFloat()
            setColor(fillColor)
            setStroke(dp(2), strokeColor)
        }
    }

    private fun makeTopActionBtn(symbol: String, onClick: () -> Unit): TextView {
        return TextView(this).apply {
            text = symbol
            textSize = 20f
            setTextColor(colorTextWhite)
            setPadding(dp(12), dp(4), dp(12), dp(4))
            setOnClickListener { onClick() }
        }
    }

    private fun makeConfigChip(label: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = label
            textSize = 11f
            isAllCaps = false
            setTextColor(colorTextWhite)
            background = makeButtonDrawable(Color.parseColor("#1B2024"), Color.parseColor("#37474F"))
            setPadding(dp(8), dp(6), dp(8), dp(6))
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                rightMargin = dp(6)
            }
            setOnClickListener { onClick() }
        }
    }

    // ==================== DIALOGS FOR ALL FEATURES ====================

    private fun showPluginSettingsMenu() {
        val items = arrayOf(
            "1. Payload Settings & Payload Generator",
            "2. SSL / TLS SNI Bug Host",
            "3. SlowDNS (DNSTT) Settings",
            "4. V2Ray (VLESS / VMess / Trojan) Settings",
            "5. Custom DNS Settings",
            "6. ShareNet Hotspot & UDPGW (7300)"
        )
        AlertDialog.Builder(this)
            .setTitle("Tunnel Settings")
            .setItems(items) { _, which ->
                when (which) {
                    0 -> showPayloadDialog()
                    1 -> showSslSniDialog()
                    2 -> showSlowDnsDialog()
                    3 -> showV2RayDialog()
                    4 -> showDnsDialog()
                    5 -> showShareNetDialog()
                }
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showPayloadDialog() {
        if (isProfileLocked) {
            Toast.makeText(this, "Profile is locked", Toast.LENGTH_SHORT).show()
            return
        }
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(12), dp(18), dp(8))
        }
        val pBox = EditText(this).apply {
            hint = "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
            setText(payloadText)
            minLines = 4
        }
        val proxyBox = EditText(this).apply {
            hint = "Optional Remote Proxy (host:port) or leave blank"
            setText(if (proxyHost.isNotEmpty()) "$proxyHost:$proxyPort" else "")
        }
        val bugHostGen = EditText(this).apply {
            hint = "Quick Generate: Enter Bug Host (e.g. cdn.operator.com)"
        }
        val chkSplitGen = CheckBox(this).apply { text = "Include [split] fragmentation" }

        layout.addView(makeDialogLabel("HTTP / WebSocket Payload"))
        layout.addView(pBox)
        layout.addView(makeDialogLabel("Remote Proxy (Optional)"))
        layout.addView(proxyBox)
        layout.addView(makeDialogLabel("Quick Payload Generator"))
        layout.addView(bugHostGen)
        layout.addView(chkSplitGen)

        AlertDialog.Builder(this)
            .setTitle("Payload & Proxy Settings")
            .setView(layout)
            .setPositiveButton("Save") { _, _ ->
                payloadText = pBox.text.toString()
                val rawProxy = proxyBox.text.toString().trim()
                if (rawProxy.contains(":")) {
                    val hp = rawProxy.split(":")
                    proxyHost = hp[0]
                    proxyPort = hp[1].toIntOrNull() ?: 80
                } else {
                    proxyHost = rawProxy
                }
                chkUsePayload.isChecked = payloadText.isNotBlank()
                saveCurrentSettings()
            }
            .setNeutralButton("Generate Payload") { _, _ ->
                val bh = bugHostGen.text.toString().trim().ifEmpty { "[host]" }
                val prefix = if (chkSplitGen.isChecked) "GET / HTTP/1.1[crlf][split]" else "GET / HTTP/1.1[crlf]"
                payloadText = "${prefix}Host: $bh[crlf]Upgrade: websocket[crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]"
                chkUsePayload.isChecked = true
                saveCurrentSettings()
                Toast.makeText(this, "WebSocket Payload Generated!", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showSslSniDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(12), dp(18), dp(8))
        }
        val sniBox = EditText(this).apply {
            hint = "SNI / Bug Host (e.g. bug.operator.com)"
            setText(sniHost)
        }
        layout.addView(makeDialogLabel("SSL / TLS Server Name Indication (SNI)"))
        layout.addView(sniBox)

        AlertDialog.Builder(this)
            .setTitle("SSL / SNI Settings")
            .setView(layout)
            .setPositiveButton("Save") { _, _ ->
                sniHost = sniBox.text.toString().trim()
                if (sniHost.isNotEmpty()) chkSsl.isChecked = true
                saveCurrentSettings()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showSlowDnsDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(12), dp(18), dp(8))
        }
        val nsBox = EditText(this).apply {
            hint = "Nameserver (e.g. ns.xtescomobile.com)"
            setText(dnsttNs)
        }
        val pubBox = EditText(this).apply {
            hint = "DNSTT Public Key (Hex or Base64)"
            setText(dnsttPubKey)
        }
        val resBox = EditText(this).apply {
            hint = "DNS Resolver (e.g. 1.1.1.1:53 or 8.8.8.8:53)"
            setText(dnsResolver)
        }
        val mtuBox = EditText(this).apply {
            hint = "MTU (Default 1232)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(dnsttMtu.toString())
        }

        layout.addView(makeDialogLabel("SlowDNS Nameserver (NS)"))
        layout.addView(nsBox)
        layout.addView(makeDialogLabel("Public Key"))
        layout.addView(pubBox)
        layout.addView(makeDialogLabel("DNS Server / Resolver"))
        layout.addView(resBox)
        layout.addView(makeDialogLabel("DNSTT MTU"))
        layout.addView(mtuBox)

        AlertDialog.Builder(this)
            .setTitle("SlowDNS (DNSTT) Settings")
            .setView(layout)
            .setPositiveButton("Save") { _, _ ->
                dnsttNs = nsBox.text.toString().trim()
                dnsttPubKey = pubBox.text.toString().trim()
                dnsResolver = resBox.text.toString().trim().ifEmpty { "1.1.1.1:53" }
                dnsttMtu = mtuBox.text.toString().toIntOrNull() ?: 1232
                if (dnsttNs.isNotEmpty()) chkSlowDns.isChecked = true
                saveCurrentSettings()
                updateActiveModeSummary()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showV2RayDialog() {
        val scroll = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(12), dp(18), dp(8))
        }

        val uriPasteBox = EditText(this).apply {
            hint = "Paste vless://, vmess://, or trojan:// link here"
            minLines = 2
        }
        val protoSpinner = Spinner(this).apply {
            val protos = arrayOf("vless", "vmess", "trojan")
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, protos)
            setSelection(protos.indexOf(v2rayProto).coerceAtLeast(0))
        }
        val hostBox = EditText(this).apply {
            hint = "V2Ray Server Host / IP"
            setText(v2rayHost)
        }
        val portBox = EditText(this).apply {
            hint = "Port (e.g. 443, 80, 2053)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(v2rayPort.toString())
        }
        val uuidBox = EditText(this).apply {
            hint = "UUID or Trojan Password"
            setText(v2rayUuid)
        }
        val netBox = EditText(this).apply {
            hint = "Transport: ws, tcp, grpc, httpupgrade"
            setText(v2rayNet)
        }
        val pathBox = EditText(this).apply {
            hint = "WS Path (/vless) or gRPC serviceName"
            setText(v2rayPath)
        }
        val secBox = EditText(this).apply {
            hint = "Security: tls, reality, or none"
            setText(v2raySecurity)
        }
        val flowBox = EditText(this).apply {
            hint = "XTLS Flow (e.g. xtls-rprx-vision or blank)"
            setText(v2rayFlow)
        }
        val sniBox = EditText(this).apply {
            hint = "SNI / Bug Host (e.g. www.microsoft.com)"
            setText(v2raySni)
        }
        val pbkBox = EditText(this).apply {
            hint = "Reality Public Key (pbk)"
            setText(v2rayPbk)
        }
        val sidBox = EditText(this).apply {
            hint = "Reality ShortId (sid)"
            setText(v2raySid)
        }
        val fpBox = EditText(this).apply {
            hint = "uTLS Fingerprint (chrome, firefox, ios)"
            setText(v2rayFp)
        }

        layout.addView(makeDialogLabel("Import vless://, vmess://, trojan:// (Reality/XTLS/gRPC)"))
        layout.addView(uriPasteBox)
        layout.addView(makeDialogLabel("Protocol"))
        layout.addView(protoSpinner)
        layout.addView(makeDialogLabel("Server Address & Port"))
        layout.addView(hostBox)
        layout.addView(portBox)
        layout.addView(makeDialogLabel("UUID / Password"))
        layout.addView(uuidBox)
        layout.addView(makeDialogLabel("Transport (ws / tcp / grpc) & Path / serviceName"))
        layout.addView(netBox)
        layout.addView(pathBox)
        layout.addView(makeDialogLabel("Security (tls / reality / none) & XTLS Flow"))
        layout.addView(secBox)
        layout.addView(flowBox)
        layout.addView(makeDialogLabel("SNI & Reality (pbk / sid / fp)"))
        layout.addView(sniBox)
        layout.addView(pbkBox)
        layout.addView(sidBox)
        layout.addView(fpBox)
        scroll.addView(layout)

        AlertDialog.Builder(this)
            .setTitle("V2Ray / Xray Settings")
            .setView(scroll)
            .setPositiveButton("Save") { _, _ ->
                val pasted = uriPasteBox.text.toString().trim()
                val parsed = if (pasted.isNotEmpty()) TunnelEngine.parseV2RayLink(pasted) else null
                if (parsed != null) {
                    v2rayProto = parsed.optString("v2ray_proto", "vless")
                    v2rayHost = parsed.optString("v2ray_host", "")
                    v2rayPort = parsed.optInt("v2ray_port", 443)
                    v2rayUuid = parsed.optString("v2ray_uuid", "")
                    v2rayNet = parsed.optString("v2ray_net", "ws")
                    v2rayPath = parsed.optString("v2ray_path", "/")
                    v2raySni = parsed.optString("v2ray_sni", "")
                    v2raySecurity = parsed.optString("v2ray_security", "tls")
                    v2rayFlow = parsed.optString("v2ray_flow", "")
                    v2rayFp = parsed.optString("v2ray_fp", "chrome")
                    v2rayPbk = parsed.optString("v2ray_pbk", "")
                    v2raySid = parsed.optString("v2ray_sid", "")
                    v2raySpx = parsed.optString("v2ray_spx", "/")
                    v2rayTls = v2raySecurity != "none"
                    Toast.makeText(this, "Imported $v2rayProto ($v2rayNet/$v2raySecurity)", Toast.LENGTH_SHORT).show()
                } else {
                    v2rayProto = protoSpinner.selectedItem.toString()
                    v2rayHost = hostBox.text.toString().trim()
                    v2rayPort = portBox.text.toString().toIntOrNull() ?: 443
                    v2rayUuid = uuidBox.text.toString().trim()
                    v2rayNet = netBox.text.toString().trim().ifEmpty { "ws" }
                    v2rayPath = pathBox.text.toString().trim().ifEmpty { "/" }
                    v2raySecurity = secBox.text.toString().trim().ifEmpty { "tls" }
                    v2rayFlow = flowBox.text.toString().trim()
                    v2raySni = sniBox.text.toString().trim()
                    v2rayPbk = pbkBox.text.toString().trim()
                    v2raySid = sidBox.text.toString().trim()
                    v2rayFp = fpBox.text.toString().trim().ifEmpty { "chrome" }
                    v2rayTls = v2raySecurity != "none"
                }
                chkV2ray.isChecked = true
                saveCurrentSettings()
                updateActiveModeSummary()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showDnsDialog() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(12), dp(18), dp(8))
        }
        val d1 = EditText(this).apply {
            hint = "Primary DNS (e.g. 1.1.1.1)"
            setText(customDns1)
        }
        val d2 = EditText(this).apply {
            hint = "Secondary DNS (e.g. 8.8.8.8)"
            setText(customDns2)
        }
        layout.addView(makeDialogLabel("Primary DNS Server"))
        layout.addView(d1)
        layout.addView(makeDialogLabel("Secondary DNS Server"))
        layout.addView(d2)

        AlertDialog.Builder(this)
            .setTitle("Custom DNS Settings")
            .setView(layout)
            .setPositiveButton("Save") { _, _ ->
                customDns1 = d1.text.toString().trim().ifEmpty { "1.1.1.1" }
                customDns2 = d2.text.toString().trim().ifEmpty { "8.8.8.8" }
                chkEnableDns.isChecked = true
                saveCurrentSettings()
                updateActiveModeSummary()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showShareNetDialog() {
        val ip = LiteVpnService.getHotspotIpAddress()
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(12), dp(18), dp(8))
        }
        val chkShare = CheckBox(this).apply {
            text = "Enable ShareNet Hotspot Proxy ($ip:8080 & SOCKS5 $ip:10808)"
            isChecked = enableShareNet
        }
        val chkUdp = CheckBox(this).apply {
            text = "Enable BadVPN UDPGW"
            isChecked = enableUdpGw
        }
        val udpPortBox = EditText(this).apply {
            hint = "UDPGW Port (Default 7300)"
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(udpGwPort.toString())
        }
        layout.addView(chkShare)
        layout.addView(chkUdp)
        layout.addView(makeDialogLabel("UDPGW Port"))
        layout.addView(udpPortBox)

        AlertDialog.Builder(this)
            .setTitle("Hotspot ShareNet & UDPGW")
            .setView(layout)
            .setPositiveButton("Save") { _, _ ->
                enableShareNet = chkShare.isChecked
                enableUdpGw = chkUdp.isChecked
                udpGwPort = udpPortBox.text.toString().toIntOrNull() ?: 7300
                saveCurrentSettings()
                updateActiveModeSummary()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showOpenSaveMenu() {
        val options = arrayOf(
            "Import Config (.klite / klite://)",
            "Export Locked Config (.klite)",
            "Paste V2Ray Link from Clipboard",
            "Reset / Clear Config"
        )
        AlertDialog.Builder(this)
            .setTitle("Config Manager")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> showImportExportDialog(false)
                    1 -> showImportExportDialog(true)
                    2 -> {
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = cm.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
                        val parsed = TunnelEngine.parseV2RayLink(clip)
                        if (parsed != null) {
                            v2rayProto = parsed.optString("v2ray_proto", "vless")
                            v2rayHost = parsed.optString("v2ray_host", "")
                            v2rayPort = parsed.optInt("v2ray_port", 443)
                            v2rayUuid = parsed.optString("v2ray_uuid", "")
                            v2rayNet = parsed.optString("v2ray_net", "ws")
                            v2rayPath = parsed.optString("v2ray_path", "/")
                            v2raySni = parsed.optString("v2ray_sni", "")
                            v2raySecurity = parsed.optString("v2ray_security", "tls")
                            v2rayFlow = parsed.optString("v2ray_flow", "")
                            v2rayFp = parsed.optString("v2ray_fp", "chrome")
                            v2rayPbk = parsed.optString("v2ray_pbk", "")
                            v2raySid = parsed.optString("v2ray_sid", "")
                            v2raySpx = parsed.optString("v2ray_spx", "/")
                            v2rayTls = v2raySecurity != "none" 
                            chkV2ray.isChecked = true
                            saveCurrentSettings()
                            updateActiveModeSummary()
                            Toast.makeText(this, "Imported V2Ray ($v2rayHost:$v2rayPort)", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this, "No valid vless/vmess/trojan link in clipboard", Toast.LENGTH_SHORT).show()
                        }
                    }
                    3 -> {
                        isProfileLocked = false
                        serverInput.isEnabled = true
                        serverInput.setText("")
                        Toast.makeText(this, "Config cleared", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .show()
    }

    private fun toggleConnection() {
        if (LiteVpnService.isRunning) {
            val stopIntent = Intent(this, LiteVpnService::class.java).apply {
                action = LiteVpnService.ACTION_STOP
            }
            startService(stopIntent)
            return
        }
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, 1001)
        } else {
            onActivityResult(1001, RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001 && resultCode == RESULT_OK) {
            saveCurrentSettings()
            val cfgJson = buildConfigJson().toString()
            val startIntent = Intent(this, LiteVpnService::class.java).apply {
                action = LiteVpnService.ACTION_START
                putExtra(LiteVpnService.EXTRA_CONFIG_JSON, cfgJson)
            }
            startService(startIntent)
            switchTab(isSsh = false)
        }
    }

    private fun buildConfigJson(): JSONObject {
        val rawServer = serverInput.text.toString().trim()
        var host = "127.0.0.1"
        var portsStr = "22,80,443"
        var user = "root"
        var pass = ""

        if (rawServer.contains("@")) {
            val parts = rawServer.split("@", limit = 2)
            val hp = parts[0].split(":", limit = 2)
            host = hp[0]
            if (hp.size > 1 && hp[1].isNotEmpty()) portsStr = hp[1]
            val up = parts[1].split(":", limit = 2)
            user = up[0]
            if (up.size > 1) pass = up[1]
        } else if (rawServer.contains(":")) {
            val hp = rawServer.split(":", limit = 2)
            host = hp[0]
            if (hp[1].isNotEmpty()) portsStr = hp[1]
        } else if (rawServer.isNotEmpty()) {
            host = rawServer
        }

        val firstPort = portsStr.split(",").firstOrNull()?.trim()?.toIntOrNull() ?: 22

        return JSONObject().apply {
            put("server_host", host)
            put("server_port", firstPort)
            put("server_ports", portsStr)
            put("ssh_user", user)
            put("ssh_pass", pass)

            // 8 HTTP Custom Checkboxes
            put("use_payload", chkUsePayload.isChecked)
            put("use_ssl", chkSsl.isChecked)
            put("use_dns", chkEnableDns.isChecked)
            put("use_slowdns", chkSlowDns.isChecked)
            put("auto_replace", chkAutoReplace.isChecked)
            put("use_wakelock", chkWakeLock.isChecked)
            put("use_psiphon", chkPsiphon.isChecked)
            put("use_v2ray", chkV2ray.isChecked)

            // Payload & Proxy
            put("payload", payloadText)
            put("proxy_host", proxyHost)
            put("proxy_port", proxyPort)
            put("sni", sniHost)

            // DNS
            put("custom_dns", customDns1)
            put("custom_dns_secondary", customDns2)

            // SlowDNS
            put("dnstt_ns", dnsttNs)
            put("dnstt_pubkey", dnsttPubKey)
            put("dns_resolver", dnsResolver)
            put("dnstt_mtu", dnsttMtu)

            // V2Ray (works standalone OR chained with SlowDNS when both are checked)
            put("v2ray_proto", v2rayProto)
            put("v2ray_host", v2rayHost.ifEmpty { host })
            put("v2ray_port", v2rayPort)
            put("v2ray_uuid", v2rayUuid)
            put("v2ray_net", v2rayNet)
            put("v2ray_path", v2rayPath)
            put("v2ray_sni", v2raySni.ifEmpty { sniHost })
            put("v2ray_security", v2raySecurity)
            put("v2ray_flow", v2rayFlow)
            put("v2ray_fp", v2rayFp)
            put("v2ray_pbk", v2rayPbk)
            put("v2ray_sid", v2raySid)
            put("v2ray_spx", v2raySpx)
            put("v2ray_tls", v2rayTls)

            // ShareNet & UDPGW
            put("enable_sharenet", enableShareNet)
            put("sharenet_http_port", 8080)
            put("sharenet_socks_port", 10808)
            put("enable_udpgw", enableUdpGw)
            put("udpgw_port", udpGwPort)
            put("keepalive_sec", 45)
        }
    }

    private fun showImportExportDialog(isExport: Boolean) {
        val box = EditText(this).apply {
            minLines = 4
            hint = if (isExport) "Encrypted .klite token" else "Paste klite:// token"
        }
        if (isExport) {
            val cfg = buildConfigJson().apply { put("locked", true) }
            box.setText("klite://" + encryptConfig(cfg.toString()))
        }
        AlertDialog.Builder(this)
            .setTitle(if (isExport) "Export Locked Profile (.klite)" else "Import Profile (.klite)")
            .setView(box)
            .setPositiveButton(if (isExport) "Copy" else "Import") { _, _ ->
                val raw = box.text.toString().trim()
                if (isExport) {
                    val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    cm.setPrimaryClip(ClipData.newPlainText("klite", raw))
                    Toast.makeText(this, "Copied to clipboard!", Toast.LENGTH_SHORT).show()
                } else if (raw.startsWith("klite://")) {
                    try {
                        val jsonStr = decryptConfig(raw.removePrefix("klite://"))
                        applyImportedConfig(JSONObject(jsonStr))
                        Toast.makeText(this, "Profile imported!", Toast.LENGTH_SHORT).show()
                    } catch (_: Exception) {
                        Toast.makeText(this, "Invalid .klite token", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun applyImportedConfig(cfg: JSONObject) {
        val locked = cfg.optBoolean("locked", false)
        isProfileLocked = locked
        serverInput.setText(
            "${cfg.optString("server_host")}:${cfg.optString("server_ports", "22")}@${cfg.optString("ssh_user")}:${cfg.optString("ssh_pass")}"
        )
        chkUsePayload.isChecked = cfg.optBoolean("use_payload", false)
        chkSsl.isChecked = cfg.optBoolean("use_ssl", false)
        chkEnableDns.isChecked = cfg.optBoolean("use_dns", true)
        chkSlowDns.isChecked = cfg.optBoolean("use_slowdns", false)
        chkAutoReplace.isChecked = cfg.optBoolean("auto_replace", true)
        chkWakeLock.isChecked = cfg.optBoolean("use_wakelock", true)
        chkPsiphon.isChecked = cfg.optBoolean("use_psiphon", false)
        chkV2ray.isChecked = cfg.optBoolean("use_v2ray", false)

        payloadText = cfg.optString("payload", payloadText)
        sniHost = cfg.optString("sni", "")
        dnsttNs = cfg.optString("dnstt_ns", "")
        dnsttPubKey = cfg.optString("dnstt_pubkey", "")
        dnsResolver = cfg.optString("dns_resolver", "1.1.1.1:53")
        v2rayProto = cfg.optString("v2ray_proto", "vless")
        v2rayHost = cfg.optString("v2ray_host", "")
        v2rayPort = cfg.optInt("v2ray_port", 443)
        v2rayUuid = cfg.optString("v2ray_uuid", "")
        v2rayNet = cfg.optString("v2ray_net", "ws")
        v2rayPath = cfg.optString("v2ray_path", "/")
        v2raySni = cfg.optString("v2ray_sni", "")
        v2raySecurity = cfg.optString("v2ray_security", "tls")
        v2rayFlow = cfg.optString("v2ray_flow", "")
        v2rayFp = cfg.optString("v2ray_fp", "chrome")
        v2rayPbk = cfg.optString("v2ray_pbk", "")
        v2raySid = cfg.optString("v2ray_sid", "")
        v2raySpx = cfg.optString("v2ray_spx", "/")
        v2rayTls = cfg.optBoolean("v2ray_tls", true)

        if (locked) {
            serverInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            serverInput.isEnabled = false
        }
        updateActiveModeSummary()
    }

    private fun encryptConfig(plain: String): String {
        val key = SecretKeySpec("KurdoLiteKey2026".toByteArray(Charsets.UTF_8), "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return Base64.encodeToString(cipher.doFinal(plain.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    private fun decryptConfig(enc: String): String {
        val key = SecretKeySpec("KurdoLiteKey2026".toByteArray(Charsets.UTF_8), "AES")
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return String(cipher.doFinal(Base64.decode(enc, Base64.NO_WRAP)), Charsets.UTF_8)
    }

    private fun refreshLogView() {
        val text = synchronized(logBuffer) {
            if (logBuffer.isEmpty()) "HTTP Custom Lite Ready.\nTip: Check both [V2ray] and [SlowDns] to tunnel V2Ray over SlowDNS."
            else logBuffer.joinToString("\n")
        }
        logBox.text = text
    }

    private fun saveCurrentSettings() {
        if (isProfileLocked) return
        getSharedPreferences("kurdolite_hc_prefs", Context.MODE_PRIVATE).edit().apply {
            putString("server", serverInput.text.toString())
            putBoolean("use_payload", chkUsePayload.isChecked)
            putBoolean("use_ssl", chkSsl.isChecked)
            putBoolean("use_dns", chkEnableDns.isChecked)
            putBoolean("use_slowdns", chkSlowDns.isChecked)
            putBoolean("auto_replace", chkAutoReplace.isChecked)
            putBoolean("use_wakelock", chkWakeLock.isChecked)
            putBoolean("use_psiphon", chkPsiphon.isChecked)
            putBoolean("use_v2ray", chkV2ray.isChecked)
            putString("payload", payloadText)
            putString("proxy_host", proxyHost)
            putInt("proxy_port", proxyPort)
            putString("sni", sniHost)
            putString("dns1", customDns1)
            putString("dns2", customDns2)
            putString("dnstt_ns", dnsttNs)
            putString("dnstt_pub", dnsttPubKey)
            putString("dns_res", dnsResolver)
            putInt("dnstt_mtu", dnsttMtu)
            putString("v2_proto", v2rayProto)
            putString("v2_host", v2rayHost)
            putInt("v2_port", v2rayPort)
            putString("v2_uuid", v2rayUuid)
            putString("v2_net", v2rayNet)
            putString("v2_path", v2rayPath)
            putString("v2_sni", v2raySni)
            putString("v2_sec", v2raySecurity)
            putString("v2_flow", v2rayFlow)
            putString("v2_fp", v2rayFp)
            putString("v2_pbk", v2rayPbk)
            putString("v2_sid", v2raySid)
            putString("v2_spx", v2raySpx)
            putBoolean("v2_tls", v2rayTls)
            putBoolean("sharenet", enableShareNet)
            apply()
        }
    }

    private fun loadSavedSettings() {
        val sp = getSharedPreferences("kurdolite_hc_prefs", Context.MODE_PRIVATE)
        serverInput.setText(sp.getString("server", ""))
        chkUsePayload.isChecked = sp.getBoolean("use_payload", false)
        chkSsl.isChecked = sp.getBoolean("use_ssl", false)
        chkEnableDns.isChecked = sp.getBoolean("use_dns", true)
        chkSlowDns.isChecked = sp.getBoolean("use_slowdns", false)
        chkAutoReplace.isChecked = sp.getBoolean("auto_replace", true)
        chkWakeLock.isChecked = sp.getBoolean("use_wakelock", true)
        chkPsiphon.isChecked = sp.getBoolean("use_psiphon", false)
        chkV2ray.isChecked = sp.getBoolean("use_v2ray", false)
        payloadText = sp.getString("payload", payloadText) ?: payloadText
        proxyHost = sp.getString("proxy_host", "") ?: ""
        proxyPort = sp.getInt("proxy_port", 80)
        sniHost = sp.getString("sni", "") ?: ""
        customDns1 = sp.getString("dns1", "1.1.1.1") ?: "1.1.1.1"
        customDns2 = sp.getString("dns2", "8.8.8.8") ?: "8.8.8.8"
        dnsttNs = sp.getString("dnstt_ns", "") ?: ""
        dnsttPubKey = sp.getString("dnstt_pub", "") ?: ""
        dnsResolver = sp.getString("dns_res", "1.1.1.1:53") ?: "1.1.1.1:53"
        dnsttMtu = sp.getInt("dnstt_mtu", 1232)
        v2rayProto = sp.getString("v2_proto", "vless") ?: "vless"
        v2rayHost = sp.getString("v2_host", "") ?: ""
        v2rayPort = sp.getInt("v2_port", 443)
        v2rayUuid = sp.getString("v2_uuid", "") ?: ""
        v2rayNet = sp.getString("v2_net", "ws") ?: "ws"
        v2rayPath = sp.getString("v2_path", "/") ?: "/"
        v2raySni = sp.getString("v2_sni", "") ?: ""
        v2raySecurity = sp.getString("v2_sec", "tls") ?: "tls"
        v2rayFlow = sp.getString("v2_flow", "") ?: ""
        v2rayFp = sp.getString("v2_fp", "chrome") ?: "chrome"
        v2rayPbk = sp.getString("v2_pbk", "") ?: ""
        v2raySid = sp.getString("v2_sid", "") ?: ""
        v2raySpx = sp.getString("v2_spx", "/") ?: "/"
        v2rayTls = sp.getBoolean("v2_tls", true)
        enableShareNet = sp.getBoolean("sharenet", false)
    }

    private fun makeDialogLabel(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 12f
        setTypeface(null, Typeface.BOLD)
        setTextColor(colorTeal)
        setPadding(0, dp(8), 0, dp(2))
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
