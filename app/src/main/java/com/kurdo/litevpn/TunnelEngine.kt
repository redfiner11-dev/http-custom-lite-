package com.kurdo.litevpn

import android.content.Context
import android.util.Base64
import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocketFactory
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Properties
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

object TunnelEngine {

    private val running = AtomicBoolean(false)
    private var sshSession: Session? = null
    private var socksServer: ServerSocket? = null
    private var httpServer: ServerSocket? = null
    private var dnsGatewaySocket: DatagramSocket? = null
    private var dnsttProcess: Process? = null
    private var v2rayProcess: Process? = null
    private var isNativeV2RayActive = AtomicBoolean(false)
    private var activeConfig: JSONObject = JSONObject()
    private var appContext: Context? = null
    private val pool = Executors.newCachedThreadPool()
    private val rng = SecureRandom()

    const val LOCAL_DNS_GW_PORT = 8091
    const val LOCAL_DNSTT_PORT = 7000

    fun start(
        context: Context,
        configJson: String,
        onState: (String, String) -> Unit,
        onLog: (String) -> Unit
    ) {
        stop()
        appContext = context.applicationContext
        running.set(true)
        activeConfig = JSONObject(configJson)
        pool.execute {
            runSupervisor(activeConfig, onState, onLog)
        }
    }

    fun stop() {
        running.set(false)
        isNativeV2RayActive.set(false)
        try { socksServer?.close() } catch (_: Exception) {}
        try { httpServer?.close() } catch (_: Exception) {}
        try { dnsGatewaySocket?.close() } catch (_: Exception) {}
        try { v2rayProcess?.destroy() } catch (_: Exception) {}
        try { dnsttProcess?.destroy() } catch (_: Exception) {}
        try { sshSession?.disconnect() } catch (_: Exception) {}
        socksServer = null
        httpServer = null
        dnsGatewaySocket = null
        v2rayProcess = null
        dnsttProcess = null
        sshSession = null
    }

    fun onNetworkHandover(onLog: (String) -> Unit) {
        if (!running.get()) return
        onLog("Network switch detected -> verifying active tunnel...")
        pool.execute {
            try {
                sshSession?.sendKeepAliveMsg()
            } catch (_: Exception) {
                onLog("Rebinding tunnel after network handover...")
                try { sshSession?.disconnect() } catch (_: Exception) {}
            }
        }
    }

    private fun runSupervisor(
        cfg: JSONObject,
        onState: (String, String) -> Unit,
        onLog: (String) -> Unit
    ) {
        val useV2ray = cfg.optBoolean("use_v2ray", false)
        val useSlowDns = cfg.optBoolean("use_slowdns", false)
        val enableShareNet = cfg.optBoolean("enable_sharenet", false)
        val socksPort = cfg.optInt("sharenet_socks_port", 10808)
        val httpPort = cfg.optInt("sharenet_http_port", 8080)
        val bindAddr = if (enableShareNet) "0.0.0.0" else "127.0.0.1"

        // Always start the Local UDP DNS Gateway on 127.0.0.1:8091 for libtun2socks.so
        startLocalDnsGateway(cfg, onLog)

        if (useSlowDns) {
            startNativeSlowDnsProcess(cfg, onLog)
        }

        // Check if native libv2ray.so (Xray-core) binary is available when V2Ray mode is selected
        val ctx = appContext
        val libV2rayFile = if (ctx != null) File(ctx.applicationInfo.nativeLibraryDir, "libv2ray.so") else null
        val canUseNativeXray = useV2ray && libV2rayFile != null && libV2rayFile.exists()

        if (!canUseNativeXray) {
            // Start built-in Kotlin SOCKS5 / ShareNet listeners (used by SSH mode & fallback V2Ray mode)
            try {
                socksServer = ServerSocket()
                socksServer?.reuseAddress = true
                socksServer?.bind(InetSocketAddress(bindAddr, socksPort))
                pool.execute { acceptSocks5Loop(socksServer!!, onLog) }

                if (enableShareNet) {
                    httpServer = ServerSocket()
                    httpServer?.reuseAddress = true
                    httpServer?.bind(InetSocketAddress("0.0.0.0", httpPort))
                    pool.execute { acceptHttpShareNetLoop(httpServer!!, onLog) }
                    onLog("ShareNet Hotspot -> HTTP 0.0.0.0:$httpPort | SOCKS5 $bindAddr:$socksPort")
                }
            } catch (e: Exception) {
                onState("ERROR", "Local proxy bind failed: ${e.message}")
                return
            }
        }

        var backoffMs = 2000L
        while (running.get()) {
            try {
                onState("CONNECTING", "Starting tunnel...")
                if (canUseNativeXray) {
                    runNativeXrayCore(libV2rayFile!!, cfg, onState, onLog)
                } else {
                    connectOnce(cfg, onState, onLog)
                }
                backoffMs = 2000L
            } catch (e: Exception) {
                if (!running.get()) break
                onLog("Tunnel error: ${e.message} (retry in ${backoffMs / 1000}s)")
                onState("RECONNECTING", e.message ?: "Retrying")
                try { Thread.sleep(backoffMs) } catch (_: Exception) {}
                if (backoffMs < 20000L) backoffMs *= 2
            }
        }
        onState("DISCONNECTED", "Stopped")
    }

    /**
     * Launches the native Xray-core binary (libv2ray.so) with full support for:
     * - VLESS, VMess, Trojan, Shadowsocks
     * - XTLS-Reality (pbk, sid, spx, fp) & XTLS Vision (xtls-rprx-vision)
     * - gRPC (serviceName, multiMode), WebSocket (ws), TCP, HTTPUpgrade, SplitHTTP
     * - Chaining V2Ray over SlowDNS (127.0.0.1:7000) when both V2ray and SlowDns are checked!
     */
    private fun runNativeXrayCore(
        libV2rayFile: File,
        cfg: JSONObject,
        onState: (String, String) -> Unit,
        onLog: (String) -> Unit
    ) {
        val ctx = appContext ?: throw Exception("App context unavailable")
        libV2rayFile.setExecutable(true)

        val xrayConfigJson = buildXrayConfigJson(cfg, onLog)
        val cfgFile = File(ctx.filesDir, "v2ray_config.json")
        cfgFile.writeText(xrayConfigJson.toString(2))

        val useSlowDns = cfg.optBoolean("use_slowdns", false)
        val proto = cfg.optString("v2ray_proto", "vless").uppercase()
        val net = cfg.optString("v2ray_net", "ws").uppercase()
        val sec = cfg.optString("v2ray_security", if (cfg.optBoolean("v2ray_tls", true)) "tls" else "none").uppercase()
        val modeLabel = if (useSlowDns) "Xray ($proto/$net/$sec) over SlowDNS" else "Xray ($proto/$net/$sec)"

        onLog("Launching Native libv2ray.so -> $modeLabel")
        val pb = ProcessBuilder(libV2rayFile.absolutePath, "run", "-c", cfgFile.absolutePath)
        pb.directory(ctx.filesDir)
        pb.redirectErrorStream(true)
        val proc = pb.start()
        v2rayProcess = proc
        isNativeV2RayActive.set(true)

        pool.execute {
            try {
                val reader = BufferedReader(InputStreamReader(proc.inputStream))
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    val l = line?.trim() ?: continue
                    if (l.isNotEmpty()) onLog("Xray: $l")
                }
            } catch (_: Exception) {}
        }

        // Wait briefly and verify process is alive and listening on SOCKS5 port
        Thread.sleep(700)
        if (!proc.isAlive) {
            isNativeV2RayActive.set(false)
            throw Exception("libv2ray.so exited prematurely - check V2Ray config in logs")
        }

        onLog("Connected! Native $modeLabel active -> starting TUN2SOCKS.")
        onState("CONNECTED", modeLabel)

        while (running.get() && proc.isAlive) {
            Thread.sleep(2000L)
        }
        isNativeV2RayActive.set(false)
        if (running.get()) {
            throw Exception("Xray process terminated unexpectedly")
        }
    }

    /**
     * Builds a complete Xray-core JSON configuration supporting:
     * - VLESS / VMess / Trojan
     * - TLS / XTLS-Reality (pbk, sid, spx, uTLS fingerprint) / XTLS Vision flow
     * - TCP / WebSocket / gRPC / HTTPUpgrade
     * - V2Ray over SlowDNS (dials 127.0.0.1:7000 while keeping SNI & Host headers)
     */
    private fun buildXrayConfigJson(cfg: JSONObject, onLog: (String) -> Unit): JSONObject {
        val rawCustomJson = cfg.optString("v2ray_raw_json", "").trim()
        if (rawCustomJson.startsWith("{") && rawCustomJson.endsWith("}")) {
            try {
                onLog("Using custom raw Xray JSON configuration")
                return JSONObject(rawCustomJson)
            } catch (_: Exception) {}
        }

        val socksPort = cfg.optInt("sharenet_socks_port", 10808)
        val httpPort = cfg.optInt("sharenet_http_port", 8080)
        val enableShareNet = cfg.optBoolean("enable_sharenet", false)
        val listenIp = if (enableShareNet) "0.0.0.0" else "127.0.0.1"

        val useSlowDns = cfg.optBoolean("use_slowdns", false)
        val proto = cfg.optString("v2ray_proto", "vless").lowercase()
        val remoteHost = cfg.optString("v2ray_host", "").ifEmpty { cfg.optString("server_host", "127.0.0.1") }
        val remotePort = cfg.optInt("v2ray_port", 443).let { if (it in 1..65535) it else 443 }

        // If SlowDNS is checked alongside V2Ray, dial local dnstt-client (127.0.0.1:7000)
        val dialAddress = if (useSlowDns) "127.0.0.1" else remoteHost
        val dialPort = if (useSlowDns) LOCAL_DNSTT_PORT else remotePort

        val uuid = cfg.optString("v2ray_uuid", "").trim()
        val flow = cfg.optString("v2ray_flow", "").trim()
        val net = cfg.optString("v2ray_net", "ws").lowercase()
        val path = cfg.optString("v2ray_path", "/").ifEmpty { "/" }
        val sni = cfg.optString("v2ray_sni", "").ifEmpty { cfg.optString("sni", remoteHost) }.ifEmpty { remoteHost }
        val security = cfg.optString("v2ray_security", if (cfg.optBoolean("v2ray_tls", true)) "tls" else "none").lowercase()
        val fp = cfg.optString("v2ray_fp", "chrome").ifEmpty { "chrome" }
        val pbk = cfg.optString("v2ray_pbk", "").trim()
        val sid = cfg.optString("v2ray_sid", "").trim()
        val spx = cfg.optString("v2ray_spx", "/").ifEmpty { "/" }

        val inbounds = JSONArray().apply {
            put(JSONObject().apply {
                put("tag", "socks-in")
                put("port", socksPort)
                put("listen", listenIp)
                put("protocol", "socks")
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls"))
                })
                put("settings", JSONObject().apply {
                    put("auth", "noauth")
                    put("udp", true)
                })
            })
            if (enableShareNet) {
                put(JSONObject().apply {
                    put("tag", "http-in")
                    put("port", httpPort)
                    put("listen", "0.0.0.0")
                    put("protocol", "http")
                })
            }
        }

        val outboundSettings = when (proto) {
            "trojan" -> JSONObject().apply {
                put("servers", JSONArray().put(JSONObject().apply {
                    put("address", dialAddress)
                    put("port", dialPort)
                    put("password", uuid)
                }))
            }
            "vmess" -> JSONObject().apply {
                put("vnext", JSONArray().put(JSONObject().apply {
                    put("address", dialAddress)
                    put("port", dialPort)
                    put("users", JSONArray().put(JSONObject().apply {
                        put("id", uuid)
                        put("alterId", 0)
                        put("security", "auto")
                    }))
                }))
            }
            else -> JSONObject().apply {
                put("vnext", JSONArray().put(JSONObject().apply {
                    put("address", dialAddress)
                    put("port", dialPort)
                    put("users", JSONArray().put(JSONObject().apply {
                        put("id", uuid)
                        put("encryption", "none")
                        if (flow.isNotEmpty()) {
                            put("flow", flow)
                        }
                    }))
                }))
            }
        }

        val streamSettings = JSONObject().apply {
            put("network", net)
            put("security", security)

            when (security) {
                "reality" -> {
                    put("realitySettings", JSONObject().apply {
                        put("show", false)
                        put("fingerprint", fp)
                        put("serverName", sni)
                        put("publicKey", pbk)
                        put("shortId", sid)
                        put("spiderX", spx)
                    })
                }
                "tls" -> {
                    put("tlsSettings", JSONObject().apply {
                        put("allowInsecure", true)
                        put("serverName", sni)
                        put("fingerprint", fp)
                    })
                }
            }

            when (net) {
                "ws" -> {
                    put("wsSettings", JSONObject().apply {
                        put("path", path)
                        put("headers", JSONObject().apply {
                            put("Host", sni)
                        })
                    })
                }
                "grpc" -> {
                    put("grpcSettings", JSONObject().apply {
                        put("serviceName", path.removePrefix("/"))
                        put("multiMode", false)
                    })
                }
                "httpupgrade" -> {
                    put("httpupgradeSettings", JSONObject().apply {
                        put("path", path)
                        put("host", sni)
                    })
                }
            }
        }

        val outbounds = JSONArray().apply {
            put(JSONObject().apply {
                put("tag", "V2RAY")
                put("protocol", if (proto in listOf("vless", "vmess", "trojan")) proto else "vless")
                put("settings", outboundSettings)
                put("streamSettings", streamSettings)
                put("mux", JSONObject().apply {
                    put("enabled", false)
                })
            })
            put(JSONObject().apply {
                put("tag", "direct")
                put("protocol", "freedom")
            })
        }

        return JSONObject().apply {
            put("log", JSONObject().apply {
                put("loglevel", "warning")
            })
            put("inbounds", inbounds)
            put("outbounds", outbounds)
        }
    }

    private fun startLocalDnsGateway(cfg: JSONObject, onLog: (String) -> Unit) {
        try {
            val udpSock = DatagramSocket(null)
            udpSock.reuseAddress = true
            udpSock.bind(InetSocketAddress("127.0.0.1", LOCAL_DNS_GW_PORT))
            dnsGatewaySocket = udpSock
            val primaryDns = cfg.optString("custom_dns", "1.1.1.1").ifEmpty { "1.1.1.1" }
            val secondaryDns = cfg.optString("custom_dns_secondary", "8.8.8.8").ifEmpty { "8.8.8.8" }
            onLog("DNS Gateway listening on 127.0.0.1:$LOCAL_DNS_GW_PORT -> $primaryDns / $secondaryDns")

            pool.execute {
                val buf = ByteArray(2048)
                while (running.get() && !udpSock.isClosed) {
                    try {
                        val pkt = DatagramPacket(buf, buf.size)
                        udpSock.receive(pkt)
                        val queryBytes = pkt.data.copyOfRange(pkt.offset, pkt.offset + pkt.length)
                        val clientAddr = pkt.address
                        val clientPort = pkt.port
                        pool.execute {
                            val resp = resolveDnsQuery(queryBytes, primaryDns, secondaryDns, cfg.optInt("sharenet_socks_port", 10808))
                            if (resp != null && !udpSock.isClosed) {
                                try {
                                    udpSock.send(DatagramPacket(resp, resp.size, clientAddr, clientPort))
                                } catch (_: Exception) {}
                            }
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (e: Exception) {
            onLog("DNS Gateway bind warning: ${e.message}")
        }
    }

    private fun resolveDnsQuery(query: ByteArray, dns1: String, dns2: String, socksPort: Int): ByteArray? {
        // 1. Try DNS-over-TCP (RFC 1035) inside the active tunnel (via local SOCKS5 if native Xray is active, or openTunnelStream)
        for (dnsHost in listOf(dns1, dns2)) {
            val cleanHost = dnsHost.split(":")[0].trim()
            if (cleanHost.isEmpty()) continue
            try {
                val tunnelStreams = if (isNativeV2RayActive.get()) {
                    openLocalSocks5Stream(socksPort, cleanHost, 53)
                } else {
                    openTunnelStream(cleanHost, 53)
                }
                if (tunnelStreams != null) {
                    val inp = DataInputStream(tunnelStreams.first)
                    val out = tunnelStreams.second
                    val tcpFrame = ByteArray(query.size + 2)
                    tcpFrame[0] = ((query.size shr 8) and 0xFF).toByte()
                    tcpFrame[1] = (query.size and 0xFF).toByte()
                    System.arraycopy(query, 0, tcpFrame, 2, query.size)
                    out.write(tcpFrame)
                    out.flush()
                    val respLen = inp.readUnsignedShort()
                    val resp = ByteArray(respLen)
                    inp.readFully(resp)
                    try { out.close() } catch (_: Exception) {}
                    try { inp.close() } catch (_: Exception) {}
                    return resp
                }
            } catch (_: Exception) {}
        }

        // 2. Fallback: Direct UDP DNS query (bypasses tun0 via addDisallowedApplication)
        for (dnsHost in listOf(dns1, dns2)) {
            val cleanHost = dnsHost.split(":")[0].trim()
            if (cleanHost.isEmpty()) continue
            var dSock: DatagramSocket? = null
            try {
                dSock = DatagramSocket()
                dSock.soTimeout = 3500
                dSock.send(DatagramPacket(query, query.size, InetAddress.getByName(cleanHost), 53))
                val rBuf = ByteArray(2048)
                val rPkt = DatagramPacket(rBuf, rBuf.size)
                dSock.receive(rPkt)
                return rPkt.data.copyOfRange(0, rPkt.length)
            } catch (_: Exception) {
            } finally {
                try { dSock?.close() } catch (_: Exception) {}
            }
        }
        return null
    }

    private fun openLocalSocks5Stream(socksPort: Int, targetHost: String, targetPort: Int): Pair<InputStream, OutputStream>? {
        return try {
            val s = Socket()
            s.soTimeout = 6000
            s.connect(InetSocketAddress("127.0.0.1", socksPort), 4000)
            val inp = DataInputStream(s.getInputStream())
            val out = s.getOutputStream()
            out.write(byteArrayOf(0x05, 0x01, 0x00))
            out.flush()
            if (inp.read() != 0x05 || inp.read() != 0x00) {
                s.close()
                return null
            }
            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            val req = ByteArrayOutputStream()
            req.write(byteArrayOf(0x05, 0x01, 0x00, 0x03, hostBytes.size.toByte()))
            req.write(hostBytes)
            req.write((targetPort shr 8) and 0xFF)
            req.write(targetPort and 0xFF)
            out.write(req.toByteArray())
            out.flush()
            val ver = inp.read()
            val rep = inp.read()
            inp.read() // rsv
            val atyp = inp.read()
            if (ver != 0x05 || rep != 0x00) {
                s.close()
                return null
            }
            when (atyp) {
                0x01 -> inp.readFully(ByteArray(4))
                0x03 -> {
                    val l = inp.read()
                    inp.readFully(ByteArray(l))
                }
                0x04 -> inp.readFully(ByteArray(16))
            }
            inp.readUnsignedShort()
            Pair(inp, out)
        } catch (_: Exception) {
            null
        }
    }

    private fun startNativeSlowDnsProcess(cfg: JSONObject, onLog: (String) -> Unit) {
        val ctx = appContext ?: return
        try {
            dnsttProcess?.destroy()
            val nsDomain = cfg.optString("dnstt_ns", "").trim()
            val pubKey = cfg.optString("dnstt_pubkey", "").trim()
            val resolver = cfg.optString("dns_resolver", "1.1.1.1:53").trim().ifEmpty { "1.1.1.1:53" }

            if (nsDomain.isEmpty() || pubKey.isEmpty()) {
                onLog("SlowDNS warning: Please set Nameserver (NS) and Public Key in SlowDNS settings!")
                return
            }

            val pubFile = File(ctx.filesDir, "server.pub")
            pubFile.writeText(pubKey + "\n")

            val libDnsFile = File(ctx.applicationInfo.nativeLibraryDir, "libdns.so")
            if (!libDnsFile.exists()) {
                onLog("SlowDNS binary not found at ${libDnsFile.absolutePath}")
                return
            }
            libDnsFile.setExecutable(true)

            val cmd = mutableListOf(libDnsFile.absolutePath)
            when {
                resolver.startsWith("https://", ignoreCase = true) -> {
                    cmd.add("-doh")
                    cmd.add(resolver)
                }
                resolver.startsWith("tls://", ignoreCase = true) || resolver.startsWith("dot://", ignoreCase = true) -> {
                    cmd.add("-dot")
                    cmd.add(resolver.substringAfter("://"))
                }
                else -> {
                    cmd.add("-udp")
                    val udpTarget = if (resolver.contains(":")) resolver else "$resolver:53"
                    cmd.add(udpTarget)
                }
            }
            cmd.add("-pubkey-file")
            cmd.add(pubFile.absolutePath)
            cmd.add(nsDomain)
            cmd.add("127.0.0.1:$LOCAL_DNSTT_PORT")

            onLog("Starting Native SlowDNS (dnstt-client) -> NS: $nsDomain via $resolver")
            val pb = ProcessBuilder(cmd)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            dnsttProcess = proc

            pool.execute {
                try {
                    val reader = BufferedReader(InputStreamReader(proc.inputStream))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        val l = line?.trim() ?: continue
                        if (l.isNotEmpty()) onLog("SlowDNS: $l")
                    }
                } catch (_: Exception) {}
            }

            Thread.sleep(600)
        } catch (e: Exception) {
            onLog("SlowDNS start error: ${e.message}")
        }
    }

    private fun connectOnce(
        cfg: JSONObject,
        onState: (String, String) -> Unit,
        onLog: (String) -> Unit
    ) {
        val useV2ray = cfg.optBoolean("use_v2ray", false)
        val useSlowDns = cfg.optBoolean("use_slowdns", false)
        val usePayload = cfg.optBoolean("use_payload", false)
        val useSsl = cfg.optBoolean("use_ssl", false)
        val autoReplace = cfg.optBoolean("auto_replace", true)
        val usePsiphon = cfg.optBoolean("use_psiphon", false)

        if (useV2ray) {
            val v2Transport = if (useSlowDns) "V2Ray over SlowDNS" else "V2Ray (${cfg.optString("v2ray_proto", "vless").uppercase()})"
            onLog("Connecting $v2Transport...")
            val testSock = openV2RayTransportSocket(cfg, onLog)
            testSock.close()
            onLog("Connected! $v2Transport active -> starting TUN2SOCKS routing.")
            onState("CONNECTED", v2Transport)

            while (running.get()) {
                Thread.sleep(2000L)
            }
            return
        }

        val host = cfg.optString("server_host", "127.0.0.1")
        val portsStr = cfg.optString("server_ports", "22")
        val candidatePorts = if (useSlowDns) listOf(LOCAL_DNSTT_PORT) else parsePortList(portsStr)
        val user = cfg.optString("ssh_user", "root")
        val pass = cfg.optString("ssh_pass", "")
        val payload = if (usePayload) cfg.optString("payload", "") else ""
        val sni = cfg.optString("sni", "")
        val keepAliveSec = cfg.optInt("keepalive_sec", 45).coerceAtLeast(20)

        var lastErr: Exception? = null
        for (targetPort in candidatePorts) {
            if (!running.get()) return
            try {
                val connectHost = if (useSlowDns) "127.0.0.1" else host
                onLog("Connecting SSH -> $user@$host" + if (useSlowDns) " via SlowDNS (127.0.0.1:$LOCAL_DNSTT_PORT)" else ":$targetPort")
                val jsch = JSch()
                val session = jsch.getSession(user, connectHost, targetPort)
                session.setPassword(pass)

                val props = Properties()
                props["StrictHostKeyChecking"] = "no"
                props["PreferredAuthentications"] = "password,keyboard-interactive"
                session.setConfig(props)
                session.serverAliveInterval = keepAliveSec * 1000
                session.serverAliveCountMax = 3

                session.setSocketFactory(object : SocketFactory {
                    override fun createSocket(tHost: String, tPort: Int): Socket {
                        return buildCustomSshSocket(
                            host = if (useSlowDns) "127.0.0.1" else host,
                            port = tPort,
                            realHost = host,
                            useSlowDns = useSlowDns,
                            useSsl = useSsl,
                            usePayload = usePayload,
                            autoReplace = autoReplace,
                            usePsiphon = usePsiphon,
                            payload = payload,
                            sni = sni,
                            cfg = cfg,
                            onLog = onLog
                        )
                    }
                    override fun getInputStream(socket: Socket): InputStream = socket.getInputStream()
                    override fun getOutputStream(socket: Socket): OutputStream = socket.getOutputStream()
                })

                session.connect(18000)
                sshSession = session

                val enableUdpGw = cfg.optBoolean("enable_udpgw", true)
                val udpgwPort = cfg.optInt("udpgw_port", 7300)
                if (enableUdpGw) {
                    try {
                        session.setPortForwardingL("127.0.0.1", 7300, "127.0.0.1", udpgwPort)
                        onLog("UDPGW Port Forwarding active (127.0.0.1:7300 -> remote 127.0.0.1:$udpgwPort)")
                    } catch (_: Exception) {}
                }

                val modeDesc = buildList {
                    add(if (useSlowDns) "SlowDNS+SSH" else "SSH:$targetPort")
                    if (usePayload) add("Payload")
                    if (useSsl) add("SSL")
                }.joinToString("+")

                onLog("SSH Authenticated ($modeDesc) -> starting TUN2SOCKS routing.")
                onState("CONNECTED", modeDesc)

                while (running.get() && session.isConnected) {
                    Thread.sleep(2000L)
                }
                return
            } catch (e: Exception) {
                lastErr = e
                onLog("SSH attempt failed: ${e.message}")
            }
        }
        throw lastErr ?: Exception("All SSH ports failed ($portsStr)")
    }

    private fun parsePortList(portsStr: String): List<Int> {
        val list = portsStr.split(",", ";", " ")
            .mapNotNull { it.trim().toIntOrNull() }
            .filter { it in 1..65535 }
        return if (list.isNotEmpty()) list else listOf(22, 80, 443)
    }

    private fun buildCustomSshSocket(
        host: String,
        port: Int,
        realHost: String,
        useSlowDns: Boolean,
        useSsl: Boolean,
        usePayload: Boolean,
        autoReplace: Boolean,
        usePsiphon: Boolean,
        payload: String,
        sni: String,
        cfg: JSONObject,
        onLog: (String) -> Unit
    ): Socket {
        val baseSocket = Socket()
        baseSocket.tcpNoDelay = true
        baseSocket.keepAlive = true

        val proxyHost = cfg.optString("proxy_host", "").trim()
        val proxyPort = cfg.optInt("proxy_port", 0)

        when {
            useSlowDns -> {
                baseSocket.connect(InetSocketAddress("127.0.0.1", LOCAL_DNSTT_PORT), 15000)
            }
            proxyHost.isNotEmpty() && proxyPort in 1..65535 -> {
                onLog("Connecting via Remote Proxy $proxyHost:$proxyPort...")
                baseSocket.connect(InetSocketAddress(proxyHost, proxyPort), 12000)
            }
            else -> {
                baseSocket.connect(InetSocketAddress(host, port), 12000)
            }
        }

        val activeSocket: Socket = if (useSsl) {
            val sniHost = sni.ifEmpty { realHost }
            onLog("TLS/SSL Handshake (SNI: $sniHost)...")
            wrapTlsSni(baseSocket, sniHost, port)
        } else {
            baseSocket
        }

        if (usePayload && payload.isNotBlank()) {
            onLog("Injecting HTTP Payload" + if (autoReplace) " (Auto-Replace ON)" else "")
            injectHttpPayload(activeSocket, realHost, port, sni, payload, autoReplace, usePsiphon, onLog)
        }

        return activeSocket
    }

    private fun wrapTlsSni(baseSocket: Socket, sniHost: String, port: Int): SSLSocket {
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        val sc = SSLContext.getInstance("TLS")
        sc.init(null, trustAll, SecureRandom())
        val sslSocket = sc.socketFactory.createSocket(baseSocket, sniHost, port, true) as SSLSocket
        val params = SSLParameters()
        if (sniHost.isNotEmpty()) {
            params.serverNames = listOf(SNIHostName(sniHost))
        }
        sslSocket.sslParameters = params
        sslSocket.startHandshake()
        return sslSocket
    }

    private fun injectHttpPayload(
        socket: Socket,
        host: String,
        port: Int,
        sni: String,
        rawPayload: String,
        autoReplace: Boolean,
        usePsiphon: Boolean,
        onLog: (String) -> Unit
    ) {
        val expanded = rawPayload
            .replace("[host_port]", "$host:$port")
            .replace("[host]", host)
            .replace("[port]", port.toString())
            .replace("[sni]", sni.ifEmpty { host })
            .replace("[ua]", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0 Mobile Safari/537.36")
            .replace("[protocol]", "HTTP/1.1")
            .replace("[crlf]", "\r\n")
            .replace("[lf]", "\n")
            .replace("[cr]", "\r")
            .replace("\\r\\n", "\r\n")
            .replace("\\n", "\n")

        val segments = when {
            expanded.contains("[split]") -> expanded.split("[split]")
            expanded.contains("[instant_split]") -> expanded.split("[instant_split]")
            usePsiphon && expanded.length > 24 -> listOf(expanded.substring(0, 16), expanded.substring(16))
            else -> listOf(expanded)
        }

        val out = socket.getOutputStream()
        for (i in segments.indices) {
            val seg = segments[i]
            if (seg.isNotEmpty()) {
                out.write(seg.toByteArray(Charsets.UTF_8))
                out.flush()
            }
            if (i < segments.size - 1) {
                Thread.sleep(75)
            }
        }

        val inp = socket.getInputStream()
        val lineSb = StringBuilder()
        var b: Int
        while (inp.read().also { b = it } != -1) {
            lineSb.append(b.toChar())
            if (b == '\n'.code) break
        }
        val rawStatus = lineSb.toString().trim()
        val displayStatus = if (autoReplace && (rawStatus.contains("101") || rawStatus.contains("200") || rawStatus.startsWith("HTTP/"))) {
            "HTTP/1.1 200 Connection established"
        } else {
            rawStatus
        }
        onLog("Payload response: $displayStatus")

        if (rawStatus.startsWith("HTTP/")) {
            var tail = ""
            while (inp.read().also { b = it } != -1) {
                tail += b.toChar()
                if (tail.endsWith("\r\n\r\n") || tail.endsWith("\n\n") || tail.contains("SSH-2.0")) break
                if (tail.length > 4096) break
            }
        }
    }

    private fun openV2RayTransportSocket(cfg: JSONObject, onLog: (String) -> Unit): Socket {
        val useSlowDns = cfg.optBoolean("use_slowdns", false)
        val v2Host = cfg.optString("v2ray_host", "").ifEmpty { cfg.optString("server_host", "127.0.0.1") }
        val v2Port = cfg.optInt("v2ray_port", 443).let { if (it in 1..65535) it else 443 }
        val v2Tls = cfg.optBoolean("v2ray_tls", true) || cfg.optBoolean("use_ssl", false)
        val v2Sni = cfg.optString("v2ray_sni", "").ifEmpty { cfg.optString("sni", v2Host) }
        val v2Net = cfg.optString("v2ray_net", "ws")
        val v2Path = cfg.optString("v2ray_path", "/").ifEmpty { "/" }

        val rawSock = Socket()
        rawSock.tcpNoDelay = true
        rawSock.keepAlive = true

        if (useSlowDns) {
            onLog("Chaining V2Ray transport over SlowDNS (127.0.0.1:$LOCAL_DNSTT_PORT)...")
            rawSock.connect(InetSocketAddress("127.0.0.1", LOCAL_DNSTT_PORT), 15000)
        } else {
            rawSock.connect(InetSocketAddress(v2Host, v2Port), 12000)
        }

        val transportSock: Socket = if (v2Tls) {
            wrapTlsSni(rawSock, v2Sni.ifEmpty { v2Host }, v2Port)
        } else {
            rawSock
        }

        if (v2Net.equals("ws", ignoreCase = true)) {
            performWebSocketHandshake(transportSock, v2Sni.ifEmpty { v2Host }, v2Path)
        }

        return transportSock
    }

    private fun performWebSocketHandshake(sock: Socket, wsHost: String, wsPath: String) {
        val keyBytes = ByteArray(16)
        rng.nextBytes(keyBytes)
        val secKey = Base64.encodeToString(keyBytes, Base64.NO_WRAP)
        val path = if (wsPath.startsWith("/")) wsPath else "/$wsPath"

        val req = buildString {
            append("GET $path HTTP/1.1\r\n")
            append("Host: $wsHost\r\n")
            append("Upgrade: websocket\r\n")
            append("Connection: Upgrade\r\n")
            append("Sec-WebSocket-Key: $secKey\r\n")
            append("Sec-WebSocket-Version: 13\r\n")
            append("User-Agent: Mozilla/5.0 (Linux; Android 14)\r\n\r\n")
        }
        val out = sock.getOutputStream()
        out.write(req.toByteArray(Charsets.UTF_8))
        out.flush()

        val inp = sock.getInputStream()
        var headerTail = ""
        var b: Int
        while (inp.read().also { b = it } != -1) {
            headerTail += b.toChar()
            if (headerTail.endsWith("\r\n\r\n") || headerTail.endsWith("\n\n")) break
            if (headerTail.length > 4096) break
        }
    }

    private fun openTunnelStream(targetHost: String, targetPort: Int): Pair<InputStream, OutputStream>? {
        val useV2ray = activeConfig.optBoolean("use_v2ray", false)
        if (useV2ray) {
            return openV2RayStream(targetHost, targetPort)
        }

        val s = sshSession
        if (s != null && s.isConnected) {
            return try {
                val ch = s.openChannel("direct-tcpip") as ChannelDirectTCPIP
                ch.setHost(targetHost)
                ch.setPort(targetPort)
                val inp = ch.inputStream
                val out = ch.outputStream
                ch.connect(10000)
                Pair(inp, out)
            } catch (_: Exception) {
                null
            }
        }
        return null
    }

    private fun openV2RayStream(targetHost: String, targetPort: Int): Pair<InputStream, OutputStream>? {
        return try {
            val sock = openV2RayTransportSocket(activeConfig, {})
            val proto = activeConfig.optString("v2ray_proto", "vless").lowercase()
            val uuidStr = activeConfig.optString("v2ray_uuid", "").trim()
            val isWs = activeConfig.optString("v2ray_net", "ws").equals("ws", ignoreCase = true)

            val baseIn = sock.getInputStream()
            val baseOut = sock.getOutputStream()

            val wrappedOut: OutputStream = if (isWs) WebSocketClientOutputStream(baseOut, rng) else baseOut
            val wsIn: InputStream = if (isWs) WebSocketClientInputStream(baseIn) else baseIn

            if (proto == "trojan") {
                val header = buildTrojanHeader(uuidStr, targetHost, targetPort)
                wrappedOut.write(header)
                wrappedOut.flush()
                Pair(wsIn, wrappedOut)
            } else {
                val header = buildVlessHeader(uuidStr, targetHost, targetPort)
                wrappedOut.write(header)
                wrappedOut.flush()
                Pair(VlessResponseInputStream(wsIn), wrappedOut)
            }
        } catch (_: Exception) {
            null
        }
    }

    private class VlessResponseInputStream(private val delegate: InputStream) : InputStream() {
        private var headerStripped = false

        private fun ensureHeaderStripped() {
            if (!headerStripped) {
                headerStripped = true
                val ver = delegate.read()
                if (ver >= 0) {
                    val addonLen = delegate.read()
                    if (addonLen > 0) {
                        var rem = addonLen
                        val skipBuf = ByteArray(addonLen)
                        while (rem > 0) {
                            val n = delegate.read(skipBuf, 0, rem)
                            if (n <= 0) break
                            rem -= n
                        }
                    }
                }
            }
        }

        override fun read(): Int {
            ensureHeaderStripped()
            return delegate.read()
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            ensureHeaderStripped()
            return delegate.read(b, off, len)
        }

        override fun close() {
            delegate.close()
        }
    }

    private fun buildVlessHeader(uuidStr: String, targetHost: String, targetPort: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x00)
        val uuid = try {
            UUID.fromString(uuidStr)
        } catch (_: Exception) {
            UUID.nameUUIDFromBytes(uuidStr.toByteArray(Charsets.UTF_8))
        }
        val bb = ByteBuffer.allocate(16)
        bb.putLong(uuid.mostSignificantBits)
        bb.putLong(uuid.leastSignificantBits)
        out.write(bb.array())
        out.write(0x00)
        out.write(0x01)
        out.write((targetPort shr 8) and 0xFF)
        out.write(targetPort and 0xFF)
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        out.write(0x02)
        out.write(hostBytes.size and 0xFF)
        out.write(hostBytes)
        return out.toByteArray()
    }

    private fun buildTrojanHeader(password: String, targetHost: String, targetPort: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val digest = MessageDigest.getInstance("SHA-224").digest(password.toByteArray(Charsets.UTF_8))
        val hexPass = digest.joinToString("") { "%02x".format(it) }
        out.write(hexPass.toByteArray(Charsets.UTF_8))
        out.write("\r\n".toByteArray(Charsets.UTF_8))
        out.write(0x01)
        out.write(0x03)
        val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
        out.write(hostBytes.size and 0xFF)
        out.write(hostBytes)
        out.write((targetPort shr 8) and 0xFF)
        out.write(targetPort and 0xFF)
        out.write("\r\n".toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    private class WebSocketClientOutputStream(
        private val rawOut: OutputStream,
        private val random: SecureRandom
    ) : OutputStream() {
        override fun write(b: Int) {
            write(byteArrayOf(b.toByte()), 0, 1)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            val frame = ByteArrayOutputStream()
            frame.write(0x82)
            when {
                len <= 125 -> frame.write(0x80 or len)
                len <= 65535 -> {
                    frame.write(0x80 or 126)
                    frame.write((len shr 8) and 0xFF)
                    frame.write(len and 0xFF)
                }
                else -> {
                    frame.write(0x80 or 127)
                    val l = len.toLong()
                    for (shift in 56 downTo 0 step 8) {
                        frame.write(((l shr shift) and 0xFF).toInt())
                    }
                }
            }
            val mask = ByteArray(4)
            random.nextBytes(mask)
            frame.write(mask)
            val maskedPayload = ByteArray(len)
            for (i in 0 until len) {
                maskedPayload[i] = (b[off + i].toInt() xor mask[i % 4].toInt()).toByte()
            }
            frame.write(maskedPayload)
            synchronized(rawOut) {
                rawOut.write(frame.toByteArray())
            }
        }

        override fun flush() {
            synchronized(rawOut) {
                rawOut.flush()
            }
        }

        override fun close() {
            try { rawOut.close() } catch (_: Exception) {}
        }
    }

    private class WebSocketClientInputStream(rawIn: InputStream) : InputStream() {
        private val din = DataInputStream(rawIn)
        private var currentFrame: ByteArray = ByteArray(0)
        private var framePos = 0

        override fun read(): Int {
            val one = ByteArray(1)
            val n = read(one, 0, 1)
            return if (n <= 0) -1 else (one[0].toInt() and 0xFF)
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (framePos >= currentFrame.size) {
                if (!readNextFrame()) return -1
            }
            val avail = (currentFrame.size - framePos).coerceAtMost(len)
            System.arraycopy(currentFrame, framePos, b, off, avail)
            framePos += avail
            return avail
        }

        private fun readNextFrame(): Boolean {
            return try {
                val b0 = din.readUnsignedByte()
                val opcode = b0 and 0x0F
                if (opcode == 0x08) return false
                val b1 = din.readUnsignedByte()
                val masked = (b1 and 0x80) != 0
                var payloadLen = (b1 and 0x7F).toLong()
                if (payloadLen == 126L) {
                    payloadLen = din.readUnsignedShort().toLong()
                } else if (payloadLen == 127L) {
                    payloadLen = din.readLong()
                }
                val maskKey = ByteArray(4)
                if (masked) din.readFully(maskKey)
                val data = ByteArray(payloadLen.toInt())
                din.readFully(data)
                if (masked) {
                    for (i in data.indices) {
                        data[i] = (data[i].toInt() xor maskKey[i % 4].toInt()).toByte()
                    }
                }
                currentFrame = data
                framePos = 0
                true
            } catch (_: Exception) {
                false
            }
        }
    }

    private fun acceptSocks5Loop(server: ServerSocket, onLog: (String) -> Unit) {
        while (running.get() && !server.isClosed) {
            try {
                val client = server.accept()
                pool.execute { handleSocks5Client(client) }
            } catch (_: Exception) {}
        }
    }

    private fun handleSocks5Client(client: Socket) {
        try {
            client.use { sock ->
                val inp = DataInputStream(sock.getInputStream())
                val out = sock.getOutputStream()

                val ver = inp.read()
                if (ver != 0x05) return
                val nMethods = inp.read()
                if (nMethods > 0) {
                    val methods = ByteArray(nMethods)
                    inp.readFully(methods)
                }
                out.write(byteArrayOf(0x05, 0x00))
                out.flush()

                val reqVer = inp.read()
                val cmd = inp.read()
                inp.read()
                val atyp = inp.read()
                if (reqVer != 0x05 || cmd != 0x01) return

                val host = when (atyp) {
                    0x01 -> {
                        val ip = ByteArray(4)
                        inp.readFully(ip)
                        InetAddress.getByAddress(ip).hostAddress ?: return
                    }
                    0x03 -> {
                        val len = inp.read()
                        val dom = ByteArray(len)
                        inp.readFully(dom)
                        String(dom, Charsets.UTF_8)
                    }
                    0x04 -> {
                        val ip6 = ByteArray(16)
                        inp.readFully(ip6)
                        InetAddress.getByAddress(ip6).hostAddress ?: return
                    }
                    else -> return
                }
                val port = inp.readUnsignedShort()

                val remote = openTunnelStream(host, port)
                if (remote == null) {
                    out.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    out.flush()
                    return
                }
                out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                out.flush()
                pipeStreams(inp, out, remote.first, remote.second)
            }
        } catch (_: Exception) {}
    }

    private fun acceptHttpShareNetLoop(server: ServerSocket, onLog: (String) -> Unit) {
        while (running.get() && !server.isClosed) {
            try {
                val client = server.accept()
                pool.execute { handleHttpShareNetClient(client) }
            } catch (_: Exception) {}
        }
    }

    private fun handleHttpShareNetClient(client: Socket) {
        try {
            client.use { sock ->
                val inp = sock.getInputStream()
                val out = sock.getOutputStream()
                val reader = BufferedReader(InputStreamReader(inp))
                val reqLine = reader.readLine() ?: return
                val parts = reqLine.split(" ")
                if (parts.size < 2) return
                val method = parts[0]
                val targetUri = parts[1]

                val headers = mutableListOf<String>()
                var hostHeader = ""
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                    headers.add(line)
                    if (line.lowercase().startsWith("host:")) {
                        hostHeader = line.substring(5).trim()
                    }
                }

                if (method.equals("CONNECT", ignoreCase = true)) {
                    val hp = targetUri.split(":")
                    val h = hp[0]
                    val p = if (hp.size > 1) hp[1].toIntOrNull() ?: 443 else 443
                    val remote = openTunnelStream(h, p) ?: return
                    out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                    out.flush()
                    pipeStreams(inp, out, remote.first, remote.second)
                } else {
                    val hp = hostHeader.split(":")
                    val h = hp[0]
                    val p = if (hp.size > 1) hp[1].toIntOrNull() ?: 80 else 80
                    val remote = openTunnelStream(h, p) ?: return
                    val rebuilt = buildString {
                        append(reqLine).append("\r\n")
                        for (hdr in headers) append(hdr).append("\r\n")
                        append("\r\n")
                    }
                    remote.second.write(rebuilt.toByteArray())
                    remote.second.flush()
                    pipeStreams(inp, out, remote.first, remote.second)
                }
            }
        } catch (_: Exception) {}
    }

    private fun pipeStreams(
        cIn: InputStream,
        cOut: OutputStream,
        rIn: InputStream,
        rOut: OutputStream
    ) {
        val t1 = Thread {
            val buf = ByteArray(32768)
            try {
                var n: Int
                while (cIn.read(buf).also { n = it } > 0) {
                    rOut.write(buf, 0, n)
                    rOut.flush()
                }
            } catch (_: Exception) {}
        }
        val t2 = Thread {
            val buf = ByteArray(32768)
            try {
                var n: Int
                while (rIn.read(buf).also { n = it } > 0) {
                    cOut.write(buf, 0, n)
                    cOut.flush()
                }
            } catch (_: Exception) {}
        }
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    }

    /**
     * Parses vless://, vmess://, or trojan:// links, including Xray Reality (pbk, sid, spx, fp),
     * XTLS Vision (flow=xtls-rprx-vision), and gRPC (type=grpc&serviceName=...)!
     */
    fun parseV2RayLink(uriStr: String): JSONObject? {
        val raw = uriStr.trim()
        return try {
            when {
                raw.startsWith("vless://", ignoreCase = true) || raw.startsWith("trojan://", ignoreCase = true) -> {
                    val proto = if (raw.startsWith("trojan://", true)) "trojan" else "vless"
                    val u = URI(raw)
                    val uuid = u.userInfo ?: ""
                    val host = u.host ?: ""
                    val port = if (u.port > 0) u.port else 443
                    val query = u.rawQuery ?: ""
                    val params = mutableMapOf<String, String>()
                    for (pair in query.split("&")) {
                        val kv = pair.split("=", limit = 2)
                        if (kv.size == 2) params[kv[0]] = java.net.URLDecoder.decode(kv[1], "UTF-8")
                    }
                    val netType = params["type"] ?: "ws"
                    val secType = params["security"] ?: "tls"
                    val pathOrService = if (netType == "grpc") (params["serviceName"] ?: params["path"] ?: "") else (params["path"] ?: "/")
                    JSONObject().apply {
                        put("v2ray_proto", proto)
                        put("v2ray_host", host)
                        put("v2ray_port", port)
                        put("v2ray_uuid", uuid)
                        put("v2ray_net", netType)
                        put("v2ray_path", pathOrService)
                        put("v2ray_sni", params["sni"] ?: params["host"] ?: host)
                        put("v2ray_security", secType)
                        put("v2ray_tls", secType != "none")
                        put("v2ray_flow", params["flow"] ?: "")
                        put("v2ray_fp", params["fp"] ?: "chrome")
                        put("v2ray_pbk", params["pbk"] ?: "")
                        put("v2ray_sid", params["sid"] ?: "")
                        put("v2ray_spx", params["spx"] ?: "/")
                    }
                }
                raw.startsWith("vmess://", ignoreCase = true) -> {
                    val b64 = raw.substring(8).trim()
                    val decoded = String(Base64.decode(b64, Base64.DEFAULT), Charsets.UTF_8)
                    val j = JSONObject(decoded)
                    val host = j.optString("add", "")
                    val port = j.optString("port", "443").toIntOrNull() ?: 443
                    val tlsVal = j.optString("tls", "")
                    JSONObject().apply {
                        put("v2ray_proto", "vmess")
                        put("v2ray_host", host)
                        put("v2ray_port", port)
                        put("v2ray_uuid", j.optString("id", ""))
                        put("v2ray_net", j.optString("net", "ws"))
                        put("v2ray_path", j.optString("path", "/"))
                        put("v2ray_sni", j.optString("sni", j.optString("host", host)))
                        put("v2ray_security", if (tlsVal == "tls") "tls" else "none")
                        put("v2ray_tls", tlsVal == "tls")
                    }
                }
                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }
}
