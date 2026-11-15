package org.bugs4u.proxyserver.core

import android.os.ParcelFileDescriptor

object Tun2Socks {
    private var isLoaded = false
    var logCallback: ((String) -> Unit)? = null

    private fun ensureLoaded() {
        if (!isLoaded) {
            System.loadLibrary("tun2socks")
            isLoaded = true
        }
    }

    @JvmStatic
    fun Start(
        vpnInterfaceFileDescriptor: ParcelFileDescriptor?,
        vpnInterfaceMTU: Int,
        vpnIpAddress: String,
        vpnNetMask: String,
        socksServerAddress: String,
        udpgwServerAddress: String,
        dnsgwServerAddress: String,
        udpgwTransparentDNS: Boolean
    ) {
        ensureLoaded()
        if (vpnInterfaceFileDescriptor != null) {
            val fd = vpnInterfaceFileDescriptor.detachFd()
            runTun2Socks(
                fd,
                vpnInterfaceMTU,
                vpnIpAddress,
                vpnNetMask,
                socksServerAddress,
                udpgwServerAddress,
                dnsgwServerAddress,
                if (udpgwTransparentDNS) 1 else 0
            )
        }
    }

    @JvmStatic
    fun Stop() {
        try {
            ensureLoaded()
            terminateTun2Socks()
        } catch (_: Throwable) {}
    }

    @JvmStatic
    fun logTun2Socks(level: String?, channel: String?, msg: String?) {
        if (level == "ERROR" && !msg.isNullOrBlank()) {
            logCallback?.invoke("tun2socks: $msg")
        }
    }

    @JvmStatic
    private external fun runTun2Socks(
        vpnInterfaceFileDescriptor: Int,
        vpnInterfaceMTU: Int,
        vpnIpAddress: String,
        vpnNetMask: String,
        socksServerAddress: String,
        udpgwServerAddress: String,
        dnsgwServerAddress: String,
        udpgwTransparentDNS: Int
    ): Int

    @JvmStatic
    private external fun terminateTun2Socks(): Int
}
