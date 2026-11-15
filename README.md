# ⚡ KurdoLite VPN (Ultra-Light HTTP Custom Alternative + ShareNet)

An ultra-lightweight, zero-ad, battery-optimized Android tunneling client with every core feature of HTTP Custom:

- **SSH + Custom HTTP/WebSocket Payload (`Port 80 / 443 / ws-fast`)**: Full `[host]`, `[port]`, `[crlf]`, `[ua]`, `[split]`, and `Upgrade: websocket` payload injection + built-in Payload Generator.
- **SSL / TLS SNI Bug Host Spoofing**: Custom SNI handshake over TLS 1.2/1.3.
- **SlowDNS (DNSTT Turbo Engine)**: Tuned with `MTU 1232/1252`, custom Nameserver (`NS`), Public Key, and DoH / UDP DNS resolvers.
- **V2Ray / Xray (`VLESS WebSocket + TLS`)**: Integrated VLESS stream handler.
- **ShareNet (Wi-Fi Hotspot Proxy + Root Tethering)**:
  - **Hotspot HTTP Proxy**: `0.0.0.0:8080`
  - **Hotspot SOCKS5 Proxy**: `0.0.0.0:10808`
  - Automatically displays your phone's active Hotspot IP (`192.168.43.1` or `192.168.x.x`) and auto-configures `iptables` on rooted devices.
- **Locked Profile Export/Import (`.klite`)**: AES-encrypted config sharing with locked payload/server fields, just like `.hc` files.
- **Ultra-Low Battery Architecture**:
  - **0 Ads / 0 Analytics / 0 WakeLocks**: No Firebase, no AdMob, no background tracking threads.
  - **45-Second Adaptive Keep-Alive + Android `NetworkCallback`**: Lets your phone's 4G/5G modem enter low-power sleep states between bursts instead of draining battery with 1-second ping loops.
  - **True OLED `#000000` UI + Auto-Sleeping Logs**: Log rendering pauses automatically when the screen is off or minimized.

---

## 🚀 How to Get Your `.apk` in 3 Clicks (No PC Setup Required!)

Because this project includes an automated **GitHub Actions Cloud Builder** (`.github/workflows/build-apk.yml`), GitHub's servers will compile both the Go native core and the Android `.apk` for you automatically:

1. **Create a new GitHub Repository** (can be Private or Public) on your GitHub account.
2. **Upload all files from this ZIP** into the repository (or push via Git).
3. Click the **Actions** tab in your GitHub repository → select **Build Ultra-Light APK (Cloud Builder)** → click **Run workflow**.
4. After ~2 minutes, scroll down to **Artifacts** and download **`KurdoLite-HTTP-Custom-APK.zip`**, which contains your ready-to-install `.apk` file!
