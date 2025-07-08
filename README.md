
# ESP8266 Deauther Advanced v4.0.0 - All-in-One Edition

**Developed by 0x0806**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ESP8266](https://img.shields.io/badge/ESP8266-Compatible-blue.svg)](https://www.espressif.com/en/products/socs/esp8266)
[![Version](https://img.shields.io/badge/Version-v4.0.0--Advanced-green.svg)](https://github.com/spacehuhntech/esp8266_deauther)

## 🛡️ Overview

The ESP8266 Deauther Advanced is the most comprehensive WiFi security testing tool available in a single Arduino sketch (.ino file). This all-in-one implementation combines advanced deauthentication attacks, beacon spam, probe attacks, packet monitoring, and a beautiful modern web interface - all without requiring external dependencies or separate files.

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND TESTING PURPOSES ONLY**

- Use only on networks you own or have explicit permission to test
- Check local laws and regulations before use
- We are not responsible for any misuse of this software
- This tool is designed to test and improve WiFi network security

## ✨ Features

### 🔥 Core Attack Capabilities
- **Advanced Deauthentication Attacks**: Multiple attack vectors with enhanced packet crafting
- **Beacon Spam**: Creates fake WiFi networks with realistic characteristics
- **Probe Request Attacks**: Confuses WiFi tracking systems
- **Targeted Station Attacks**: Focuses on specific client devices
- **Multiple Reason Codes**: Uses various deauth/disassoc reason codes for effectiveness

### 📡 Network Analysis
- **WiFi Network Scanner**: Discovers all nearby networks including hidden ones
- **Station Detection**: Identifies connected client devices
- **Packet Monitor**: Real-time packet capture and analysis
- **Channel Hopping**: Supports all WiFi channels (1-14)
- **Signal Strength Analysis**: RSSI measurements and classification

### 🎨 Modern Web Interface
- **Responsive Design**: Works on mobile and desktop
- **Real-time Updates**: Live statistics and status monitoring
- **Tabbed Interface**: Organized feature sections
- **Professional UI/UX**: Modern gradients and animations
- **Dark Theme**: Easy on the eyes during long testing sessions

### 🔧 Advanced Configuration
- **SSID Management**: Add/remove custom SSIDs for beacon spam
- **Attack Parameters**: Configurable packets per second (1-100)
- **Statistics Tracking**: Comprehensive attack and system metrics
- **Settings Persistence**: EEPROM storage for configurations
- **Button Controls**: Hardware reset and emergency stop

## 🛠️ Hardware Requirements

### Minimum Requirements
- **ESP8266** microcontroller (NodeMCU, Wemos D1 Mini, etc.)
- **Built-in LED** (GPIO 2) - for status indication
- **Button** (GPIO 0) - for reset/emergency stop (optional)

### Recommended Hardware
- NodeMCU v1.0 or Wemos D1 Mini
- External antenna for better range
- Stable 3.3V power supply

## 📥 Installation

### Arduino IDE Setup

1. **Install ESP8266 Board Package**:
   - File → Preferences
   - Add to Additional Board Manager URLs: `http://arduino.esp8266.com/stable/package_esp8266com_index.json`
   - Tools → Board → Boards Manager → Search "ESP8266" → Install

2. **Required Libraries** (Auto-installed):
   - ESP8266WiFi
   - ESP8266WebServer
   - DNSServer
   - EEPROM
   - LittleFS

3. **Board Configuration**:
   - Board: "NodeMCU 1.0 (ESP-12E Module)" or your specific ESP8266 board
   - Flash Size: "4MB (FS:2MB OTA:~1019KB)"
   - CPU Frequency: "80 MHz"
   - Flash Mode: "DIO"
   - Flash Frequency: "40MHz"
   - Upload Speed: "921600"

### Upload Instructions

1. Download `esp8266_deauther_modern.ino`
2. Open in Arduino IDE
3. Select your ESP8266 board and COM port
4. Click Upload
5. Wait for "Done uploading" message

## 🚀 Usage

### First Time Setup

1. **Power on** your ESP8266
2. **Connect** to WiFi network: `ESP8266-Deauther-Advanced`
3. **Password**: `deauther`
4. **Open browser** and navigate to: `192.168.4.1`

### Web Interface Navigation

#### 📡 Scanner Tab
- **Scan Networks**: Discover nearby WiFi networks
- **Select Targets**: Choose networks for attack
- **View Statistics**: See discovered networks and stations

#### ⚔️ Attacks Tab
- **Configure Attack**: Set packets per second (1-100)
- **Start Deauth**: Begin deauthentication attack
- **Monitor Progress**: Real-time attack statistics

#### 📻 Beacon Tab
- **Beacon Spam**: Create fake WiFi networks
- **Probe Attack**: Send probe requests

#### 📝 SSIDs Tab
- **Manage SSIDs**: Add/remove custom network names
- **Enable/Disable**: Toggle individual SSIDs

#### 👁️ Monitor Tab
- **Packet Monitoring**: Capture and analyze WiFi traffic
- **Device Tracking**: Count unique devices

#### 📊 Stats Tab
- **System Statistics**: View comprehensive metrics
- **Reset Counters**: Clear all statistics

### Hardware Controls

- **Button Press** (3 seconds): Emergency stop all attacks
- **LED Indicators**:
  - Slow blink: Idle
  - Fast blink: Attack in progress
  - Medium blink: Scanning/monitoring

## ⚙️ Configuration

### Attack Settings
```cpp
#define MAX_SSIDS 50           // Maximum custom SSIDs
#define MAX_STATIONS 50        // Maximum tracked stations
int packetsPerSecond = 20;     // Default attack intensity
```

### Network Settings
```cpp
#define AP_SSID "ESP8266-Deauther-Advanced"
#define AP_PASS "deauther"
```

### Hardware Pins
```cpp
#define LED_PIN 2     // Status LED
#define BUTTON_PIN 0  // Reset button
```

## 🔒 Security Features

- **WPA2 Detection**: Identifies encryption types
- **Hidden Network Discovery**: Finds networks not broadcasting SSID
- **MAC Address Analysis**: Tracks unique devices
- **Realistic Packet Crafting**: Uses proper 802.11 frame structures
- **Channel Intelligence**: Optimizes channel switching

## 📊 Performance Metrics

### Attack Capabilities
- **Deauth Rate**: Up to 100 packets/second
- **Network Coverage**: All 2.4GHz channels (1-14)
- **Range**: Depends on hardware (typically 50-100m)
- **Efficiency**: Optimized for minimal false positives

### System Performance
- **Memory Usage**: Optimized for ESP8266 constraints
- **Stability**: Watchdog protection and error recovery
- **Responsiveness**: Real-time web interface updates

## 🐛 Troubleshooting

### Common Issues

**Can't connect to web interface:**
- Ensure ESP8266 is powered and LED is blinking
- Check WiFi connection to "ESP8266-Deauther-Advanced"
- Try different browser or clear cache

**Attack not working:**
- Verify target network selection
- Check if target uses WPA3 (not supported)
- Ensure proper antenna connection

**Upload fails:**
- Check COM port selection
- Press and hold FLASH button during upload
- Try lower upload speed (115200)

**Memory errors:**
- Flash size set to 4MB with 2MB FS
- Close other programs during upload

### LED Status Codes
- **Solid OFF**: No power or serious error
- **Slow blink (1s)**: Normal operation, ready
- **Fast blink (0.1s)**: Attack in progress
- **Medium blink (0.25s)**: Scanning or monitoring

## 🔬 Technical Details

### Packet Structures
The deauther uses proper 802.11 frame structures:
- **Deauthentication frames**: Reason codes 1-16
- **Disassociation frames**: Multiple reason codes
- **Beacon frames**: Realistic timing and elements
- **Probe requests**: Proper SSID encoding

### Attack Algorithms
- **Multi-vector attacks**: Combines deauth + disassoc
- **Targeted attacks**: Focuses on specific client-AP pairs
- **Broadcast attacks**: Affects all clients on network
- **Channel optimization**: Switches between target channels

### Web Interface Technology
- **Responsive CSS**: Modern gradients and animations
- **JavaScript**: Real-time updates without page refresh
- **JSON APIs**: Structured data exchange
- **WebSocket-like updates**: Polling for live data

## 🤝 Contributing

This is an all-in-one implementation designed for maximum compatibility and ease of use. For the main ESP8266 Deauther project with modular architecture, visit:

[Official ESP8266 Deauther Repository](https://github.com/spacehuhntech/esp8266_deauther)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Stefan Kremser (spacehuhntech)**: Original ESP8266 Deauther concept
- **ESP8266 Community**: Libraries and documentation
- **Security Researchers**: WiFi vulnerability research
- **Open Source Community**: Tools and inspiration

## 📞 Support

For issues related to this advanced all-in-one version:
- Check the troubleshooting section above
- Verify hardware compatibility
- Ensure proper board configuration

For general ESP8266 Deauther questions:
- Visit [deauther.com](https://deauther.com)
- Check the [official documentation](https://deauther.com/docs/)
- Join the community discussions

---

**⚡ Most Advanced WiFi Security Testing Tool - All in One .ino File**

*Developed by 0x0806 - Educational purposes only*
