
# WiFi & BLE Security Testing Platform

**Developed by 0x0806**

A comprehensive, real-world Arduino-based security testing platform that extends ESP8266 deauther capabilities to ESP32, supporting both 2.4GHz and 5GHz dual-band operations with advanced BLE attack features.

## 🚨 LEGAL DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

This tool is designed for:
- Educational purposes to understand wireless security
- Authorized penetration testing on networks you own or have explicit permission to test
- Security research in controlled environments

**WARNING**: Unauthorized use of this tool against networks you do not own or lack permission to test is ILLEGAL and may violate local laws. The author is not responsible for any misuse of this software.

## ✨ Features

### WiFi Attack Capabilities
- **Deauthentication Attacks**: Disconnect clients from target networks
- **Beacon Spam**: Flood area with fake access points
- **Probe Request Flooding**: Generate massive probe request traffic
- **Karma Attacks**: Respond to all probe requests with fake APs
- **Evil Twin**: Create fake access points mimicking legitimate ones
- **Handshake Capture**: Capture WPA/WPA2 handshakes
- **PMKID Capture**: Extract PMKID for offline cracking
- **Packet Monitoring**: Real-time packet analysis

### ESP32 Enhanced Features
- **Dual-Band Support**: Simultaneous 2.4GHz and 5GHz operations
- **BLE Spam Attacks**: Flood nearby devices with BLE packets
- **BLE Beacon Flooding**: Create multiple fake BLE beacons
- **BLE Device Spoofing**: Impersonate legitimate BLE devices
- **Dual-Core Processing**: Efficient attack handling using both CPU cores
- **Advanced Memory Management**: Handle larger datasets and attack vectors

### Platform Compatibility
- **Auto-Detection**: Automatically detects ESP8266 or ESP32 platform
- **Backward Compatibility**: Full ESP8266 feature support maintained
- **Unified Interface**: Single codebase for both platforms

## 🛠️ Hardware Requirements

### Supported Platforms
- **ESP32**: Full feature set including BLE and dual-band WiFi
- **ESP8266**: WiFi-only features (2.4GHz)

### Recommended Hardware
- ESP32 DevKit (for full functionality)
- ESP8266 NodeMCU (for WiFi-only testing)
- External antenna (optional, for better range)

## 📋 Installation

### Arduino IDE Setup

1. **Install ESP32/ESP8266 Board Support**:
   - Open Arduino IDE
   - Go to `File` → `Preferences`
   - Add board manager URLs:
     ```
     https://dl.espressif.com/dl/package_esp32_index.json
     https://arduino.esp8266.com/stable/package_esp8266com_index.json
     ```
   - Go to `Tools` → `Board` → `Boards Manager`
   - Install "ESP32" and "ESP8266" board packages

2. **Install Required Libraries**:
   - For ESP32: All libraries are included in the ESP32 core
   - For ESP8266: Install ESP8266WiFi library if not already included

3. **Upload the Code**:
   - Open `WiFi_BLE_SecurityTester.ino`
   - Select your board type (`ESP32 Dev Module` or `NodeMCU 1.0`)
   - Select the correct port
   - Upload the sketch

## 🚀 Usage

### Initial Setup

1. **Power on the device**
2. **Connect to the Access Point**:
   - SSID: `SecurityTester_0x0806`
   - Password: `security123`
3. **Open web interface**:
   - Navigate to `192.168.4.1` in your browser
   - The captive portal should automatically redirect you

### Web Interface Features

#### WiFi Attacks
- **Network Scanning**: Discover nearby WiFi networks
- **Target Selection**: Click on networks to auto-populate attack fields
- **Attack Configuration**: Set SSID, MAC address, and channel
- **Real-time Statistics**: Monitor attack progress and packet counts

#### BLE Attacks (ESP32 Only)
- **BLE Device Scanning**: Discover nearby Bluetooth Low Energy devices
- **BLE Spam**: Flood area with BLE advertisement packets
- **Beacon Flooding**: Create multiple fake BLE beacons
- **Device Spoofing**: Impersonate legitimate BLE devices

### Attack Types

#### 1. Deauthentication Attack
```
Target: Specific client or broadcast
Purpose: Disconnect devices from networks
Usage: Select network → Enter target MAC → Start Deauth Attack
```

#### 2. Beacon Spam
```
Target: Broadcast area
Purpose: Create fake access points
Usage: Click "Beacon Spam" → Monitor fake AP creation
```

#### 3. Probe Flood
```
Target: Access points
Purpose: Generate probe request traffic
Usage: Click "Probe Flood" → Monitor probe requests
```

#### 4. Karma Attack
```
Target: Client devices
Purpose: Respond to all probe requests
Usage: Click "Karma Attack" → Wait for client connections
```

#### 5. Evil Twin
```
Target: Specific network
Purpose: Create fake AP with same SSID
Usage: Select target network → Click "Evil Twin"
```

## 📊 Statistics and Monitoring

The web interface provides real-time statistics:
- **WiFi Packets**: Total WiFi packets transmitted
- **BLE Packets**: Total BLE packets transmitted (ESP32 only)
- **Uptime**: Device operational time
- **Attack Time**: Duration of current attack
- **Attack Status**: Current attack type and status

## 🔧 Configuration

### Access Point Settings
```cpp
#define AP_SSID "SecurityTester_0x0806"
#define AP_PASS "security123"
#define DNS_PORT 53
#define WEB_PORT 80
```

### Attack Parameters
```cpp
#define MAX_CLIENTS 32
#define BEACON_INTERVAL 100
#define DEAUTH_REASON 7
```

## 🛡️ Security Considerations

### Responsible Usage
- Only test on networks you own or have explicit permission to test
- Ensure testing is conducted in isolated environments when possible
- Be aware of local laws and regulations regarding wireless security testing
- Use strong passwords for the device's access point

### Detection Avoidance
- Randomize MAC addresses when possible
- Vary attack timing and patterns
- Use appropriate power levels to limit range
- Monitor for intrusion detection systems

## 🔍 Troubleshooting

### Common Issues

**Device not creating access point**:
- Check power supply (ensure adequate current)
- Verify board selection in Arduino IDE
- Reset the device and wait for initialization

**Web interface not loading**:
- Ensure you're connected to the device's WiFi network
- Try accessing `192.168.4.1` directly
- Clear browser cache and try again

**Attacks not working**:
- Verify target information (SSID, MAC, channel)
- Check if target is within range
- Ensure legal authorization for testing

**ESP32 BLE features not available**:
- Verify ESP32 board is selected (not ESP8266)
- Check that BLE is not disabled in code
- Restart device if BLE initialization fails

### Serial Monitor Output
Monitor the serial output at 115200 baud for debugging information:
```
WiFi & BLE Security Tester v2.0
Developed by 0x0806
Platform: ESP32 (Dual-band + BLE)
Access Point Started
SSID: SecurityTester_0x0806
IP: 192.168.4.1
```

## 📈 Performance Optimization

### ESP32 Dual-Core Usage
- Core 0: WiFi attack processing
- Core 1: BLE attack processing
- Optimized task scheduling for maximum efficiency

### Memory Management
- Efficient packet handling
- Dynamic memory allocation for attack data
- Garbage collection for long-running attacks

## 🔮 Future Enhancements

- [ ] WPA3 attack support
- [ ] 802.11ax (WiFi 6) compatibility
- [ ] Advanced BLE 5.0 features
- [ ] Packet capture and analysis
- [ ] Integration with external tools
- [ ] Mobile app companion

## 📝 License

This project is released under the MIT License. See LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## 📞 Support

For issues, questions, or contributions:
- Create an issue on GitHub
- Ensure you provide detailed information about your setup
- Include serial monitor output for debugging

## ⚖️ Legal Notice

This tool is provided "as is" without warranty of any kind. Users are solely responsible for ensuring their use complies with applicable laws and regulations. The author disclaims all liability for any damages or legal issues arising from the use of this software.

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
