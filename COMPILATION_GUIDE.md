
# ESP8266 Deauther Advanced - Compilation Guide

## Prerequisites

### Arduino IDE Setup
1. **Install Arduino IDE 1.8.19 or newer**
2. **Add ESP8266 Board Package:**
   - File → Preferences
   - Additional Board Manager URLs: `http://arduino.esp8266.com/stable/package_esp8266com_index.json`
   - Tools → Board → Boards Manager
   - Search "ESP8266" and install version **2.7.4 or 3.1.2**

### Board Configuration
```
Board: "NodeMCU 1.0 (ESP-12E Module)" or "Generic ESP8266 Module"
Flash Size: "4MB (FS:2MB OTA:~1019KB)"
CPU Frequency: "80 MHz"
Flash Mode: "DIO"
Flash Frequency: "40MHz"
Upload Speed: "921600" (or 115200 if upload fails)
Debug Level: "None"
IwIP Variant: "v2 Lower Memory"
VTables: "Flash"
Exceptions: "Legacy (new can return nullptr)"
Erase Flash: "Only Sketch" (or "All Flash Contents" for first upload)
```

## Memory Optimization Settings

If you encounter memory issues, use these settings:

### Aggressive Memory Reduction
```cpp
#define MAX_SSIDS 10          // Reduced from 20
#define MAX_STATIONS 10       // Reduced from 20
```

### Compiler Optimization
Add to `platform.local.txt` (create in ESP8266 package folder):
```
compiler.c.extra_flags=-Os -ffunction-sections -fdata-sections
compiler.cpp.extra_flags=-Os -ffunction-sections -fdata-sections
compiler.c.elf.extra_flags=-Wl,--gc-sections
```

## Common Issues & Solutions

### 1. `user_interface.h` Not Found
**Solution:** Ensure ESP8266 Core 2.7.4+ is installed
```bash
# Check installed version in Arduino IDE:
# Tools → Board → Boards Manager → Search "ESP8266"
```

### 2. `LittleFS.h` Not Found
**Solution:** Use ESP8266 Core 3.0.0+ or enable SPIFFS fallback
```cpp
// The code automatically falls back to SPIFFS if LittleFS unavailable
```

### 3. `wifi_send_pkt_freedom` Undefined
**Solution:** Use older ESP8266 Core (2.7.4) or add manual declaration
```cpp
extern "C" {
  int wifi_send_pkt_freedom(uint8_t *buf, int len, bool sys_seq);
}
```

### 4. Memory/Heap Issues
**Symptoms:** Random crashes, watchdog resets
**Solutions:**
- Reduce `MAX_SSIDS` and `MAX_STATIONS` to 10
- Use "IwIP v2 Lower Memory" variant
- Set Flash Size to 4MB with 2MB FS
- Enable `-Os` optimization

### 5. Upload/Flash Issues
**Solutions:**
- Hold FLASH button during upload
- Reduce upload speed to 115200
- Use "All Flash Contents" erase option
- Check USB cable and driver

### 6. Compilation Errors
**Generic Solutions:**
- Clean build: Delete temporary files
- Restart Arduino IDE
- Reinstall ESP8266 core
- Check all file paths are correct

## Performance Tuning

### For Stability (Recommended)
```cpp
#define MAX_SSIDS 15
#define MAX_STATIONS 15
packetsPerSecond = 10  // Lower attack intensity
```

### For Maximum Performance
```cpp
#define MAX_SSIDS 20
#define MAX_STATIONS 20
packetsPerSecond = 50  // Higher attack intensity
```

## Verification Steps

After successful compilation:

1. **Check Serial Output:**
```
ESP8266 Deauther Advanced v4.0.0 - Developed by 0x0806
ESP8266 Core Version: 2.7.4
SDK Version: 2.2.2-dev(38a443e)
Free Heap: 45000+ bytes
Advanced Deauther ready!
Access Point: ESP8266-Deauther-Advanced
IP Address: 192.168.4.1
```

2. **Check Memory Usage:**
- Sketch should use <80% of program storage
- Global variables should use <75% of dynamic memory

3. **Test Basic Functions:**
- AP creation
- Web interface loading
- Network scanning
- LED operation

## Alternative Compilation Methods

### PlatformIO (Advanced Users)
```ini
[env:nodemcuv2]
platform = espressif8266@2.6.3
board = nodemcuv2
framework = arduino
upload_speed = 921600
monitor_speed = 115200
build_flags = 
    -Os
    -DDEFAULT_ESP8266
    -DESP8266
lib_deps = 
    ESP8266WiFi
    ESP8266WebServer
    DNSServer
```

### Arduino CLI
```bash
arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 esp8266_deauther_modern.ino
arduino-cli upload -p /dev/ttyUSB0 --fqbn esp8266:esp8266:nodemcuv2 esp8266_deauther_modern.ino
```

## Hardware-Specific Notes

### NodeMCU v1.0
- Use CP2102 driver
- LED on GPIO 2 (built-in)
- Button on GPIO 0 (FLASH)

### Wemos D1 Mini
- Use CH340 driver  
- LED on GPIO 2 (built-in)
- May need external button

### Generic ESP8266
- Verify GPIO mappings
- May need external LED/button
- Check power supply (3.3V, 250mA+)

## Troubleshooting Command

Add this to your sketch for debugging:
```cpp
void printSystemInfo() {
  Serial.printf("Chip ID: %08X\n", ESP.getChipId());
  Serial.printf("Flash ID: %08X\n", ESP.getFlashChipId());
  Serial.printf("Flash Size: %u\n", ESP.getFlashChipRealSize());
  Serial.printf("Free Heap: %u\n", ESP.getFreeHeap());
  Serial.printf("Core Version: %s\n", ESP.getCoreVersion().c_str());
  Serial.printf("SDK Version: %s\n", ESP.getSdkVersion());
}
```

## Success Checklist

- [ ] ESP8266 Core 2.7.4+ installed
- [ ] Correct board selected
- [ ] Memory settings optimized
- [ ] Compilation successful (no errors)
- [ ] Upload successful
- [ ] Serial monitor shows startup messages
- [ ] Free heap > 40KB
- [ ] WiFi AP created successfully
- [ ] Web interface accessible
- [ ] Network scan works
- [ ] No watchdog resets

---

**Need Help?** Check the main README or create an issue with:
- Arduino IDE version
- ESP8266 Core version  
- Board type
- Complete error message
- Hardware setup details
