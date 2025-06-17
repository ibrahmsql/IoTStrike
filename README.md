# IoTStrike Hardware Security Framework

**Advanced IoT and Embedded System Security Testing Platform**

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/iotstrike/framework)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20ARM%20%7C%20MIPS-lightgrey.svg)](#supported-platforms)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](#building)

## Overview

IoTStrike is a comprehensive hardware security testing framework designed for IoT devices, embedded systems, and hardware security research. The framework provides real hardware interaction capabilities without simulations or emulations, ensuring authentic security testing results.

## 🚀 Key Features

### Hardware Communication
- **UART/Serial**: Full-duplex communication with configurable parameters
- **SPI**: Master/slave mode support with multiple chip select
- **I2C**: Multi-master bus communication and device scanning
- **GPIO**: Digital I/O control with interrupt support
- **USB**: Device enumeration and communication
- **Wireless**: 802.11 WiFi, Bluetooth, Zigbee, LoRa support

### Security Testing Modules
- **Firmware Analysis**: Binary analysis, vulnerability detection, crypto analysis
- **Wireless Exploitation**: WPS attacks, deauth, packet injection
- **Real-time Attacks**: Timing attacks, interrupt manipulation
- **Side-channel Analysis**: Power analysis, electromagnetic analysis
- **Hardware Debugging**: JTAG/SWD interface support

### Advanced Capabilities
- **Cross-platform**: ARM, MIPS, x86, x86_64 support
- **Real-time**: Hardware timer-based precise timing
- **Memory-safe**: Secure memory management and buffer protection
- **Multi-threaded**: Parallel processing for complex attacks
- **Extensible**: Plugin architecture for custom modules

## 📋 Requirements

### System Requirements
- Linux-based operating system (Ubuntu 20.04+ recommended)
- Minimum 512MB RAM (2GB+ recommended)
- Root privileges for hardware access
- Hardware interfaces (UART, SPI, I2C, GPIO, USB, Wireless)

### Dependencies

#### Core Libraries
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    make \
    pkg-config \
    git

# Hardware Interface Libraries
sudo apt-get install -y \
    libpcap-dev \
    libusb-1.0-0-dev \
    libiw-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    libgpiod-dev

# Optional: Wireless Tools
sudo apt-get install -y \
    wireless-tools \
    iw \
    aircrack-ng
```

#### Zig Compiler (for side-channel analysis)
```bash
# Download and install Zig
wget https://ziglang.org/download/0.11.0/zig-linux-x86_64-0.11.0.tar.xz
tar -xf zig-linux-x86_64-0.11.0.tar.xz
sudo mv zig-linux-x86_64-0.11.0 /opt/zig
echo 'export PATH="/opt/zig:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

## 🔧 Building

### Quick Build
```bash
git clone https://github.com/ibrahmsql/iotstrike.git
cd framework
make clean
make all
```

### Platform-Specific Builds
```bash
# ARM cross-compilation
make arm

# MIPS cross-compilation
make mips

# Embedded systems
make embedded
```

### Build Targets
- `make all` - Build main framework and tools
- `make iotstrike` - Build main framework only
- `make tools` - Build CLI testing tools
- `make clean` - Clean build artifacts
- `make install` - Install to system
- `make test` - Run hardware validation tests

## 🚀 Quick Start

### 1. Hardware Validation
```bash
# Run comprehensive hardware tests
sudo ./build/iotstrike --all

# Test specific hardware
sudo ./build/hardware_test --uart /dev/ttyUSB0
sudo ./build/hardware_test --spi /dev/spidev0.0
sudo ./build/hardware_test --gpio 18
```

### 2. Wireless Security Testing
```bash
# Scan for wireless networks
sudo ./build/wireless_test --interface wlan0 --scan

# Test monitor mode
sudo ./build/wireless_test --interface wlan0 --monitor

# Capture packets
sudo ./build/wireless_test --interface wlan0 --capture packets.pcap --time 60

# WPS security test
sudo ./build/wireless_test --interface wlan0 --wps 00:11:22:33:44:55
```

### 3. Firmware Analysis
```bash
# Analyze firmware binary
sudo ./build/iotstrike --firmware firmware.bin

# Interactive mode
sudo ./build/iotstrike --interactive
```

### 4. Hardware Interface Testing
```bash
# UART communication test
sudo ./build/iotstrike --hardware --target uart:/dev/ttyUSB0:115200

# SPI device interaction
sudo ./build/iotstrike --hardware --target spi:/dev/spidev0.0:1000000

# I2C device scanning
sudo ./build/iotstrike --hardware --target i2c:/dev/i2c-1
```

## 📖 Usage Examples

### Example 1: IoT Device Security Assessment
```bash
# Step 1: Hardware discovery
sudo ./build/iotstrike --hardware

# Step 2: Firmware extraction and analysis
sudo ./build/iotstrike --firmware extracted_firmware.bin

# Step 3: Wireless security testing
sudo ./build/wireless_test --interface wlan0 --scan
sudo ./build/wireless_test --interface wlan0 --wps TARGET_BSSID

# Step 4: Hardware interface testing
sudo ./build/hardware_test --uart /dev/ttyUSB0 --verbose
sudo ./build/hardware_test --spi /dev/spidev0.0 --verbose
```

### Example 2: Real-time Attack Simulation
```bash
# Timing attack on cryptographic operations
sudo ./build/iotstrike --realtime --target uart:/dev/ttyUSB0

# Side-channel power analysis
sudo ./build/iotstrike --sidechannel --samples 10000
```

### Example 3: Custom Hardware Testing
```bash
# GPIO manipulation for hardware debugging
sudo ./build/hardware_test --gpio 18 --verbose
sudo ./build/hardware_test --gpio 19 --verbose

# USB device enumeration and testing
sudo ./build/hardware_test --usb --verbose
```

## 🔧 Configuration

### Configuration File
Create `/etc/iotstrike/config.json`:
```json
{
  "hardware": {
    "uart_devices": ["/dev/ttyUSB0", "/dev/ttyACM0"],
    "spi_devices": ["/dev/spidev0.0", "/dev/spidev1.0"],
    "i2c_devices": ["/dev/i2c-1", "/dev/i2c-2"],
    "gpio_base": 0,
    "default_timeout": 5000
  },
  "wireless": {
    "default_interface": "wlan0",
    "monitor_mode": true,
    "packet_injection": true
  },
  "security": {
    "level": "high",
    "memory_protection": true,
    "privilege_dropping": true
  },
  "logging": {
    "level": "info",
    "file": "/var/log/iotstrike.log",
    "console": true
  }
}
```

### Environment Variables
```bash
export IOTSTRIKE_CONFIG="/etc/iotstrike/config.json"
export IOTSTRIKE_LOG_LEVEL="debug"
export IOTSTRIKE_HARDWARE_TIMEOUT="10000"
```

## 🏗️ Architecture

### Core Components
```
IoTStrike Framework
├── Core Engine (C)
│   ├── Hardware Abstraction Layer
│   ├── Memory Management
│   ├── Error Handling
│   └── Threading
├── Hardware Modules (C)
│   ├── UART/Serial
│   ├── SPI
│   ├── I2C
│   ├── GPIO
│   ├── USB
│   └── Wireless
├── Security Modules (C)
│   ├── Firmware Analysis
│   ├── Wireless Exploitation
│   ├── Real-time Attacks
│   └── Hardware Debugging
├── Side-channel Analysis (Zig)
│   ├── Power Analysis
│   ├── EM Analysis
│   └── Timing Analysis
├── Assembly Utilities (ASM)
│   ├── Low-level Hardware Access
│   ├── Timing-critical Operations
│   └── Platform-specific Code
└── CLI Tools (C)
    ├── Hardware Test
    ├── Wireless Test
    └── Firmware Analyzer
```

## 🔒 Security Features

### Memory Protection
- Stack canary protection
- Buffer overflow detection
- Secure memory zeroization
- Memory leak prevention

### Privilege Management
- Automatic privilege dropping
- Capability-based security
- Sandboxed execution
- Resource limiting

### Secure Communication
- Encrypted data transmission
- Authentication mechanisms
- Secure key storage
- Certificate validation

## 🧪 Testing

### Hardware Validation
```bash
# Run all hardware tests
make test

# Individual component tests
sudo ./build/hardware_test --all --verbose
sudo ./build/wireless_test --interface wlan0 --monitor
```

### Unit Tests
```bash
# Run unit tests (when implemented)
make unittest

# Memory leak testing
valgrind --leak-check=full ./build/iotstrike --help
```

## 📊 Supported Platforms

### Primary Platforms
- **Raspberry Pi** (ARM)
- **BeagleBone** (ARM)
- **Arduino** (AVR/ARM)
- **Linux Embedded** (Various)
- **RISC-V** (Experimental)

### Operating Systems
- Ubuntu 20.04+
- Debian 10+
- Raspbian
- OpenWrt
- Buildroot

### Hardware Interfaces
- UART/USART
- SPI (Master/Slave)
- I2C/TWI
- GPIO
- USB (Host/Device)
- Ethernet
- WiFi (802.11)
- Bluetooth
- Zigbee
- LoRa/LoRaWAN

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/ibrahmsql/iotstrike.git
cd framework
git checkout -b feature/new-feature

# Make changes
make clean && make all
make test

# Submit pull request
```

### Coding Standards
- C99 standard compliance
- Memory-safe programming practices
- Comprehensive error handling
- Detailed documentation
- Hardware validation tests

### Adding New Hardware Support
1. Implement HAL functions in `src/hardware/`
2. Add header definitions in `include/`
3. Create test cases in `tools/`
4. Update documentation
5. Submit pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

### Community
- **GitHub Issues**: [Report bugs and request features](https://github.com/ibrahmsql/iotstrike/issues)
- **Discussions**: [Community discussions](https://github.com/ibrahmsql/iotstrike/discussions)
- **Wiki**: [Documentation and tutorials](https://github.com/ibrahmsql/iotstrike/wiki)

### Project Structure Notes
- **`/lib` Directory**: Currently empty - will contain compiled libraries after build
- **`/docs` Directory**: Currently empty - reserved for future documentation files
- **Build Output**: Compiled binaries and libraries are generated in `/build` directory

### Professional Support
- **Email**: [ibrahimsql@proton.me]
- **Consulting**: Hardware security assessments
- **Training**: IoT security workshops

## 🙏 Acknowledgments

- Hardware security research community
- Open source contributors
- IoT security researchers
- Embedded systems developers

## 📈 Roadmap

### Version 1.1 (Q2 2025)
- [ ] CAN bus support
- [ ] LIN bus support
- [ ] Enhanced Zigbee support
- [ ] Web interface
- [ ] REST API

### Version 1.2 (Q3 2026)
- [ ] Machine learning integration
- [ ] Automated vulnerability detection
- [ ] Cloud integration
- [ ] Mobile app

### Version 2.0 (Q4 2028)
- [ ] GUI application
- [ ] Plugin marketplace
- [ ] Enterprise features
- [ ] Advanced analytics

---

**IoTStrike Hardware Security Framework** - Securing the IoT ecosystem, one device at a time.