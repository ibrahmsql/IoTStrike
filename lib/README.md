# IoTStrike Libraries

This directory contains compiled libraries for the IoTStrike Hardware Security Framework.

## Library Files

After building the project with `make`, you will find:

- **`libiotstrike.so`** (Linux/macOS) or **`libiotstrike.dll`** (Windows)
  - Main shared library containing core IoTStrike functionality
  - Used for linking with external applications

## Usage

### Linking with Your Application

```bash
# Compile your application with IoTStrike library
gcc -o myapp myapp.c -L./lib -liotstrike -I./include
```

### Installation

To install libraries system-wide:

```bash
make install
```

This will copy libraries to:
- Linux: `/usr/local/lib/`
- macOS: `/usr/local/lib/`
- Windows: System directory

## Library Dependencies

The IoTStrike library depends on:
- OpenSSL (crypto, ssl)
- libpcap (packet capture)
- pthread (threading)
- Standard math library (m)

## Development

For development builds:

```bash
# Debug build
make debug

# Release build
make release

# Clean build artifacts
make clean
```

## Notes

- Libraries are automatically generated during the build process
- This directory may be empty until you run `make`
- Ensure all dependencies are installed before building