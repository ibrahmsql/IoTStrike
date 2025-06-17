# Contributing to IoTStrike Hardware Security Framework

We welcome contributions to the IoTStrike Hardware Security Framework! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security Considerations](#security-considerations)
- [Hardware Support](#hardware-support)
- [Community](#community)

## Code of Conduct

### Our Pledge

We are committed to making participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes:**
- The use of sexualized language or imagery
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information without explicit permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported by contacting the project team at [ibrahimsql@proton.me]. All complaints will be reviewed and investigated promptly and fairly.

## Getting Started

### Prerequisites

- **C Programming**: Strong knowledge of C99 standard
- **Linux Systems**: Understanding of Linux kernel interfaces
- **Hardware Interfaces**: Familiarity with UART, SPI, I2C, GPIO, USB
- **Security Concepts**: Knowledge of hardware security principles
- **Git**: Version control system proficiency

### First Contribution

Looking for a good first issue? Check out:
- Issues labeled `good first issue`
- Issues labeled `help wanted`
- Documentation improvements
- Test case additions
- Hardware driver implementations

## Development Environment

### System Requirements

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    gcc \
    make \
    pkg-config \
    git \
    valgrind \
    gdb \
    clang-format \
    cppcheck \
    doxygen

# Hardware libraries
sudo apt-get install -y \
    libpcap-dev \
    libusb-1.0-0-dev \
    libiw-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    libgpiod-dev
```

### Development Tools

```bash
# Static analysis
sudo apt-get install -y cppcheck clang-static-analyzer

# Memory debugging
sudo apt-get install -y valgrind

# Code formatting
sudo apt-get install -y clang-format

# Documentation
sudo apt-get install -y doxygen graphviz
```

### Setting Up the Development Environment

```bash
# Clone the repository
git clone https://github.com/iotstrike/framework.git
cd framework

# Create development branch
git checkout -b feature/your-feature-name

# Build the project
make clean
make all

# Run tests
make test

# Run static analysis
make analyze
```

## Contributing Process

### 1. Fork and Clone

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/framework.git
cd framework

# Add upstream remote
git remote add upstream https://github.com/iotstrike/framework.git
```

### 2. Create a Branch

```bash
# Create and switch to a new branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b bugfix/issue-number-description

# Or for documentation
git checkout -b docs/documentation-improvement
```

### 3. Make Changes

- Write clean, well-documented code
- Follow the coding standards
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Commit Changes

```bash
# Stage your changes
git add .

# Commit with descriptive message
git commit -m "feat: add SPI device enumeration support

- Implement spi_enumerate_devices() function
- Add support for multiple SPI buses
- Include error handling for device detection
- Add unit tests for enumeration logic

Closes #123"
```

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
# Fill out the pull request template
```

### 6. Code Review Process

- Maintainers will review your pull request
- Address any feedback or requested changes
- Once approved, your changes will be merged

## Coding Standards

### C Code Style

#### Naming Conventions

```c
// Functions: snake_case
int hardware_init(void);
int uart_configure(int fd, uart_config_t *config);

// Variables: snake_case
int device_count;
char *buffer_ptr;

// Constants: UPPER_SNAKE_CASE
#define MAX_BUFFER_SIZE 1024
#define DEFAULT_TIMEOUT 5000

// Structures: snake_case with _t suffix
typedef struct {
    int fd;
    uint32_t baudrate;
    uint8_t data_bits;
} uart_config_t;

// Enums: snake_case with _e suffix
typedef enum {
    IOTSTRIKE_SUCCESS = 0,
    IOTSTRIKE_ERROR_INVALID_PARAM = -1,
    IOTSTRIKE_ERROR_HARDWARE = -2
} iotstrike_result_e;
```

#### Code Formatting

```c
// Use 4 spaces for indentation (no tabs)
// Brace style: Allman
if (condition)
{
    // Code here
    function_call();
}
else
{
    // Alternative code
    other_function();
}

// Function definitions
int function_name(int param1, char *param2)
{
    // Function body
    return 0;
}

// Pointer declarations
char *ptr;          // Preferred
char* ptr;          // Avoid
char * ptr;         // Avoid
```

#### Error Handling

```c
// Always check return values
int result = hardware_init();
if (result != IOTSTRIKE_SUCCESS)
{
    log_error("Hardware initialization failed: %d", result);
    return result;
}

// Use goto for cleanup in complex functions
int complex_function(void)
{
    char *buffer = NULL;
    int fd = -1;
    int result = IOTSTRIKE_SUCCESS;
    
    buffer = malloc(BUFFER_SIZE);
    if (!buffer)
    {
        result = IOTSTRIKE_ERROR_MEMORY;
        goto cleanup;
    }
    
    fd = open("/dev/device", O_RDWR);
    if (fd < 0)
    {
        result = IOTSTRIKE_ERROR_HARDWARE;
        goto cleanup;
    }
    
    // Main logic here
    
cleanup:
    if (buffer) free(buffer);
    if (fd >= 0) close(fd);
    return result;
}
```

#### Memory Management

```c
// Always initialize pointers
char *buffer = NULL;

// Check malloc return values
buffer = malloc(size);
if (!buffer)
{
    return IOTSTRIKE_ERROR_MEMORY;
}

// Zero sensitive memory
memset_s(password, sizeof(password), 0, sizeof(password));

// Free and nullify
free(buffer);
buffer = NULL;
```

### Header Files

```c
// Header guard
#ifndef IOTSTRIKE_MODULE_H
#define IOTSTRIKE_MODULE_H

// System includes first
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Local includes
#include "iotstrike.h"
#include "hardware.h"

// Constants
#define MODULE_VERSION "1.0.0"
#define MAX_DEVICES 16

// Type definitions
typedef struct module_config module_config_t;

// Function prototypes
int module_init(const module_config_t *config);
void module_cleanup(void);

#endif // IOTSTRIKE_MODULE_H
```

### Documentation Standards

```c
/**
 * @brief Initialize UART communication interface
 * 
 * This function initializes the UART interface with the specified
 * configuration parameters. It opens the device file, configures
 * the terminal settings, and prepares the interface for communication.
 * 
 * @param device_path Path to the UART device (e.g., "/dev/ttyUSB0")
 * @param config Pointer to UART configuration structure
 * @param timeout_ms Timeout in milliseconds for operations
 * 
 * @return File descriptor on success, negative error code on failure
 * @retval >= 0 Valid file descriptor
 * @retval IOTSTRIKE_ERROR_INVALID_PARAM Invalid parameters
 * @retval IOTSTRIKE_ERROR_HARDWARE Hardware access failed
 * 
 * @note This function requires root privileges for device access
 * @warning The returned file descriptor must be closed with uart_close()
 * 
 * @see uart_close(), uart_configure()
 * 
 * @example
 * @code
 * uart_config_t config = {
 *     .baudrate = 115200,
 *     .data_bits = 8,
 *     .stop_bits = 1,
 *     .parity = UART_PARITY_NONE
 * };
 * 
 * int fd = uart_init("/dev/ttyUSB0", &config, 5000);
 * if (fd < 0) {
 *     fprintf(stderr, "UART initialization failed\n");
 *     return -1;
 * }
 * @endcode
 */
int uart_init(const char *device_path, const uart_config_t *config, int timeout_ms);
```

## Testing Guidelines

### Unit Tests

```c
// test_uart.c
#include "unity.h"
#include "uart.h"

void setUp(void)
{
    // Setup before each test
}

void tearDown(void)
{
    // Cleanup after each test
}

void test_uart_init_valid_params(void)
{
    uart_config_t config = {
        .baudrate = 115200,
        .data_bits = 8,
        .stop_bits = 1,
        .parity = UART_PARITY_NONE
    };
    
    // Mock the hardware for testing
    int result = uart_init_mock(&config);
    TEST_ASSERT_EQUAL(IOTSTRIKE_SUCCESS, result);
}

void test_uart_init_invalid_params(void)
{
    int result = uart_init_mock(NULL);
    TEST_ASSERT_EQUAL(IOTSTRIKE_ERROR_INVALID_PARAM, result);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_uart_init_valid_params);
    RUN_TEST(test_uart_init_invalid_params);
    return UNITY_END();
}
```

### Hardware Tests

```c
// test_hardware_uart.c - Real hardware testing
#include "hardware_test.h"

int test_uart_loopback(const char *device)
{
    uart_config_t config = {
        .baudrate = 115200,
        .data_bits = 8,
        .stop_bits = 1,
        .parity = UART_PARITY_NONE
    };
    
    int fd = uart_init(device, &config, 5000);
    if (fd < 0)
    {
        return TEST_FAIL;
    }
    
    // Test data
    const char *test_data = "Hello, IoTStrike!";
    char receive_buffer[64] = {0};
    
    // Send data
    int sent = uart_send(fd, test_data, strlen(test_data));
    if (sent != strlen(test_data))
    {
        uart_close(fd);
        return TEST_FAIL;
    }
    
    // Receive data (assuming loopback)
    int received = uart_receive(fd, receive_buffer, sizeof(receive_buffer) - 1, 1000);
    if (received != strlen(test_data))
    {
        uart_close(fd);
        return TEST_FAIL;
    }
    
    // Verify data
    if (strcmp(test_data, receive_buffer) != 0)
    {
        uart_close(fd);
        return TEST_FAIL;
    }
    
    uart_close(fd);
    return TEST_PASS;
}
```

### Test Execution

```bash
# Run all tests
make test

# Run specific test suite
make test-uart
make test-spi
make test-wireless

# Run with memory checking
make test-valgrind

# Run hardware tests (requires hardware)
make test-hardware

# Generate coverage report
make coverage
```

## Documentation

### Code Documentation

- Use Doxygen-style comments for all public functions
- Include parameter descriptions and return values
- Provide usage examples for complex functions
- Document any side effects or requirements

### README Updates

- Update feature lists for new capabilities
- Add usage examples for new functionality
- Update installation instructions if needed
- Include any new dependencies

### API Documentation

```bash
# Generate API documentation
make docs

# View generated documentation
open docs/html/index.html
```

## Security Considerations

### Security Review Checklist

- [ ] Input validation for all user inputs
- [ ] Buffer overflow protection
- [ ] Integer overflow checks
- [ ] Secure memory handling
- [ ] Proper error handling
- [ ] Privilege escalation prevention
- [ ] Resource leak prevention
- [ ] Thread safety (if applicable)

### Security Testing

```bash
# Static analysis
make analyze

# Memory safety testing
valgrind --tool=memcheck --leak-check=full ./build/iotstrike

# Address sanitizer
make CFLAGS="-fsanitize=address" clean all

# Thread sanitizer (if applicable)
make CFLAGS="-fsanitize=thread" clean all
```

### Secure Coding Practices

```c
// Input validation
int validate_input(const char *input, size_t max_len)
{
    if (!input || strlen(input) >= max_len)
    {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    // Additional validation logic
    return IOTSTRIKE_SUCCESS;
}

// Safe string operations
int safe_copy(char *dest, size_t dest_size, const char *src)
{
    if (!dest || !src || dest_size == 0)
    {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    size_t src_len = strlen(src);
    if (src_len >= dest_size)
    {
        return IOTSTRIKE_ERROR_BUFFER_TOO_SMALL;
    }
    
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
    
    return IOTSTRIKE_SUCCESS;
}
```

## Hardware Support

### Adding New Hardware Support

1. **Create Hardware Abstraction Layer (HAL)**:
   ```c
   // src/hardware/new_hardware.c
   #include "new_hardware.h"
   
   int new_hardware_init(const new_hardware_config_t *config)
   {
       // Implementation
   }
   
   int new_hardware_operation(int param)
   {
       // Implementation
   }
   
   void new_hardware_cleanup(void)
   {
       // Implementation
   }
   ```

2. **Create Header File**:
   ```c
   // include/new_hardware.h
   #ifndef IOTSTRIKE_NEW_HARDWARE_H
   #define IOTSTRIKE_NEW_HARDWARE_H
   
   typedef struct {
       // Configuration parameters
   } new_hardware_config_t;
   
   int new_hardware_init(const new_hardware_config_t *config);
   int new_hardware_operation(int param);
   void new_hardware_cleanup(void);
   
   #endif
   ```

3. **Add Test Cases**:
   ```c
   // tools/test_new_hardware.c
   #include "hardware_test.h"
   #include "new_hardware.h"
   
   int test_new_hardware(void)
   {
       // Test implementation
   }
   ```

4. **Update Build System**:
   ```makefile
   # Add to Makefile
   SRCS += src/hardware/new_hardware.c
   TOOLS += tools/test_new_hardware
   ```

5. **Update Documentation**:
   - Add to README.md
   - Update hardware support list
   - Include usage examples

### Hardware Testing Requirements

- All hardware modules must include test cases
- Tests should work with common development boards
- Include both unit tests and integration tests
- Document required hardware connections
- Provide simulation/mock options for CI

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Pull Requests**: Code contributions and reviews
- **Email**: [ibrahimsql@proton.me] for security issues

### Getting Help

- Check existing issues and documentation first
- Provide detailed information when asking questions
- Include relevant code snippets and error messages
- Be patient and respectful in all interactions

### Recognition

We recognize contributors in several ways:
- Contributors list in README.md
- Release notes acknowledgments
- Security researchers hall of fame
- Annual contributor awards

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version numbers bumped
- [ ] Security review completed
- [ ] Performance benchmarks run
- [ ] Cross-platform testing completed

---

Thank you for contributing to the IoTStrike Hardware Security Framework! Your contributions help make IoT and embedded systems more secure.

For questions about contributing, please contact [ibrahimsql@proton.me] or open an issue on GitHub.