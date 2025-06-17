/**
 * IoTStrike Hardware Security Framework
 * Hardware Validation Tests
 * 
 * @file hardware_validation.c
 * @author ibrahimsql
 * @version 1.0.0
 */

#include "iotstrike.h"
#include "hardware.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

/**
 * Test UART hardware availability
 */
static iotstrike_error_t test_uart_hardware(void) {
    printf("[TEST] Checking UART hardware...\n");
    
    const char* uart_devices[] = {
        "/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
        "/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2",
        "/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2"
    };
    
    int available_count = 0;
    for (size_t i = 0; i < sizeof(uart_devices) / sizeof(uart_devices[0]); i++) {
        if (access(uart_devices[i], F_OK) == 0) {
            printf("  [OK] Found UART device: %s\n", uart_devices[i]);
            available_count++;
        }
    }
    
    if (available_count == 0) {
        printf("  [WARNING] No UART devices found\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [INFO] Found %d UART device(s)\n", available_count);
    return IOTSTRIKE_SUCCESS;
}

/**
 * Test SPI hardware availability
 */
static iotstrike_error_t test_spi_hardware(void) {
    printf("[TEST] Checking SPI hardware...\n");
    
    const char* spi_devices[] = {
        "/dev/spidev0.0", "/dev/spidev0.1",
        "/dev/spidev1.0", "/dev/spidev1.1",
        "/dev/spidev2.0", "/dev/spidev2.1"
    };
    
    int available_count = 0;
    for (size_t i = 0; i < sizeof(spi_devices) / sizeof(spi_devices[0]); i++) {
        if (access(spi_devices[i], F_OK) == 0) {
            printf("  [OK] Found SPI device: %s\n", spi_devices[i]);
            available_count++;
        }
    }
    
    if (available_count == 0) {
        printf("  [WARNING] No SPI devices found\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [INFO] Found %d SPI device(s)\n", available_count);
    return IOTSTRIKE_SUCCESS;
}

/**
 * Test I2C hardware availability
 */
static iotstrike_error_t test_i2c_hardware(void) {
    printf("[TEST] Checking I2C hardware...\n");
    
    const char* i2c_devices[] = {
        "/dev/i2c-0", "/dev/i2c-1", "/dev/i2c-2",
        "/dev/i2c-3", "/dev/i2c-4", "/dev/i2c-5"
    };
    
    int available_count = 0;
    for (size_t i = 0; i < sizeof(i2c_devices) / sizeof(i2c_devices[0]); i++) {
        if (access(i2c_devices[i], F_OK) == 0) {
            printf("  [OK] Found I2C device: %s\n", i2c_devices[i]);
            available_count++;
        }
    }
    
    if (available_count == 0) {
        printf("  [WARNING] No I2C devices found\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [INFO] Found %d I2C device(s)\n", available_count);
    return IOTSTRIKE_SUCCESS;
}

/**
 * Test GPIO hardware availability
 */
static iotstrike_error_t test_gpio_hardware(void) {
    printf("[TEST] Checking GPIO hardware...\n");
    
    // Check if GPIO sysfs interface is available
    if (access("/sys/class/gpio", F_OK) != 0) {
        printf("  [ERROR] GPIO sysfs interface not available\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [OK] GPIO sysfs interface available\n");
    
    // Check for gpiochip devices
    const char* gpio_chips[] = {
        "/dev/gpiochip0", "/dev/gpiochip1", "/dev/gpiochip2",
        "/dev/gpiochip3", "/dev/gpiochip4"
    };
    
    int available_count = 0;
    for (size_t i = 0; i < sizeof(gpio_chips) / sizeof(gpio_chips[0]); i++) {
        if (access(gpio_chips[i], F_OK) == 0) {
            printf("  [OK] Found GPIO chip: %s\n", gpio_chips[i]);
            available_count++;
        }
    }
    
    if (available_count == 0) {
        printf("  [WARNING] No GPIO chips found\n");
    } else {
        printf("  [INFO] Found %d GPIO chip(s)\n", available_count);
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Test USB hardware availability
 */
static iotstrike_error_t test_usb_hardware(void) {
    printf("[TEST] Checking USB hardware...\n");
    
    // Check if USB subsystem is available
    if (access("/sys/bus/usb", F_OK) != 0) {
        printf("  [ERROR] USB subsystem not available\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [OK] USB subsystem available\n");
    
#ifdef HAVE_LIBUSB
    // Test libusb initialization
    libusb_context *ctx = NULL;
    int result = libusb_init(&ctx);
    if (result < 0) {
        printf("  [ERROR] Failed to initialize libusb: %s\n", libusb_error_name(result));
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    // Get device list
    libusb_device **devices;
    ssize_t device_count = libusb_get_device_list(ctx, &devices);
    if (device_count < 0) {
        printf("  [ERROR] Failed to get USB device list\n");
        libusb_exit(ctx);
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    printf("  [OK] Found %zd USB device(s)\n", device_count);
    
    libusb_free_device_list(devices, 1);
    libusb_exit(ctx);
    
    return IOTSTRIKE_SUCCESS;
#else
    printf("  [WARNING] libusb not available - USB testing disabled\n");
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Test wireless hardware availability
 */
static iotstrike_error_t test_wireless_hardware(void) {
    printf("[TEST] Checking wireless hardware...\n");
    
    // Check for wireless interfaces
    if (access("/proc/net/wireless", F_OK) != 0) {
        printf("  [WARNING] Wireless subsystem not available\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [OK] Wireless subsystem available\n");
    
    // Check for common wireless interface names
    const char* wireless_interfaces[] = {
        "/sys/class/net/wlan0", "/sys/class/net/wlan1",
        "/sys/class/net/wlp2s0", "/sys/class/net/wlp3s0",
        "/sys/class/net/wifi0", "/sys/class/net/wifi1"
    };
    
    int available_count = 0;
    for (size_t i = 0; i < sizeof(wireless_interfaces) / sizeof(wireless_interfaces[0]); i++) {
        if (access(wireless_interfaces[i], F_OK) == 0) {
            printf("  [OK] Found wireless interface: %s\n", 
                   strrchr(wireless_interfaces[i], '/') + 1);
            available_count++;
        }
    }
    
    if (available_count == 0) {
        printf("  [WARNING] No wireless interfaces found\n");
    } else {
        printf("  [INFO] Found %d wireless interface(s)\n", available_count);
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Test memory and CPU capabilities
 */
static iotstrike_error_t test_system_capabilities(void) {
    printf("[TEST] Checking system capabilities...\n");
    
    // Check available memory
    FILE *meminfo = fopen("/proc/meminfo", "r");
    if (meminfo) {
        char line[256];
        while (fgets(line, sizeof(line), meminfo)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                unsigned long mem_kb;
                if (sscanf(line, "MemTotal: %lu kB", &mem_kb) == 1) {
                    printf("  [INFO] Total memory: %lu MB\n", mem_kb / 1024);
                    if (mem_kb < 512 * 1024) { // Less than 512MB
                        printf("  [WARNING] Low memory system detected\n");
                    }
                }
                break;
            }
        }
        fclose(meminfo);
    }
    
    // Check CPU information
    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (cpuinfo) {
        char line[256];
        int cpu_count = 0;
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "processor", 9) == 0) {
                cpu_count++;
            }
        }
        printf("  [INFO] CPU cores: %d\n", cpu_count);
        fclose(cpuinfo);
    }
    
    // Check for high-resolution timers
    if (access("/proc/timer_list", F_OK) == 0) {
        printf("  [OK] High-resolution timers available\n");
    } else {
        printf("  [WARNING] High-resolution timers not available\n");
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run comprehensive hardware validation
 */
iotstrike_error_t run_hardware_validation(void) {
    printf("\n=== Hardware Validation Tests ===\n");
    
    iotstrike_error_t overall_result = IOTSTRIKE_SUCCESS;
    int passed_tests = 0;
    int total_tests = 7;
    
    // Run individual tests
    if (test_uart_hardware() == IOTSTRIKE_SUCCESS) passed_tests++;
    if (test_spi_hardware() == IOTSTRIKE_SUCCESS) passed_tests++;
    if (test_i2c_hardware() == IOTSTRIKE_SUCCESS) passed_tests++;
    if (test_gpio_hardware() == IOTSTRIKE_SUCCESS) passed_tests++;
    if (test_usb_hardware() == IOTSTRIKE_SUCCESS) passed_tests++;
    if (test_wireless_hardware() == IOTSTRIKE_SUCCESS) passed_tests++;
    if (test_system_capabilities() == IOTSTRIKE_SUCCESS) passed_tests++;
    
    printf("\n=== Validation Summary ===\n");
    printf("Tests passed: %d/%d\n", passed_tests, total_tests);
    
    if (passed_tests < total_tests / 2) {
        printf("[ERROR] Critical hardware validation failure\n");
        overall_result = IOTSTRIKE_ERROR_HARDWARE;
    } else if (passed_tests < total_tests) {
        printf("[WARNING] Some hardware components not available\n");
        overall_result = IOTSTRIKE_SUCCESS; // Continue with warnings
    } else {
        printf("[OK] All hardware validation tests passed\n");
    }
    
    printf("================================\n\n");
    
    return overall_result;
}

/**
 * Get platform string for current system
 */
const char* get_platform_string(void) {
#if defined(__arm__) || defined(__aarch64__)
    return "ARM";
#elif defined(__x86_64__) || defined(__amd64__)
    return "x86_64";
#elif defined(__i386__)
    return "x86";
#elif defined(__mips__)
    return "MIPS";
#elif defined(__riscv)
    return "RISC-V";
#else
    return "Unknown";
#endif
}