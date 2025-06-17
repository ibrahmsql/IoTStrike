/**
 * IoTStrike Hardware Security Framework
 * Hardware Test CLI Tool
 * 
 * @file hardware_test.c
 * @author ibrahimsql
 * @version 1.0.0
 */

#include "../include/iotstrike.h"
#include "../include/hardware.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nHardware Test Tool for IoTStrike Framework\n\n");
    printf("Options:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -v, --verbose        Enable verbose output\n");
    printf("  -u, --uart DEVICE    Test UART device\n");
    printf("  -s, --spi DEVICE     Test SPI device\n");
    printf("  -i, --i2c DEVICE     Test I2C device\n");
    printf("  -g, --gpio PIN       Test GPIO pin\n");
    printf("  -U, --usb            Test USB devices\n");
    printf("  -w, --wireless       Test wireless interfaces\n");
    printf("  -a, --all            Test all available hardware\n");
    printf("\nExamples:\n");
    printf("  %s --uart /dev/ttyUSB0\n", program_name);
    printf("  %s --spi /dev/spidev0.0\n", program_name);
    printf("  %s --i2c /dev/i2c-1\n", program_name);
    printf("  %s --gpio 18\n", program_name);
    printf("  %s --all\n", program_name);
}

static iotstrike_error_t test_uart_device(const char *device, bool verbose) {
    printf("Testing UART device: %s\n", device);
    
    uart_config_t config;
    iotstrike_error_t result = uart_init(&config, device);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot initialize UART device\n");
        return result;
    }
    
    // Configure UART
    result = uart_configure(&config, 115200, 8, UART_STOP_1, UART_PARITY_NONE);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot configure UART device\n");
        uart_close(&config);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] UART configured: 115200 8N1\n");
    }
    
    // Test data transmission
    const char *test_data = "IoTStrike Test\n";
    result = uart_send(&config, (const uint8_t*)test_data, strlen(test_data));
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot send data to UART\n");
        uart_close(&config);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] Test data sent successfully\n");
    }
    
    // Test data reception (with timeout)
    uint8_t buffer[256];
    size_t received;
    result = uart_receive(&config, buffer, sizeof(buffer), &received);
    if (result == IOTSTRIKE_SUCCESS && received > 0) {
        if (verbose) {
            printf("  [INFO] Received %zu bytes\n", received);
        }
    }
    
    uart_close(&config);
    printf("  [PASS] UART test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_spi_device(const char *device, bool verbose) {
    printf("Testing SPI device: %s\n", device);
    
    spi_config_t config;
    iotstrike_error_t result = spi_init(&config, device);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot initialize SPI device\n");
        return result;
    }
    
    // Configure SPI
    result = spi_configure(&config, 1000000, SPI_MODE_0, 8);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot configure SPI device\n");
        spi_close(&config);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] SPI configured: 1MHz, Mode 0, 8 bits\n");
    }
    
    // Test SPI transfer
    uint8_t tx_data[] = {0xAA, 0x55, 0xFF, 0x00};
    uint8_t rx_data[sizeof(tx_data)];
    
    result = spi_transfer(&config, tx_data, rx_data, sizeof(tx_data));
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] SPI transfer failed\n");
        spi_close(&config);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] SPI transfer completed\n");
        printf("  [INFO] TX: ");
        for (size_t i = 0; i < sizeof(tx_data); i++) {
            printf("0x%02X ", tx_data[i]);
        }
        printf("\n");
        printf("  [INFO] RX: ");
        for (size_t i = 0; i < sizeof(rx_data); i++) {
            printf("0x%02X ", rx_data[i]);
        }
        printf("\n");
    }
    
    spi_close(&config);
    printf("  [PASS] SPI test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_i2c_device(const char *device, bool verbose) {
    printf("Testing I2C device: %s\n", device);
    
    i2c_config_t config;
    iotstrike_error_t result = i2c_init(&config, device, 0x50); // EEPROM address
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot initialize I2C device\n");
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] I2C initialized with slave address 0x50\n");
    }
    
    // Scan for I2C devices
    uint8_t addresses[128];
    size_t count;
    result = i2c_scan(&config, addresses, &count);
    if (result == IOTSTRIKE_SUCCESS) {
        printf("  [INFO] Found %zu I2C device(s)\n", count);
        if (verbose && count > 0) {
            printf("  [INFO] Addresses: ");
            for (size_t i = 0; i < count; i++) {
                printf("0x%02X ", addresses[i]);
            }
            printf("\n");
        }
    }
    
    i2c_close(&config);
    printf("  [PASS] I2C test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_gpio_pin(int pin, bool verbose) {
    printf("Testing GPIO pin: %d\n", pin);
    
    gpio_config_t config;
    iotstrike_error_t result = gpio_init(&config, pin, GPIO_MODE_OUTPUT);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot initialize GPIO pin\n");
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] GPIO pin %d initialized as output\n", pin);
    }
    
    // Test GPIO output
    result = gpio_set_state(&config, GPIO_STATE_HIGH);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot set GPIO high\n");
        gpio_cleanup(&config);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] GPIO set to HIGH\n");
    }
    
    usleep(100000); // 100ms delay
    
    result = gpio_set_state(&config, GPIO_STATE_LOW);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot set GPIO low\n");
        gpio_cleanup(&config);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] GPIO set to LOW\n");
    }
    
    // Test GPIO input
    gpio_cleanup(&config);
    result = gpio_init(&config, pin, GPIO_MODE_INPUT);
    if (result == IOTSTRIKE_SUCCESS) {
        gpio_state_t state;
        result = gpio_get_state(&config, &state);
        if (result == IOTSTRIKE_SUCCESS) {
            if (verbose) {
                printf("  [INFO] GPIO input state: %s\n", 
                       gpio_state_to_string(state));
            }
        }
    }
    
    gpio_cleanup(&config);
    printf("  [PASS] GPIO test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_usb_devices(bool verbose) {
    printf("Testing USB devices\n");
    
    usb_config_t configs[MAX_USB_DEVICES];
    size_t count;
    
    iotstrike_error_t result = usb_scan_devices(configs, &count);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot scan USB devices\n");
        return result;
    }
    
    printf("  [INFO] Found %zu USB device(s)\n", count);
    
    if (verbose && count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("  [INFO] Device %zu: VID=0x%04X, PID=0x%04X, Class=0x%02X\n",
                   i + 1, configs[i].vendor_id, configs[i].product_id, 
                   configs[i].device_class);
        }
    }
    
    printf("  [PASS] USB test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_all_hardware(bool verbose) {
    printf("\n=== Comprehensive Hardware Test ===\n");
    
    int passed = 0;
    int total = 0;
    
    // Test common UART devices
    const char* uart_devices[] = {"/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyS0"};
    for (size_t i = 0; i < sizeof(uart_devices) / sizeof(uart_devices[0]); i++) {
        if (access(uart_devices[i], F_OK) == 0) {
            total++;
            if (test_uart_device(uart_devices[i], verbose) == IOTSTRIKE_SUCCESS) {
                passed++;
            }
        }
    }
    
    // Test common SPI devices
    const char* spi_devices[] = {"/dev/spidev0.0", "/dev/spidev1.0"};
    for (size_t i = 0; i < sizeof(spi_devices) / sizeof(spi_devices[0]); i++) {
        if (access(spi_devices[i], F_OK) == 0) {
            total++;
            if (test_spi_device(spi_devices[i], verbose) == IOTSTRIKE_SUCCESS) {
                passed++;
            }
        }
    }
    
    // Test common I2C devices
    const char* i2c_devices[] = {"/dev/i2c-0", "/dev/i2c-1"};
    for (size_t i = 0; i < sizeof(i2c_devices) / sizeof(i2c_devices[0]); i++) {
        if (access(i2c_devices[i], F_OK) == 0) {
            total++;
            if (test_i2c_device(i2c_devices[i], verbose) == IOTSTRIKE_SUCCESS) {
                passed++;
            }
        }
    }
    
    // Test USB
    total++;
    if (test_usb_devices(verbose) == IOTSTRIKE_SUCCESS) {
        passed++;
    }
    
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d/%d tests\n", passed, total);
    
    return (passed > 0) ? IOTSTRIKE_SUCCESS : IOTSTRIKE_ERROR_HARDWARE;
}

int main(int argc, char *argv[]) {
    bool verbose = false;
    bool test_all = false;
    char *uart_device = NULL;
    char *spi_device = NULL;
    char *i2c_device = NULL;
    int gpio_pin = -1;
    bool test_usb = false;
    bool test_wireless = false;
    
    static struct option long_options[] = {
        {"help",     no_argument,       0, 'h'},
        {"verbose",  no_argument,       0, 'v'},
        {"uart",     required_argument, 0, 'u'},
        {"spi",      required_argument, 0, 's'},
        {"i2c",      required_argument, 0, 'i'},
        {"gpio",     required_argument, 0, 'g'},
        {"usb",      no_argument,       0, 'U'},
        {"wireless", no_argument,       0, 'w'},
        {"all",      no_argument,       0, 'a'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "hvu:s:i:g:Uwa", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            case 'v':
                verbose = true;
                break;
            case 'u':
                uart_device = optarg;
                break;
            case 's':
                spi_device = optarg;
                break;
            case 'i':
                i2c_device = optarg;
                break;
            case 'g':
                gpio_pin = atoi(optarg);
                break;
            case 'U':
                test_usb = true;
                break;
            case 'w':
                test_wireless = true;
                break;
            case 'a':
                test_all = true;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    printf("IoTStrike Hardware Test Tool v1.0.0\n");
    printf("=====================================\n\n");
    
    iotstrike_error_t result = IOTSTRIKE_SUCCESS;
    bool any_test_run = false;
    
    if (test_all) {
        result = test_all_hardware(verbose);
        any_test_run = true;
    } else {
        if (uart_device) {
            result = test_uart_device(uart_device, verbose);
            any_test_run = true;
        }
        
        if (spi_device) {
            result = test_spi_device(spi_device, verbose);
            any_test_run = true;
        }
        
        if (i2c_device) {
            result = test_i2c_device(i2c_device, verbose);
            any_test_run = true;
        }
        
        if (gpio_pin >= 0) {
            result = test_gpio_pin(gpio_pin, verbose);
            any_test_run = true;
        }
        
        if (test_usb) {
            result = test_usb_devices(verbose);
            any_test_run = true;
        }
    }
    
    if (!any_test_run) {
        printf("No tests specified. Use --help for usage information.\n");
        return EXIT_FAILURE;
    }
    
    return (result == IOTSTRIKE_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}