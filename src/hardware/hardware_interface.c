/**
 * IoTStrike Hardware Security Framework
 * Hardware Communication Interface Implementation
 * 
 * @file hardware_interface.c
 * @author ibrahimsql
 * @version 1.0.0
 */

#include "hardware.h"
#include <fcntl.h>
#include <errno.h>

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>
#include <linux/i2c-dev.h>
#endif

/**
 * Initialize hardware context
 */
iotstrike_error_t hardware_init(hardware_context_t *ctx) {
    if (!ctx) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(hardware_context_t));
    
#ifdef HAVE_LIBUSB
    /* Initialize libusb */
    int result = libusb_init(NULL);
    if (result < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
#endif
    
    ctx->initialized = true;
    return IOTSTRIKE_SUCCESS;
}

/**
 * Cleanup hardware context
 */
iotstrike_error_t hardware_cleanup(hardware_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Close all open devices */
    for (size_t i = 0; i < ctx->uart_count; i++) {
        uart_close(&ctx->uart_configs[i]);
    }
    
    for (size_t i = 0; i < ctx->spi_count; i++) {
        spi_close(&ctx->spi_configs[i]);
    }
    
    for (size_t i = 0; i < ctx->i2c_count; i++) {
        i2c_close(&ctx->i2c_configs[i]);
    }
    
    for (size_t i = 0; i < ctx->usb_count; i++) {
        usb_cleanup(&ctx->usb_configs[i]);
    }
    
#ifdef HAVE_LIBUSB
    /* Cleanup libusb */
    libusb_exit(NULL);
#endif
    
    ctx->initialized = false;
    return IOTSTRIKE_SUCCESS;
}

/**
 * UART Implementation
 */
iotstrike_error_t uart_init(uart_config_t *config, const char *device_path) {
    if (!config || !device_path) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(uart_config_t));
    strncpy(config->device_path, device_path, sizeof(config->device_path) - 1);
    
    config->fd = open(device_path, O_RDWR | O_NOCTTY | O_SYNC);
    if (config->fd < 0) {
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    /* Save original terminal settings */
    if (tcgetattr(config->fd, &config->old_termios) != 0) {
        close(config->fd);
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    /* Set default configuration */
    config->baudrate = DEFAULT_UART_BAUDRATE;
    config->data_bits = 8;
    config->stop_bits = UART_STOP_1;
    config->parity = UART_PARITY_NONE;
    config->flow_control = false;
    config->timeout = DEFAULT_TIMEOUT;
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t uart_configure(uart_config_t *config, uint32_t baudrate, uint8_t data_bits,
                                uart_stop_bits_t stop_bits, uart_parity_t parity) {
    if (!config || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    
    if (tcgetattr(config->fd, &tty) != 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    /* Set baud rate */
    speed_t speed;
    switch (baudrate) {
        case 9600: speed = B9600; break;
        case 19200: speed = B19200; break;
        case 38400: speed = B38400; break;
        case 57600: speed = B57600; break;
        case 115200: speed = B115200; break;
        case 230400: speed = B230400; break;
#ifdef B460800
        case 460800: speed = B460800; break;
#endif
#ifdef B921600
        case 921600: speed = B921600; break;
#endif
        default: return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    cfsetospeed(&tty, speed);
    cfsetispeed(&tty, speed);
    
    /* Set data bits */
    tty.c_cflag &= ~CSIZE;
    switch (data_bits) {
        case 5: tty.c_cflag |= CS5; break;
        case 6: tty.c_cflag |= CS6; break;
        case 7: tty.c_cflag |= CS7; break;
        case 8: tty.c_cflag |= CS8; break;
        default: return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Set stop bits */
    if (stop_bits == UART_STOP_2) {
        tty.c_cflag |= CSTOPB;
    } else {
        tty.c_cflag &= ~CSTOPB;
    }
    
    /* Set parity */
    switch (parity) {
        case UART_PARITY_NONE:
            tty.c_cflag &= ~PARENB;
            break;
        case UART_PARITY_EVEN:
            tty.c_cflag |= PARENB;
            tty.c_cflag &= ~PARODD;
            break;
        case UART_PARITY_ODD:
            tty.c_cflag |= PARENB | PARODD;
            break;
        default:
            return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Configure for raw mode */
    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_oflag &= ~OPOST;
    
    /* Set timeout */
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = config->timeout / 100; /* Convert to deciseconds */
    
    if (tcsetattr(config->fd, TCSANOW, &tty) != 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    /* Update configuration */
    config->baudrate = baudrate;
    config->data_bits = data_bits;
    config->stop_bits = stop_bits;
    config->parity = parity;
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t uart_send(uart_config_t *config, const uint8_t *data, size_t size) {
    if (!config || !data || size == 0 || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ssize_t bytes_written = write(config->fd, data, size);
    if (bytes_written < 0) {
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    if ((size_t)bytes_written != size) {
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t uart_receive(uart_config_t *config, uint8_t *buffer, size_t buffer_size, size_t *received) {
    if (!config || !buffer || buffer_size == 0 || !received || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ssize_t bytes_read = read(config->fd, buffer, buffer_size);
    if (bytes_read < 0) {
        *received = 0;
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    *received = bytes_read;
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t uart_close(uart_config_t *config) {
    if (!config || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Restore original terminal settings */
    tcsetattr(config->fd, TCSANOW, &config->old_termios);
    
    close(config->fd);
    config->fd = -1;
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * SPI Implementation
 */
iotstrike_error_t spi_init(spi_config_t *config, const char *device_path) {
    if (!config || !device_path) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(spi_config_t));
    strncpy(config->device_path, device_path, sizeof(config->device_path) - 1);
    
    config->fd = open(device_path, O_RDWR);
    if (config->fd < 0) {
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    /* Set default configuration */
    config->speed = DEFAULT_SPI_SPEED;
    config->mode = SPI_MODE_0;
    config->bits_per_word = 8;
    config->delay = 0;
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t spi_configure(spi_config_t *config, uint32_t speed, spi_mode_t mode, uint8_t bits_per_word) {
#ifdef __linux__
    if (!config || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Set SPI mode */
    if (ioctl(config->fd, SPI_IOC_WR_MODE, &mode) < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    /* Set bits per word */
    if (ioctl(config->fd, SPI_IOC_WR_BITS_PER_WORD, &bits_per_word) < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    /* Set speed */
    if (ioctl(config->fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    config->speed = speed;
    config->mode = mode;
    config->bits_per_word = bits_per_word;
    
    return IOTSTRIKE_SUCCESS;
#else
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

iotstrike_error_t spi_transfer(spi_config_t *config, const uint8_t *tx_data, uint8_t *rx_data, size_t size) {
#ifdef __linux__
    if (!config || !tx_data || !rx_data || size == 0 || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    struct spi_ioc_transfer transfer = {
        .tx_buf = (unsigned long)tx_data,
        .rx_buf = (unsigned long)rx_data,
        .len = size,
        .speed_hz = config->speed,
        .delay_usecs = config->delay,
        .bits_per_word = config->bits_per_word,
    };
    
    if (ioctl(config->fd, SPI_IOC_MESSAGE(1), &transfer) < 0) {
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    return IOTSTRIKE_SUCCESS;
#else
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

iotstrike_error_t spi_close(spi_config_t *config) {
    if (!config || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    close(config->fd);
    config->fd = -1;
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * I2C Implementation
 */
iotstrike_error_t i2c_init(i2c_config_t *config, const char *device_path, uint8_t slave_address) {
#ifdef __linux__
    if (!config || !device_path) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(i2c_config_t));
    strncpy(config->device_path, device_path, sizeof(config->device_path) - 1);
    config->slave_address = slave_address;
    
    config->fd = open(device_path, O_RDWR);
    if (config->fd < 0) {
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    /* Set slave address */
    if (ioctl(config->fd, I2C_SLAVE, slave_address) < 0) {
        close(config->fd);
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    config->speed = DEFAULT_I2C_SPEED;
    config->ten_bit_addressing = false;
    
    return IOTSTRIKE_SUCCESS;
#else
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

iotstrike_error_t i2c_scan(i2c_config_t *config, uint8_t *addresses, size_t *count) {
#ifdef __linux__
    if (!config || !addresses || !count || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    *count = 0;
    
    for (uint8_t addr = 0x03; addr < 0x78; addr++) {
        if (ioctl(config->fd, I2C_SLAVE, addr) >= 0) {
            /* Try to read one byte */
            uint8_t dummy;
            if (read(config->fd, &dummy, 1) >= 0) {
                addresses[*count] = addr;
                (*count)++;
            }
        }
    }
    
    /* Restore original slave address */
    ioctl(config->fd, I2C_SLAVE, config->slave_address);
    
    return IOTSTRIKE_SUCCESS;
#else
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

iotstrike_error_t i2c_write(i2c_config_t *config, const uint8_t *data, size_t size) {
    if (!config || !data || size == 0 || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ssize_t bytes_written = write(config->fd, data, size);
    if (bytes_written < 0 || (size_t)bytes_written != size) {
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t i2c_read(i2c_config_t *config, uint8_t *buffer, size_t size) {
    if (!config || !buffer || size == 0 || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ssize_t bytes_read = read(config->fd, buffer, size);
    if (bytes_read < 0 || (size_t)bytes_read != size) {
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t i2c_close(i2c_config_t *config) {
    if (!config || config->fd < 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    close(config->fd);
    config->fd = -1;
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * GPIO Implementation (Linux sysfs)
 */
iotstrike_error_t gpio_init(gpio_config_t *config, uint8_t pin, gpio_mode_t mode) {
    if (!config) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(gpio_config_t));
    config->pin = pin;
    config->mode = mode;
    config->state = GPIO_STATE_UNKNOWN;
    
    char path[256];
    
    /* Export GPIO pin */
    int fd = open("/sys/class/gpio/export", O_WRONLY);
    if (fd < 0) {
        return IOTSTRIKE_ERROR_PERMISSION;
    }
    
    char pin_str[8];
    snprintf(pin_str, sizeof(pin_str), "%d", pin);
    write(fd, pin_str, strlen(pin_str));
    close(fd);
    
    /* Set direction */
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", pin);
    fd = open(path, O_WRONLY);
    if (fd < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    const char *direction = (mode == GPIO_MODE_OUTPUT) ? "out" : "in";
    write(fd, direction, strlen(direction));
    close(fd);
    
    config->exported = true;
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t gpio_set_state(gpio_config_t *config, gpio_state_t state) {
    if (!config || !config->exported || config->mode != GPIO_MODE_OUTPUT) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", config->pin);
    
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    const char *value = (state == GPIO_STATE_HIGH) ? "1" : "0";
    write(fd, value, 1);
    close(fd);
    
    config->state = state;
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t gpio_get_state(gpio_config_t *config, gpio_state_t *state) {
    if (!config || !state || !config->exported) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", config->pin);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    char value;
    if (read(fd, &value, 1) != 1) {
        close(fd);
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    close(fd);
    
    *state = (value == '1') ? GPIO_STATE_HIGH : GPIO_STATE_LOW;
    config->state = *state;
    
    return IOTSTRIKE_SUCCESS;
}

iotstrike_error_t gpio_cleanup(gpio_config_t *config) {
    if (!config || !config->exported) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Unexport GPIO pin */
    int fd = open("/sys/class/gpio/unexport", O_WRONLY);
    if (fd >= 0) {
        char pin_str[8];
        snprintf(pin_str, sizeof(pin_str), "%d", config->pin);
        write(fd, pin_str, strlen(pin_str));
        close(fd);
    }
    
    config->exported = false;
    return IOTSTRIKE_SUCCESS;
}

/**
 * USB Implementation
 */
iotstrike_error_t usb_init(usb_config_t *config) {
    if (!config) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(config, 0, sizeof(usb_config_t));
    
#ifdef HAVE_LIBUSB
    int result = libusb_init(&config->context);
    if (result < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    return IOTSTRIKE_SUCCESS;
#else
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

iotstrike_error_t usb_scan_devices(usb_config_t *configs, size_t *count) {
    if (!configs || !count) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
#ifdef HAVE_LIBUSB
    libusb_device **devices;
    libusb_context *ctx = NULL;
    
    ssize_t device_count = libusb_get_device_list(ctx, &devices);
    if (device_count < 0) {
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    *count = 0;
    
    for (ssize_t i = 0; i < device_count && *count < MAX_USB_DEVICES; i++) {
        struct libusb_device_descriptor desc;
        int result = libusb_get_device_descriptor(devices[i], &desc);
        
        if (result == 0) {
            usb_config_t *config = &configs[*count];
            config->vendor_id = desc.idVendor;
            config->product_id = desc.idProduct;
            config->device_class = desc.bDeviceClass;
            (*count)++;
        }
    }
    
    libusb_free_device_list(devices, 1);
    return IOTSTRIKE_SUCCESS;
#else
    *count = 0;
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

iotstrike_error_t usb_cleanup(usb_config_t *config) {
    if (!config) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
#ifdef HAVE_LIBUSB
    if (config->handle) {
        libusb_close(config->handle);
        config->handle = NULL;
    }
    
    if (config->context) {
        libusb_exit(config->context);
        config->context = NULL;
    }
#endif
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Utility functions
 */
const char* hardware_protocol_to_string(hardware_protocol_t protocol) {
    switch (protocol) {
        case PROTOCOL_UART: return "UART";
        case PROTOCOL_SPI: return "SPI";
        case PROTOCOL_I2C: return "I2C";
        case PROTOCOL_JTAG: return "JTAG";
        case PROTOCOL_SWD: return "SWD";
        case PROTOCOL_USB: return "USB";
        case PROTOCOL_GPIO: return "GPIO";
        case PROTOCOL_RF: return "RF";
        case PROTOCOL_CAN: return "CAN";
        case PROTOCOL_LIN: return "LIN";
        default: return "Unknown";
    }
}

const char* gpio_mode_to_string(gpio_mode_t mode) {
    switch (mode) {
        case GPIO_MODE_INPUT: return "Input";
        case GPIO_MODE_OUTPUT: return "Output";
        case GPIO_MODE_PWM: return "PWM";
        case GPIO_MODE_ANALOG: return "Analog";
        case GPIO_MODE_INTERRUPT: return "Interrupt";
        default: return "Unknown";
    }
}

const char* gpio_state_to_string(gpio_state_t state) {
    switch (state) {
        case GPIO_STATE_LOW: return "Low";
        case GPIO_STATE_HIGH: return "High";
        case GPIO_STATE_UNKNOWN: return "Unknown";
        default: return "Invalid";
    }
}

/**
 * Scan for available hardware devices
 */
iotstrike_error_t hardware_scan_devices(hardware_context_t *ctx) {
    if (!ctx) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->initialized) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    // Initialize device count
    ctx->device_count = 0;
    
#ifdef HAVE_LIBUSB
    // Scan for USB devices
    libusb_device **devices;
    ssize_t device_count = libusb_get_device_list(NULL, &devices);
    
    if (device_count >= 0) {
        for (ssize_t i = 0; i < device_count && ctx->device_count < MAX_HARDWARE_DEVICES; i++) {
            struct libusb_device_descriptor desc;
            if (libusb_get_device_descriptor(devices[i], &desc) == 0) {
                // Add device to context (simplified implementation)
                ctx->device_count++;
            }
        }
        libusb_free_device_list(devices, 1);
    }
#endif
    
    // Scan for other hardware interfaces (GPIO, SPI, I2C, etc.)
    // This is a simplified implementation - in practice, you would
    // scan specific device paths and interfaces
    
#ifdef __linux__
    // Check for common hardware interfaces on Linux
    // GPIO
    if (access("/sys/class/gpio", F_OK) == 0) {
        ctx->device_count++;
    }
    
    // SPI
    if (access("/dev/spidev0.0", F_OK) == 0) {
        ctx->device_count++;
    }
    
    // I2C
    if (access("/dev/i2c-1", F_OK) == 0) {
        ctx->device_count++;
    }
#endif
    
    return IOTSTRIKE_SUCCESS;
}