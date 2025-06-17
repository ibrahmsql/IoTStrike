/**
 * IoTStrike Hardware Security Framework
 * Hardware Communication Interface Header
 * 
 * @file hardware.h
 * @author ibrahimsql
 * @brief IoTStrike Hardware Security Framework
 * @version 1.0.0
 */

#ifndef HARDWARE_H
#define HARDWARE_H

#include "iotstrike.h"
// Optional libusb dependency - disable if not available
#ifdef HAVE_LIBUSB
#include <libusb-1.0/libusb.h>
#else
// Minimal libusb definitions for compilation
typedef struct libusb_context libusb_context;
typedef struct libusb_device libusb_device;
typedef struct libusb_device_handle libusb_device_handle;
typedef struct libusb_device_descriptor {
    uint16_t idVendor;
    uint16_t idProduct;
} libusb_device_descriptor;
#define LIBUSB_SUCCESS 0
#define LIBUSB_ERROR_NO_DEVICE -4
#endif
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hardware Interface Constants */
#define MAX_DEVICES 32
#define MAX_GPIO_PINS 64
#define MAX_SPI_DEVICES 8
#define MAX_I2C_DEVICES 128
#define MAX_UART_DEVICES 16
#define MAX_USB_DEVICES 64
#define MAX_RF_CHANNELS 256

#define DEFAULT_UART_BAUDRATE 115200
#define DEFAULT_SPI_SPEED 1000000
#define DEFAULT_I2C_SPEED 100000
#define DEFAULT_GPIO_TIMEOUT 1000

/* Communication Protocols */
typedef enum {
    PROTOCOL_UART = 0,
    PROTOCOL_SPI,
    PROTOCOL_I2C,
    PROTOCOL_JTAG,
    PROTOCOL_SWD,
    PROTOCOL_USB,
    PROTOCOL_GPIO,
    PROTOCOL_RF,
    PROTOCOL_CAN,
    PROTOCOL_LIN
} hardware_protocol_t;

/* GPIO Pin Modes */
typedef enum {
    GPIO_MODE_INPUT = 0,
    GPIO_MODE_OUTPUT,
    GPIO_MODE_PWM,
    GPIO_MODE_ANALOG,
    GPIO_MODE_INTERRUPT
} gpio_mode_t;

/* GPIO Pin States */
typedef enum {
    GPIO_STATE_LOW = 0,
    GPIO_STATE_HIGH = 1,
    GPIO_STATE_UNKNOWN = -1
} gpio_state_t;

/* SPI Modes */
typedef enum {
    SPI_MODE_0 = 0,  // CPOL=0, CPHA=0
    SPI_MODE_1 = 1,  // CPOL=0, CPHA=1
    SPI_MODE_2 = 2,  // CPOL=1, CPHA=0
    SPI_MODE_3 = 3   // CPOL=1, CPHA=1
} spi_mode_t;

/* UART Parity */
typedef enum {
    UART_PARITY_NONE = 0,
    UART_PARITY_EVEN,
    UART_PARITY_ODD,
    UART_PARITY_MARK,
    UART_PARITY_SPACE
} uart_parity_t;

/* UART Stop Bits */
typedef enum {
    UART_STOP_1 = 1,
    UART_STOP_2 = 2
} uart_stop_bits_t;

/* RF Modulation Types */
typedef enum {
    RF_MODULATION_ASK = 0,
    RF_MODULATION_FSK,
    RF_MODULATION_PSK,
    RF_MODULATION_QAM,
    RF_MODULATION_OFDM
} rf_modulation_t;

/* USB Device Classes */
typedef enum {
    USB_CLASS_HID = 0x03,
    USB_CLASS_CDC = 0x02,
    USB_CLASS_MSC = 0x08,
    USB_CLASS_VENDOR = 0xFF
} usb_device_class_t;

/* JTAG States */
typedef enum {
    JTAG_STATE_RESET = 0,
    JTAG_STATE_IDLE,
    JTAG_STATE_SELECT_DR,
    JTAG_STATE_CAPTURE_DR,
    JTAG_STATE_SHIFT_DR,
    JTAG_STATE_EXIT1_DR,
    JTAG_STATE_PAUSE_DR,
    JTAG_STATE_EXIT2_DR,
    JTAG_STATE_UPDATE_DR,
    JTAG_STATE_SELECT_IR,
    JTAG_STATE_CAPTURE_IR,
    JTAG_STATE_SHIFT_IR,
    JTAG_STATE_EXIT1_IR,
    JTAG_STATE_PAUSE_IR,
    JTAG_STATE_EXIT2_IR,
    JTAG_STATE_UPDATE_IR
} jtag_state_t;

/* Hardware Device Structure */
typedef struct {
    char name[MAX_DEVICE_NAME];
    char path[MAX_PATH_LENGTH];
    hardware_protocol_t protocol;
    uint32_t vendor_id;
    uint32_t product_id;
    bool connected;
    bool initialized;
    void *handle;
    pthread_mutex_t mutex;
} hardware_device_t;

/* UART Configuration */
typedef struct {
    char device_path[MAX_PATH_LENGTH];
    uint32_t baudrate;
    uint8_t data_bits;
    uart_stop_bits_t stop_bits;
    uart_parity_t parity;
    bool flow_control;
    uint32_t timeout;
    int fd;
    struct termios old_termios;
} uart_config_t;

/* SPI Configuration */
typedef struct {
    char device_path[MAX_PATH_LENGTH];
    uint32_t speed;
    spi_mode_t mode;
    uint8_t bits_per_word;
    uint16_t delay;
    int fd;
} spi_config_t;

/* I2C Configuration */
typedef struct {
    char device_path[MAX_PATH_LENGTH];
    uint8_t slave_address;
    uint32_t speed;
    bool ten_bit_addressing;
    int fd;
} i2c_config_t;

/* GPIO Configuration */
typedef struct {
    uint8_t pin;
    gpio_mode_t mode;
    gpio_state_t state;
    uint32_t frequency;  // For PWM
    uint8_t duty_cycle;  // For PWM (0-100%)
    bool exported;
} gpio_config_t;

/* USB Configuration */
typedef struct {
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t interface;
    uint8_t endpoint_in;
    uint8_t endpoint_out;
    usb_device_class_t device_class;
    libusb_context *context;
    libusb_device_handle *handle;
} usb_config_t;

/* RF Configuration */
typedef struct {
    uint32_t frequency;
    rf_modulation_t modulation;
    uint8_t power;
    uint32_t bandwidth;
    uint32_t datarate;
    bool continuous;
    char device_path[MAX_PATH_LENGTH];
} rf_config_t;

/* JTAG Configuration */
typedef struct {
    char device_path[MAX_PATH_LENGTH];
    uint32_t frequency;
    jtag_state_t current_state;
    uint8_t ir_length;
    bool initialized;
} jtag_config_t;

/* Hardware Context */
typedef struct {
    hardware_device_t devices[MAX_DEVICES];
    size_t device_count;
    
    uart_config_t uart_configs[MAX_UART_DEVICES];
    size_t uart_count;
    
    spi_config_t spi_configs[MAX_SPI_DEVICES];
    size_t spi_count;
    
    i2c_config_t i2c_configs[MAX_I2C_DEVICES];
    size_t i2c_count;
    
    gpio_config_t gpio_configs[MAX_GPIO_PINS];
    size_t gpio_count;
    
    usb_config_t usb_configs[MAX_USB_DEVICES];
    size_t usb_count;
    
    rf_config_t rf_configs[MAX_RF_CHANNELS];
    size_t rf_count;
    
    jtag_config_t jtag_config;
    
    bool initialized;
} hardware_context_t;

/* Function Prototypes - Core */
iotstrike_error_t hardware_init(hardware_context_t *ctx);
iotstrike_error_t hardware_cleanup(hardware_context_t *ctx);
iotstrike_error_t hardware_scan_devices(hardware_context_t *ctx);
iotstrike_error_t hardware_connect_device(hardware_context_t *ctx, const char *device_name);
iotstrike_error_t hardware_disconnect_device(hardware_context_t *ctx, const char *device_name);

/* Function Prototypes - UART */
iotstrike_error_t uart_init(uart_config_t *config, const char *device_path);
iotstrike_error_t uart_configure(uart_config_t *config, uint32_t baudrate, uint8_t data_bits, 
                                uart_stop_bits_t stop_bits, uart_parity_t parity);
iotstrike_error_t uart_send(uart_config_t *config, const uint8_t *data, size_t size);
iotstrike_error_t uart_receive(uart_config_t *config, uint8_t *buffer, size_t buffer_size, size_t *received);
iotstrike_error_t uart_flush(uart_config_t *config);
iotstrike_error_t uart_close(uart_config_t *config);

/* Function Prototypes - SPI */
iotstrike_error_t spi_init(spi_config_t *config, const char *device_path);
iotstrike_error_t spi_configure(spi_config_t *config, uint32_t speed, spi_mode_t mode, uint8_t bits_per_word);
iotstrike_error_t spi_transfer(spi_config_t *config, const uint8_t *tx_data, uint8_t *rx_data, size_t size);
iotstrike_error_t spi_write(spi_config_t *config, const uint8_t *data, size_t size);
iotstrike_error_t spi_read(spi_config_t *config, uint8_t *buffer, size_t size);
iotstrike_error_t spi_close(spi_config_t *config);

/* Function Prototypes - I2C */
iotstrike_error_t i2c_init(i2c_config_t *config, const char *device_path, uint8_t slave_address);
iotstrike_error_t i2c_scan(i2c_config_t *config, uint8_t *addresses, size_t *count);
iotstrike_error_t i2c_write(i2c_config_t *config, const uint8_t *data, size_t size);
iotstrike_error_t i2c_read(i2c_config_t *config, uint8_t *buffer, size_t size);
iotstrike_error_t i2c_write_register(i2c_config_t *config, uint8_t reg, uint8_t value);
iotstrike_error_t i2c_read_register(i2c_config_t *config, uint8_t reg, uint8_t *value);
iotstrike_error_t i2c_close(i2c_config_t *config);

/* Function Prototypes - GPIO */
iotstrike_error_t gpio_init(gpio_config_t *config, uint8_t pin, gpio_mode_t mode);
iotstrike_error_t gpio_set_state(gpio_config_t *config, gpio_state_t state);
iotstrike_error_t gpio_get_state(gpio_config_t *config, gpio_state_t *state);
iotstrike_error_t gpio_set_pwm(gpio_config_t *config, uint32_t frequency, uint8_t duty_cycle);
iotstrike_error_t gpio_setup_interrupt(gpio_config_t *config, void (*callback)(uint8_t pin));
iotstrike_error_t gpio_cleanup(gpio_config_t *config);

/* Function Prototypes - USB */
iotstrike_error_t usb_init(usb_config_t *config);
iotstrike_error_t usb_scan_devices(usb_config_t *configs, size_t *count);
iotstrike_error_t usb_connect(usb_config_t *config, uint16_t vendor_id, uint16_t product_id);
iotstrike_error_t usb_send(usb_config_t *config, const uint8_t *data, size_t size);
iotstrike_error_t usb_receive(usb_config_t *config, uint8_t *buffer, size_t buffer_size, size_t *received);
iotstrike_error_t usb_control_transfer(usb_config_t *config, uint8_t request_type, uint8_t request, 
                                      uint16_t value, uint16_t index, uint8_t *data, uint16_t length);
iotstrike_error_t usb_disconnect(usb_config_t *config);
iotstrike_error_t usb_cleanup(usb_config_t *config);

/* Function Prototypes - RF */
iotstrike_error_t rf_init(rf_config_t *config, const char *device_path);
iotstrike_error_t rf_configure(rf_config_t *config, uint32_t frequency, rf_modulation_t modulation, uint8_t power);
iotstrike_error_t rf_transmit(rf_config_t *config, const uint8_t *data, size_t size);
iotstrike_error_t rf_receive(rf_config_t *config, uint8_t *buffer, size_t buffer_size, size_t *received);
iotstrike_error_t rf_scan_frequencies(rf_config_t *config, uint32_t start_freq, uint32_t end_freq, uint32_t step);
iotstrike_error_t rf_jam_frequency(rf_config_t *config, uint32_t frequency, uint32_t duration);
iotstrike_error_t rf_close(rf_config_t *config);

/* Function Prototypes - JTAG/SWD */
iotstrike_error_t jtag_init(jtag_config_t *config, const char *device_path);
iotstrike_error_t jtag_reset(jtag_config_t *config);
iotstrike_error_t jtag_state_transition(jtag_config_t *config, jtag_state_t target_state);
iotstrike_error_t jtag_shift_ir(jtag_config_t *config, const uint8_t *data, uint8_t *result, size_t bits);
iotstrike_error_t jtag_shift_dr(jtag_config_t *config, const uint8_t *data, uint8_t *result, size_t bits);
iotstrike_error_t jtag_scan_chain(jtag_config_t *config);
iotstrike_error_t jtag_read_memory(jtag_config_t *config, uint32_t address, uint8_t *buffer, size_t size);
iotstrike_error_t jtag_write_memory(jtag_config_t *config, uint32_t address, const uint8_t *data, size_t size);
iotstrike_error_t jtag_close(jtag_config_t *config);

/* Function Prototypes - Protocol Analysis */
iotstrike_error_t hardware_capture_traffic(hardware_context_t *ctx, hardware_protocol_t protocol, 
                                          const char *output_file, uint32_t duration);
iotstrike_error_t hardware_analyze_protocol(hardware_context_t *ctx, const char *capture_file);
iotstrike_error_t hardware_fuzz_protocol(hardware_context_t *ctx, hardware_protocol_t protocol, 
                                        const uint8_t *seed_data, size_t seed_size);

/* Function Prototypes - Utility */
const char* hardware_protocol_to_string(hardware_protocol_t protocol);
const char* gpio_mode_to_string(gpio_mode_t mode);
const char* gpio_state_to_string(gpio_state_t state);
const char* spi_mode_to_string(spi_mode_t mode);
const char* uart_parity_to_string(uart_parity_t parity);
const char* rf_modulation_to_string(rf_modulation_t modulation);
const char* jtag_state_to_string(jtag_state_t state);

/* Hardware Abstraction Layer */
#ifdef PLATFORM_ARM
    #include "hal_arm.h"
#elif defined(PLATFORM_MIPS)
    #include "hal_mips.h"
#elif defined(PLATFORM_X86_64)
    #include "hal_x86_64.h"
#else
    #include "hal_generic.h"
#endif

#ifdef __cplusplus
}
#endif

#endif /* HARDWARE_H */