/**
 * @file hal_generic.h
 * @brief Generic Hardware Abstraction Layer for IoTStrike Framework
 * @author ibrahimsql
 * @version 1.0.0
 * @date 2024
 * 
 * This file provides generic hardware abstraction layer definitions
 * for platforms that don't have specific HAL implementations.
 */

#ifndef HAL_GENERIC_H
#define HAL_GENERIC_H

#include "iotstrike.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generic Platform Constants */
#define HAL_GENERIC_MAX_GPIO_PINS 64
#define HAL_GENERIC_MAX_SPI_DEVICES 4
#define HAL_GENERIC_MAX_I2C_BUSES 4
#define HAL_GENERIC_MAX_UART_PORTS 8

/* Generic GPIO Definitions */
#define HAL_GPIO_MODE_INPUT 0
#define HAL_GPIO_MODE_OUTPUT 1
#define HAL_GPIO_MODE_ALT_FUNCTION 2

#define HAL_GPIO_PULL_NONE 0
#define HAL_GPIO_PULL_UP 1
#define HAL_GPIO_PULL_DOWN 2

#define HAL_GPIO_SPEED_LOW 0
#define HAL_GPIO_SPEED_MEDIUM 1
#define HAL_GPIO_SPEED_HIGH 2
#define HAL_GPIO_SPEED_VERY_HIGH 3

/* Generic SPI Definitions */
#define HAL_SPI_MODE_0 0  // CPOL=0, CPHA=0
#define HAL_SPI_MODE_1 1  // CPOL=0, CPHA=1
#define HAL_SPI_MODE_2 2  // CPOL=1, CPHA=0
#define HAL_SPI_MODE_3 3  // CPOL=1, CPHA=1

#define HAL_SPI_FIRSTBIT_MSB 0
#define HAL_SPI_FIRSTBIT_LSB 1

/* Generic I2C Definitions */
#define HAL_I2C_SPEED_STANDARD 100000   // 100 kHz
#define HAL_I2C_SPEED_FAST 400000       // 400 kHz
#define HAL_I2C_SPEED_FAST_PLUS 1000000 // 1 MHz

/* Generic UART Definitions */
#define HAL_UART_WORDLENGTH_8B 0
#define HAL_UART_WORDLENGTH_9B 1

#define HAL_UART_STOPBITS_1 0
#define HAL_UART_STOPBITS_2 1

#define HAL_UART_PARITY_NONE 0
#define HAL_UART_PARITY_EVEN 1
#define HAL_UART_PARITY_ODD 2

#define HAL_UART_HWCONTROL_NONE 0
#define HAL_UART_HWCONTROL_RTS 1
#define HAL_UART_HWCONTROL_CTS 2
#define HAL_UART_HWCONTROL_RTS_CTS 3

/* Generic Timer Definitions */
#define HAL_TIMER_PRESCALER_1 0
#define HAL_TIMER_PRESCALER_8 1
#define HAL_TIMER_PRESCALER_64 2
#define HAL_TIMER_PRESCALER_256 3
#define HAL_TIMER_PRESCALER_1024 4

/* Generic ADC Definitions */
#define HAL_ADC_RESOLUTION_8BIT 0
#define HAL_ADC_RESOLUTION_10BIT 1
#define HAL_ADC_RESOLUTION_12BIT 2
#define HAL_ADC_RESOLUTION_16BIT 3

/* Generic PWM Definitions */
#define HAL_PWM_POLARITY_HIGH 0
#define HAL_PWM_POLARITY_LOW 1

/* Generic Interrupt Definitions */
#define HAL_IRQ_TRIGGER_RISING 0
#define HAL_IRQ_TRIGGER_FALLING 1
#define HAL_IRQ_TRIGGER_BOTH 2
#define HAL_IRQ_TRIGGER_LOW 3
#define HAL_IRQ_TRIGGER_HIGH 4

/* Generic Clock Definitions */
#define HAL_CLOCK_SOURCE_INTERNAL 0
#define HAL_CLOCK_SOURCE_EXTERNAL 1
#define HAL_CLOCK_SOURCE_PLL 2

/* Generic Power Management */
#define HAL_POWER_MODE_RUN 0
#define HAL_POWER_MODE_SLEEP 1
#define HAL_POWER_MODE_STOP 2
#define HAL_POWER_MODE_STANDBY 3

/* Generic Memory Definitions */
#define HAL_MEMORY_TYPE_FLASH 0
#define HAL_MEMORY_TYPE_SRAM 1
#define HAL_MEMORY_TYPE_EEPROM 2
#define HAL_MEMORY_TYPE_EXTERNAL 3

/* Generic Status Codes */
#define HAL_OK 0
#define HAL_ERROR -1
#define HAL_BUSY -2
#define HAL_TIMEOUT -3
#define HAL_INVALID_PARAM -4
#define HAL_NOT_SUPPORTED -5

/* Generic Structure Definitions */
typedef struct {
    uint32_t pin;
    uint32_t mode;
    uint32_t pull;
    uint32_t speed;
    uint32_t alternate;
} hal_gpio_config_t;

typedef struct {
    uint32_t instance;
    uint32_t mode;
    uint32_t direction;
    uint32_t data_size;
    uint32_t clk_polarity;
    uint32_t clk_phase;
    uint32_t nss;
    uint32_t baudrate_prescaler;
    uint32_t first_bit;
    uint32_t ti_mode;
    uint32_t crc_calculation;
    uint32_t crc_polynomial;
} hal_spi_config_t;

typedef struct {
    uint32_t instance;
    uint32_t timing;
    uint32_t own_address1;
    uint32_t addressing_mode;
    uint32_t dual_address_mode;
    uint32_t own_address2;
    uint32_t own_address2_masks;
    uint32_t general_call_mode;
    uint32_t no_stretch_mode;
} hal_i2c_config_t;

typedef struct {
    uint32_t instance;
    uint32_t baudrate;
    uint32_t word_length;
    uint32_t stop_bits;
    uint32_t parity;
    uint32_t mode;
    uint32_t hw_flow_ctl;
    uint32_t over_sampling;
} hal_uart_config_t;

typedef struct {
    uint32_t instance;
    uint32_t prescaler;
    uint32_t counter_mode;
    uint32_t period;
    uint32_t clock_division;
    uint32_t repetition_counter;
    bool auto_reload_preload;
} hal_timer_config_t;

typedef struct {
    uint32_t instance;
    uint32_t clock_prescaler;
    uint32_t resolution;
    uint32_t data_align;
    uint32_t scan_conv_mode;
    uint32_t eoc_selection;
    bool continuous_conv_mode;
    bool discontinuous_conv_mode;
    uint32_t nb_discontinuous_conv;
    bool dma_continuous_requests;
} hal_adc_config_t;

typedef struct {
    uint32_t instance;
    uint32_t channel;
    uint32_t prescaler;
    uint32_t counter_mode;
    uint32_t period;
    uint32_t pulse;
    uint32_t polarity;
    uint32_t fast_mode;
} hal_pwm_config_t;

/* Generic Function Prototypes */

/* System Functions */
int hal_init(void);
int hal_deinit(void);
int hal_reset(void);
uint32_t hal_get_tick(void);
void hal_delay(uint32_t delay_ms);
void hal_delay_us(uint32_t delay_us);

/* GPIO Functions */
int hal_gpio_init(hal_gpio_config_t *config);
int hal_gpio_deinit(uint32_t pin);
int hal_gpio_write_pin(uint32_t pin, bool state);
bool hal_gpio_read_pin(uint32_t pin);
int hal_gpio_toggle_pin(uint32_t pin);
int hal_gpio_set_interrupt(uint32_t pin, uint32_t trigger, void (*callback)(void));
int hal_gpio_disable_interrupt(uint32_t pin);

/* SPI Functions */
int hal_spi_init(hal_spi_config_t *config);
int hal_spi_deinit(uint32_t instance);
int hal_spi_transmit(uint32_t instance, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_spi_receive(uint32_t instance, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_spi_transmit_receive(uint32_t instance, uint8_t *tx_data, uint8_t *rx_data, uint16_t size, uint32_t timeout);

/* I2C Functions */
int hal_i2c_init(hal_i2c_config_t *config);
int hal_i2c_deinit(uint32_t instance);
int hal_i2c_master_transmit(uint32_t instance, uint16_t dev_address, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_i2c_master_receive(uint32_t instance, uint16_t dev_address, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_i2c_mem_write(uint32_t instance, uint16_t dev_address, uint16_t mem_address, uint16_t mem_add_size, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_i2c_mem_read(uint32_t instance, uint16_t dev_address, uint16_t mem_address, uint16_t mem_add_size, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_i2c_is_device_ready(uint32_t instance, uint16_t dev_address, uint32_t trials, uint32_t timeout);

/* UART Functions */
int hal_uart_init(hal_uart_config_t *config);
int hal_uart_deinit(uint32_t instance);
int hal_uart_transmit(uint32_t instance, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_uart_receive(uint32_t instance, uint8_t *data, uint16_t size, uint32_t timeout);
int hal_uart_transmit_it(uint32_t instance, uint8_t *data, uint16_t size);
int hal_uart_receive_it(uint32_t instance, uint8_t *data, uint16_t size);

/* Timer Functions */
int hal_timer_init(hal_timer_config_t *config);
int hal_timer_deinit(uint32_t instance);
int hal_timer_start(uint32_t instance);
int hal_timer_stop(uint32_t instance);
int hal_timer_set_period(uint32_t instance, uint32_t period);
uint32_t hal_timer_get_counter(uint32_t instance);
int hal_timer_set_callback(uint32_t instance, void (*callback)(void));

/* ADC Functions */
int hal_adc_init(hal_adc_config_t *config);
int hal_adc_deinit(uint32_t instance);
int hal_adc_start(uint32_t instance);
int hal_adc_stop(uint32_t instance);
uint32_t hal_adc_get_value(uint32_t instance, uint32_t channel);
int hal_adc_start_dma(uint32_t instance, uint32_t *data, uint32_t length);
int hal_adc_stop_dma(uint32_t instance);

/* PWM Functions */
int hal_pwm_init(hal_pwm_config_t *config);
int hal_pwm_deinit(uint32_t instance, uint32_t channel);
int hal_pwm_start(uint32_t instance, uint32_t channel);
int hal_pwm_stop(uint32_t instance, uint32_t channel);
int hal_pwm_set_pulse(uint32_t instance, uint32_t channel, uint32_t pulse);
int hal_pwm_set_duty_cycle(uint32_t instance, uint32_t channel, float duty_cycle);

/* Clock Functions */
int hal_clock_config(uint32_t source, uint32_t frequency);
uint32_t hal_clock_get_frequency(uint32_t clock_source);
int hal_clock_enable(uint32_t peripheral);
int hal_clock_disable(uint32_t peripheral);

/* Power Management Functions */
int hal_power_set_mode(uint32_t mode);
uint32_t hal_power_get_mode(void);
int hal_power_enable_wakeup_source(uint32_t source);
int hal_power_disable_wakeup_source(uint32_t source);
void hal_power_enter_sleep_mode(void);
void hal_power_enter_stop_mode(void);
void hal_power_enter_standby_mode(void);

/* Memory Functions */
int hal_flash_unlock(void);
int hal_flash_lock(void);
int hal_flash_erase_page(uint32_t page_address);
int hal_flash_program_word(uint32_t address, uint32_t data);
int hal_flash_program_halfword(uint32_t address, uint16_t data);
int hal_flash_program_byte(uint32_t address, uint8_t data);
uint32_t hal_flash_read_word(uint32_t address);
uint16_t hal_flash_read_halfword(uint32_t address);
uint8_t hal_flash_read_byte(uint32_t address);

/* Interrupt Functions */
void hal_nvic_set_priority(uint32_t irq_number, uint32_t priority);
void hal_nvic_enable_irq(uint32_t irq_number);
void hal_nvic_disable_irq(uint32_t irq_number);
void hal_nvic_clear_pending_irq(uint32_t irq_number);
bool hal_nvic_get_pending_irq(uint32_t irq_number);

/* DMA Functions */
int hal_dma_init(uint32_t instance, uint32_t channel);
int hal_dma_deinit(uint32_t instance, uint32_t channel);
int hal_dma_start(uint32_t instance, uint32_t channel, uint32_t src_address, uint32_t dst_address, uint32_t data_length);
int hal_dma_stop(uint32_t instance, uint32_t channel);
bool hal_dma_is_transfer_complete(uint32_t instance, uint32_t channel);
int hal_dma_set_callback(uint32_t instance, uint32_t channel, void (*callback)(void));

/* Watchdog Functions */
int hal_watchdog_init(uint32_t timeout_ms);
int hal_watchdog_start(void);
int hal_watchdog_stop(void);
int hal_watchdog_refresh(void);

/* RTC Functions */
int hal_rtc_init(void);
int hal_rtc_deinit(void);
int hal_rtc_set_time(uint32_t hours, uint32_t minutes, uint32_t seconds);
int hal_rtc_get_time(uint32_t *hours, uint32_t *minutes, uint32_t *seconds);
int hal_rtc_set_date(uint32_t year, uint32_t month, uint32_t day);
int hal_rtc_get_date(uint32_t *year, uint32_t *month, uint32_t *day);
int hal_rtc_set_alarm(uint32_t hours, uint32_t minutes, uint32_t seconds, void (*callback)(void));
int hal_rtc_disable_alarm(void);

/* CRC Functions */
int hal_crc_init(void);
int hal_crc_deinit(void);
uint32_t hal_crc_calculate(uint32_t *data, uint32_t data_length);
uint32_t hal_crc_accumulate(uint32_t *data, uint32_t data_length);
void hal_crc_reset(void);

/* Random Number Generator Functions */
int hal_rng_init(void);
int hal_rng_deinit(void);
uint32_t hal_rng_get_random_number(void);
int hal_rng_get_random_bytes(uint8_t *buffer, uint32_t length);

/* Temperature Sensor Functions */
int hal_temp_sensor_init(void);
int hal_temp_sensor_deinit(void);
float hal_temp_sensor_get_temperature(void);

/* Voltage Reference Functions */
int hal_vref_init(void);
int hal_vref_deinit(void);
float hal_vref_get_voltage(void);

#ifdef __cplusplus
}
#endif

#endif // HAL_GENERIC_H