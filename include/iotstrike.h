/**
 * IoTStrike Hardware Security Framework
 * Main header file containing core definitions and interfaces
 * 
 * @file iotstrike.h
 * @author ibrahimsql
 * @brief IoTStrike Hardware Security Framework
 * @version 1.0.0
 * @date 2024
 */

#ifndef IOTSTRIKE_H
#define IOTSTRIKE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version Information */
#define IOTSTRIKE_VERSION_MAJOR 1
#define IOTSTRIKE_VERSION_MINOR 0
#define IOTSTRIKE_VERSION_PATCH 0
#define IOTSTRIKE_VERSION_STRING "1.0.0"

/* Platform Detection */
#ifdef TARGET_ARM
    #define PLATFORM_ARM 1
    #define ARCH_BITS 32
#elif defined(TARGET_MIPS)
    #define PLATFORM_MIPS 1
    #define ARCH_BITS 32
#elif defined(__x86_64__)
    #define PLATFORM_X86_64 1
    #define ARCH_BITS 64
#else
    #define PLATFORM_X86 1
    #define ARCH_BITS 32
#endif

#ifdef EMBEDDED_BUILD
    #define MEMORY_CONSTRAINED 1
    #define MAX_BUFFER_SIZE 1024
#else
    #define MAX_BUFFER_SIZE 8192
#endif

/* Common Constants */
#define MAX_PATH_LENGTH 4096
#define MAX_DEVICE_NAME 256
#define MAX_PROTOCOL_NAME 64
#define MAX_ERROR_MESSAGE 512
#define DEFAULT_TIMEOUT 5000  // milliseconds

/* Error Codes */
typedef enum {
    IOTSTRIKE_SUCCESS = 0,
    IOTSTRIKE_ERROR_INVALID_PARAM = -1,
    IOTSTRIKE_ERROR_MEMORY = -2,
    IOTSTRIKE_ERROR_FILE_NOT_FOUND = -3,
    IOTSTRIKE_ERROR_PERMISSION = -4,
    IOTSTRIKE_ERROR_DEVICE_NOT_FOUND = -5,
    IOTSTRIKE_ERROR_COMMUNICATION = -6,
    IOTSTRIKE_ERROR_TIMEOUT = -7,
    IOTSTRIKE_ERROR_PROTOCOL = -8,
    IOTSTRIKE_ERROR_CRYPTO = -9,
    IOTSTRIKE_ERROR_HARDWARE = -10,
    IOTSTRIKE_ERROR_NOT_IMPLEMENTED = -11,
    IOTSTRIKE_ERROR_UNKNOWN = -99
} iotstrike_error_t;

/* Architecture Types */
typedef enum {
    ARCH_UNKNOWN = 0,
    ARCH_ARM,
    ARCH_ARM64,
    ARCH_MIPS,
    ARCH_MIPS64,
    ARCH_X86,
    ARCH_X86_64,
    ARCH_RISCV,
    ARCH_AVR,
    ARCH_PIC
} architecture_t;

/* Architecture type alias for compatibility */
typedef architecture_t iotstrike_arch_t;

/* Endianness */
typedef enum {
    ENDIAN_UNKNOWN = 0,
    ENDIAN_LITTLE,
    ENDIAN_BIG
} endianness_t;

/* Log Levels */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_CRITICAL
} log_level_t;

/* Security Levels */
typedef enum {
    IOTSTRIKE_SECURITY_LOW = 0,
    IOTSTRIKE_SECURITY_MEDIUM,
    IOTSTRIKE_SECURITY_HIGH,
    IOTSTRIKE_SECURITY_CRITICAL
} iotstrike_security_level_t;

/* Platform Types */
typedef enum {
    IOTSTRIKE_PLATFORM_UNKNOWN = 0,
    IOTSTRIKE_PLATFORM_LINUX,
    IOTSTRIKE_PLATFORM_EMBEDDED,
    IOTSTRIKE_PLATFORM_RTOS,
    IOTSTRIKE_PLATFORM_BAREMETAL
} iotstrike_platform_t;

/* Log Level Alias */
typedef log_level_t iotstrike_log_level_t;

/* Forward declarations for callback types */
typedef void (*iotstrike_log_callback_t)(iotstrike_log_level_t level, const char *module, const char *message);
typedef void (*iotstrike_error_callback_t)(iotstrike_error_t error, const char *message);
typedef void (*iotstrike_progress_callback_t)(const char *operation, uint32_t progress_percent);

/* Core Framework Structure */
typedef struct {
    char name[MAX_DEVICE_NAME];
    uint32_t version;
    bool initialized;
    bool running;
    log_level_t log_level;
    char error_message[MAX_ERROR_MESSAGE];
    pthread_mutex_t mutex;
    iotstrike_log_callback_t log_callback;
    iotstrike_error_callback_t error_callback;
    iotstrike_progress_callback_t progress_callback;
} iotstrike_context_t;

/* Buffer Structure */
typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
    bool allocated;
} iotstrike_buffer_t;

/* Device Information */
typedef struct {
    char name[MAX_DEVICE_NAME];
    char path[MAX_PATH_LENGTH];
    uint32_t vendor_id;
    uint32_t product_id;
    architecture_t arch;
    endianness_t endian;
    bool connected;
    void *private_data;
} device_info_t;

/* Protocol Information */
typedef struct {
    char name[MAX_PROTOCOL_NAME];
    uint16_t port;
    uint32_t baudrate;
    uint8_t data_bits;
    uint8_t stop_bits;
    char parity;
    uint32_t timeout;
} protocol_config_t;

/* Framework Configuration */
typedef struct {
    iotstrike_security_level_t security_level;
    iotstrike_platform_t platform;
    log_level_t log_level;
    bool memory_protection;
    bool privilege_dropping;
    uint32_t default_timeout;
    char log_file[MAX_PATH_LENGTH];
} iotstrike_config_t;

/* Framework Statistics */
typedef struct {
    uint64_t operations_count;
    uint64_t errors_count;
    uint64_t bytes_processed;
    uint32_t uptime_seconds;
    uint32_t active_connections;
    double cpu_usage;
    size_t memory_usage;
} iotstrike_stats_t;

/* Function Prototypes - Core */
// Hardware validation functions
iotstrike_error_t run_hardware_validation(void);
const char* get_platform_string(void);
iotstrike_error_t iotstrike_check_privileges(void);

// Framework management functions
iotstrike_error_t iotstrike_init(iotstrike_context_t *ctx, const iotstrike_config_t *config);
iotstrike_error_t iotstrike_start(iotstrike_context_t *ctx);
iotstrike_error_t iotstrike_stop(iotstrike_context_t *ctx);
iotstrike_error_t iotstrike_cleanup(iotstrike_context_t *ctx);
iotstrike_error_t iotstrike_get_statistics(iotstrike_context_t *ctx, iotstrike_stats_t *stats);

// Callback functions

void iotstrike_set_log_callback(iotstrike_context_t *ctx, iotstrike_log_callback_t callback);
void iotstrike_set_error_callback(iotstrike_context_t *ctx, iotstrike_error_callback_t callback);
void iotstrike_set_progress_callback(iotstrike_context_t *ctx, iotstrike_progress_callback_t callback);

// Utility functions
const char* iotstrike_error_to_string(iotstrike_error_t error);
const char* iotstrike_platform_to_string(iotstrike_platform_t platform);
const char* iotstrike_security_level_to_string(iotstrike_security_level_t level);
const char* iotstrike_get_version(void);
const char* iotstrike_error_string(iotstrike_error_t error);
void iotstrike_set_log_level(iotstrike_context_t *ctx, log_level_t level);
void iotstrike_log(iotstrike_context_t *ctx, log_level_t level, const char *format, ...);

/* Function Prototypes - Buffer Management */
iotstrike_error_t iotstrike_buffer_init(iotstrike_buffer_t *buffer, size_t capacity);
iotstrike_error_t iotstrike_buffer_append(iotstrike_buffer_t *buffer, const uint8_t *data, size_t size);
iotstrike_error_t iotstrike_buffer_clear(iotstrike_buffer_t *buffer);
void iotstrike_buffer_free(iotstrike_buffer_t *buffer);

/* Function Prototypes - Utility */
uint32_t iotstrike_crc32(const uint8_t *data, size_t length);
void iotstrike_hexdump(const uint8_t *data, size_t length);
architecture_t iotstrike_detect_architecture(const uint8_t *binary, size_t size);
endianness_t iotstrike_detect_endianness(const uint8_t *binary, size_t size);

/* Module Interfaces */
#include "firmware.h"
#include "hardware.h"
#include "wireless.h"
#include "realtime.h"
#include "sidechannel.h"

/* Macros */
#define IOTSTRIKE_UNUSED(x) ((void)(x))
#define IOTSTRIKE_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define IOTSTRIKE_MIN(a, b) ((a) < (b) ? (a) : (b))
#define IOTSTRIKE_MAX(a, b) ((a) > (b) ? (a) : (b))

/* Memory Management Macros */
#define IOTSTRIKE_MALLOC(size) malloc(size)
#define IOTSTRIKE_CALLOC(count, size) calloc(count, size)
#define IOTSTRIKE_REALLOC(ptr, size) realloc(ptr, size)
#define IOTSTRIKE_FREE(ptr) do { if (ptr) { free(ptr); ptr = NULL; } } while(0)

/* Secure Memory Operations */
void iotstrike_secure_zero(void *ptr, size_t size);
void* iotstrike_secure_malloc(size_t size);
void iotstrike_secure_free(void *ptr, size_t size);

/* Thread Safety */
#define IOTSTRIKE_LOCK(ctx) pthread_mutex_lock(&(ctx)->mutex)
#define IOTSTRIKE_UNLOCK(ctx) pthread_mutex_unlock(&(ctx)->mutex)

/* Compiler Attributes */
#ifdef __GNUC__
    #define IOTSTRIKE_PACKED __attribute__((packed))
    #define IOTSTRIKE_ALIGNED(n) __attribute__((aligned(n)))
    #define IOTSTRIKE_UNUSED_FUNC __attribute__((unused))
    #define IOTSTRIKE_DEPRECATED __attribute__((deprecated))
#else
    #define IOTSTRIKE_PACKED
    #define IOTSTRIKE_ALIGNED(n)
    #define IOTSTRIKE_UNUSED_FUNC
    #define IOTSTRIKE_DEPRECATED
#endif

#ifdef __cplusplus
}
#endif

#endif /* IOTSTRIKE_H */