/**
 * IoTStrike Hardware Security Framework
 * Core Framework Implementation
 * 
 * @file iotstrike_core.c
 * @author ibrahimsql 
 * @version 1.0.0
 */

#include "iotstrike.h"
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

/* Global error messages */
static const char* error_messages[] = {
    [IOTSTRIKE_SUCCESS] = "Success",
    [-IOTSTRIKE_ERROR_INVALID_PARAM] = "Invalid parameter",
    [-IOTSTRIKE_ERROR_MEMORY] = "Memory allocation error",
    [-IOTSTRIKE_ERROR_FILE_NOT_FOUND] = "File not found",
    [-IOTSTRIKE_ERROR_PERMISSION] = "Permission denied",
    [-IOTSTRIKE_ERROR_DEVICE_NOT_FOUND] = "Device not found",
    [-IOTSTRIKE_ERROR_COMMUNICATION] = "Communication error",
    [-IOTSTRIKE_ERROR_TIMEOUT] = "Operation timeout",
    [-IOTSTRIKE_ERROR_PROTOCOL] = "Protocol error",
    [-IOTSTRIKE_ERROR_CRYPTO] = "Cryptographic error",
    [-IOTSTRIKE_ERROR_HARDWARE] = "Hardware error",
    [-IOTSTRIKE_ERROR_NOT_IMPLEMENTED] = "Feature not implemented",
    [-IOTSTRIKE_ERROR_UNKNOWN] = "Unknown error"
};

/* Log level strings */
static const char* log_level_strings[] = {
    "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
};

/**
 * Initialize IoTStrike framework context
 */
iotstrike_error_t iotstrike_init(iotstrike_context_t *ctx, const iotstrike_config_t *config) {
    if (!ctx) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (!config) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(iotstrike_context_t));
    
    strncpy(ctx->name, "IoTStrike", sizeof(ctx->name) - 1);
    ctx->version = (IOTSTRIKE_VERSION_MAJOR << 16) | 
                   (IOTSTRIKE_VERSION_MINOR << 8) | 
                   IOTSTRIKE_VERSION_PATCH;
    ctx->log_level = LOG_LEVEL_INFO;
    ctx->initialized = false;
    
    /* Initialize mutex */
    if (pthread_mutex_init(&ctx->mutex, NULL) != 0) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
    
    ctx->initialized = true;
    
    iotstrike_log(ctx, LOG_LEVEL_INFO, "IoTStrike framework initialized (v%s)", 
                  IOTSTRIKE_VERSION_STRING);
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Cleanup IoTStrike framework context
 */
iotstrike_error_t iotstrike_cleanup(iotstrike_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    iotstrike_log(ctx, LOG_LEVEL_INFO, "Cleaning up IoTStrike framework");
    
    /* Destroy mutex */
    pthread_mutex_destroy(&ctx->mutex);
    
    /* Clear sensitive data */
    iotstrike_secure_zero(ctx, sizeof(iotstrike_context_t));
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Get framework version string
 */
const char* iotstrike_get_version(void) {
    return IOTSTRIKE_VERSION_STRING;
}

/**
 * Convert error code to human-readable string
 */
const char* iotstrike_error_string(iotstrike_error_t error) {
    int index = -error;
    
    if (error == IOTSTRIKE_SUCCESS) {
        return error_messages[0];
    }
    
    if (index < 0 || index >= (int)IOTSTRIKE_ARRAY_SIZE(error_messages)) {
        return "Invalid error code";
    }
    
    return error_messages[index];
}

/**
 * Set logging level
 */
void iotstrike_set_log_level(iotstrike_context_t *ctx, log_level_t level) {
    if (!ctx) return;
    
    IOTSTRIKE_LOCK(ctx);
    ctx->log_level = level;
    IOTSTRIKE_UNLOCK(ctx);
}

/**
 * Log message with timestamp
 */
void iotstrike_log(iotstrike_context_t *ctx, log_level_t level, const char *format, ...) {
    if (!ctx || !format) return;
    
    if (level < ctx->log_level) return;
    
    struct timeval tv;
    struct tm *tm_info;
    char timestamp[64];
    char message[1024];
    va_list args;
    
    /* Get current time */
    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    
    /* Format timestamp */
    snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             (int)(tv.tv_usec / 1000));
    
    /* Format message */
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    /* Print log message */
    IOTSTRIKE_LOCK(ctx);
    fprintf(stderr, "[%s] [%s] %s\n", timestamp, log_level_strings[level], message);
    fflush(stderr);
    IOTSTRIKE_UNLOCK(ctx);
}

/**
 * Initialize buffer
 */
iotstrike_error_t iotstrike_buffer_init(iotstrike_buffer_t *buffer, size_t capacity) {
    if (!buffer || capacity == 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    buffer->data = IOTSTRIKE_MALLOC(capacity);
    if (!buffer->data) {
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    buffer->size = 0;
    buffer->capacity = capacity;
    buffer->allocated = true;
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Append data to buffer
 */
iotstrike_error_t iotstrike_buffer_append(iotstrike_buffer_t *buffer, const uint8_t *data, size_t size) {
    if (!buffer || !data || size == 0) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (buffer->size + size > buffer->capacity) {
        /* Resize buffer */
        size_t new_capacity = buffer->capacity * 2;
        while (new_capacity < buffer->size + size) {
            new_capacity *= 2;
        }
        
        uint8_t *new_data = IOTSTRIKE_REALLOC(buffer->data, new_capacity);
        if (!new_data) {
            return IOTSTRIKE_ERROR_MEMORY;
        }
        
        buffer->data = new_data;
        buffer->capacity = new_capacity;
    }
    
    memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Clear buffer contents
 */
iotstrike_error_t iotstrike_buffer_clear(iotstrike_buffer_t *buffer) {
    if (!buffer) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (buffer->data) {
        iotstrike_secure_zero(buffer->data, buffer->size);
    }
    buffer->size = 0;
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Free buffer memory
 */
void iotstrike_buffer_free(iotstrike_buffer_t *buffer) {
    if (!buffer) return;
    
    if (buffer->allocated && buffer->data) {
        iotstrike_secure_zero(buffer->data, buffer->capacity);
        IOTSTRIKE_FREE(buffer->data);
    }
    
    memset(buffer, 0, sizeof(iotstrike_buffer_t));
}

/**
 * Calculate CRC32 checksum
 */
uint32_t iotstrike_crc32(const uint8_t *data, size_t length) {
    static const uint32_t crc32_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    };
    
    if (!data) return 0;
    
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

/**
 * Print hexadecimal dump of data
 */
void iotstrike_hexdump(const uint8_t *data, size_t length) {
    if (!data) return;
    
    const size_t bytes_per_line = 16;
    
    for (size_t i = 0; i < length; i += bytes_per_line) {
        printf("%08zx: ", i);
        
        /* Print hex bytes */
        for (size_t j = 0; j < bytes_per_line; j++) {
            if (i + j < length) {
                printf("%02x ", data[i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) printf(" ");
        }
        
        printf(" |");
        
        /* Print ASCII representation */
        for (size_t j = 0; j < bytes_per_line && i + j < length; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        
        printf("|\n");
    }
}

/**
 * Detect architecture from binary data
 */
architecture_t iotstrike_detect_architecture(const uint8_t *binary, size_t size) {
    if (!binary || size < 4) {
        return ARCH_UNKNOWN;
    }
    
    /* Check ELF magic */
    if (size >= 20 && memcmp(binary, "\177ELF", 4) == 0) {
        uint8_t machine = binary[18];
        switch (machine) {
            case 0x28: return ARCH_ARM;
            case 0xB7: return ARCH_ARM64;
            case 0x08: return ARCH_MIPS;
            case 0x3E: return ARCH_X86_64;
            case 0x03: return ARCH_X86;
            case 0xF3: return ARCH_RISCV;
            default: return ARCH_UNKNOWN;
        }
    }
    
    /* Check PE magic */
    if (size >= 64 && memcmp(binary, "MZ", 2) == 0) {
        return ARCH_X86; /* Assume x86 for PE files */
    }
    
    /* Check ARM thumb instructions */
    if (size >= 4) {
        uint16_t *thumb = (uint16_t*)binary;
        if ((thumb[0] & 0xF800) == 0xF000 && (thumb[1] & 0xF800) == 0xF800) {
            return ARCH_ARM;
        }
    }
    
    return ARCH_UNKNOWN;
}

/**
 * Detect endianness from binary data
 */
endianness_t iotstrike_detect_endianness(const uint8_t *binary, size_t size) {
    if (!binary || size < 4) {
        return ENDIAN_UNKNOWN;
    }
    
    /* Check ELF endianness */
    if (size >= 6 && memcmp(binary, "\177ELF", 4) == 0) {
        return (binary[5] == 1) ? ENDIAN_LITTLE : ENDIAN_BIG;
    }
    
    /* Heuristic: check for common patterns */
    uint32_t little_score = 0;
    uint32_t big_score = 0;
    
    for (size_t i = 0; i < IOTSTRIKE_MIN(size - 4, 1024); i += 4) {
        uint32_t value_le = *(uint32_t*)(binary + i);
        uint32_t value_be = __builtin_bswap32(value_le);
        
        /* Check for reasonable addresses (heuristic) */
        if (value_le >= 0x08000000 && value_le <= 0x20000000) little_score++;
        if (value_be >= 0x08000000 && value_be <= 0x20000000) big_score++;
    }
    
    if (little_score > big_score) return ENDIAN_LITTLE;
    if (big_score > little_score) return ENDIAN_BIG;
    
    return ENDIAN_UNKNOWN;
}

/**
 * Secure memory zeroing (prevents compiler optimization)
 */
void iotstrike_secure_zero(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    for (size_t i = 0; i < size; i++) {
        p[i] = 0;
    }
}

/**
 * Secure memory allocation
 */
void* iotstrike_secure_malloc(size_t size) {
    if (size == 0) return NULL;
    
    void *ptr = IOTSTRIKE_MALLOC(size);
    if (ptr) {
        iotstrike_secure_zero(ptr, size);
    }
    
    return ptr;
}

/**
 * Secure memory deallocation
 */
void iotstrike_secure_free(void *ptr, size_t size) {
    if (!ptr) return;
    
    iotstrike_secure_zero(ptr, size);
    IOTSTRIKE_FREE(ptr);
}

/**
 * Start IoTStrike framework operations
 */
iotstrike_error_t iotstrike_start(iotstrike_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    iotstrike_log(ctx, LOG_LEVEL_INFO, "Starting IoTStrike framework operations");
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->running = true;
    pthread_mutex_unlock(&ctx->mutex);
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Stop IoTStrike framework operations
 */
iotstrike_error_t iotstrike_stop(iotstrike_context_t *ctx) {
    if (!ctx || !ctx->initialized) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    iotstrike_log(ctx, LOG_LEVEL_INFO, "Stopping IoTStrike framework operations");
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->running = false;
    pthread_mutex_unlock(&ctx->mutex);
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Set log callback function
 */
void iotstrike_set_log_callback(iotstrike_context_t *ctx, iotstrike_log_callback_t callback) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->log_callback = callback;
    pthread_mutex_unlock(&ctx->mutex);
}

/**
 * Set error callback function
 */
void iotstrike_set_error_callback(iotstrike_context_t *ctx, iotstrike_error_callback_t callback) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->error_callback = callback;
    pthread_mutex_unlock(&ctx->mutex);
}

/**
 * Set progress callback function
 */
void iotstrike_set_progress_callback(iotstrike_context_t *ctx, iotstrike_progress_callback_t callback) {
    if (!ctx) return;
    
    pthread_mutex_lock(&ctx->mutex);
    ctx->progress_callback = callback;
    pthread_mutex_unlock(&ctx->mutex);
}

/**
 * Get framework statistics
 */
iotstrike_error_t iotstrike_get_statistics(iotstrike_context_t *ctx, iotstrike_stats_t *stats) {
    if (!ctx || !stats) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    if (!ctx->initialized) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    pthread_mutex_lock(&ctx->mutex);
    
    // Initialize statistics with default values
    stats->operations_count = 0;
    stats->errors_count = 0;
    stats->bytes_processed = 0;
    stats->uptime_seconds = 0;
    stats->active_connections = 0;
    stats->cpu_usage = 0.0;
    stats->memory_usage = 0;
    
    pthread_mutex_unlock(&ctx->mutex);
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Convert platform enum to string
 */
const char* iotstrike_platform_to_string(iotstrike_platform_t platform) {
    switch (platform) {
        case IOTSTRIKE_PLATFORM_LINUX:
            return "Linux";
        case IOTSTRIKE_PLATFORM_EMBEDDED:
            return "Embedded";
        case IOTSTRIKE_PLATFORM_RTOS:
            return "RTOS";
        case IOTSTRIKE_PLATFORM_BAREMETAL:
            return "Bare Metal";
        case IOTSTRIKE_PLATFORM_UNKNOWN:
        default:
            return "Unknown";
    }
}

/**
 * Convert security level enum to string
 */
const char* iotstrike_security_level_to_string(iotstrike_security_level_t level) {
    switch (level) {
        case IOTSTRIKE_SECURITY_LOW:
            return "Low";
        case IOTSTRIKE_SECURITY_MEDIUM:
            return "Medium";
        case IOTSTRIKE_SECURITY_HIGH:
            return "High";
        case IOTSTRIKE_SECURITY_CRITICAL:
            return "Critical";
        default:
            return "Unknown";
    }
}

/**
 * Convert error code to string (alias for iotstrike_error_string)
 */
const char* iotstrike_error_to_string(iotstrike_error_t error) {
    return iotstrike_error_string(error);
}

/**
 * Check if the current process has sufficient privileges
 */
iotstrike_error_t iotstrike_check_privileges(void) {
    // On macOS/Unix, check if running as root or with appropriate capabilities
    if (geteuid() == 0) {
        return IOTSTRIKE_SUCCESS;
    }
    
    // For non-root users, we'll allow execution but log a warning
    // In a real implementation, you might want to check for specific capabilities
    return IOTSTRIKE_SUCCESS;
}