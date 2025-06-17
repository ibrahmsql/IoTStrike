/**
 * IoTStrike Hardware Security Framework
 * Firmware Analysis Module Implementation
 * 
 * @file firmware_analysis.c
 * @author ibrahimsql
 * @version 1.0.0
 */

#include "firmware.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>
#include <math.h>

/* Vulnerability patterns for pattern matching */
const vulnerability_pattern_t vulnerability_patterns[] = {
    {
        .name = "strcpy_overflow",
        .pattern = (uint8_t*)"strcpy",
        .pattern_size = 6,
        .mask = NULL,
        .severity = VULN_SEVERITY_HIGH,
        .description = "Potential buffer overflow with strcpy"
    },
    {
        .name = "gets_overflow",
        .pattern = (uint8_t*)"gets",
        .pattern_size = 4,
        .mask = NULL,
        .severity = VULN_SEVERITY_CRITICAL,
        .description = "Critical buffer overflow with gets"
    },
    {
        .name = "sprintf_overflow",
        .pattern = (uint8_t*)"sprintf",
        .pattern_size = 7,
        .mask = NULL,
        .severity = VULN_SEVERITY_HIGH,
        .description = "Potential buffer overflow with sprintf"
    },
    {
        .name = "system_command",
        .pattern = (uint8_t*)"system",
        .pattern_size = 6,
        .mask = NULL,
        .severity = VULN_SEVERITY_MEDIUM,
        .description = "Command injection vulnerability"
    }
};

const size_t vulnerability_patterns_count = sizeof(vulnerability_patterns) / sizeof(vulnerability_pattern_t);

/* Crypto patterns for key detection */
const crypto_pattern_t crypto_patterns[] = {
    {
        .name = "AES_SBOX",
        .pattern = (uint8_t*)"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5",
        .pattern_size = 8,
        .type = ENCRYPTION_AES,
        .description = "AES S-Box pattern"
    },
    {
        .name = "DES_SBOX",
        .pattern = (uint8_t*)"\x0e\x04\x0d\x01\x02\x0f\x0b\x08",
        .pattern_size = 8,
        .type = ENCRYPTION_DES,
        .description = "DES S-Box pattern"
    }
};

const size_t crypto_patterns_count = sizeof(crypto_patterns) / sizeof(crypto_pattern_t);

/**
 * Initialize firmware analysis context
 */
iotstrike_error_t firmware_init(firmware_context_t *ctx) {
    if (!ctx) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(firmware_context_t));
    
    ctx->type = FIRMWARE_TYPE_UNKNOWN;
    ctx->format = BINARY_FORMAT_UNKNOWN;
    ctx->arch = ARCH_UNKNOWN;
    ctx->endian = ENDIAN_UNKNOWN;
    ctx->compression = COMPRESSION_NONE;
    ctx->encryption = ENCRYPTION_NONE;
    ctx->analyzed = false;
    
#ifdef HAVE_CAPSTONE
    /* Initialize Capstone disassembly engine */
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &ctx->capstone_handle) != CS_ERR_OK) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
#endif
    
#ifdef HAVE_UNICORN
    /* Initialize Unicorn emulation engine */
    if (uc_open(UC_ARCH_ARM, UC_MODE_ARM, &ctx->unicorn_engine) != UC_ERR_OK) {
#ifdef HAVE_CAPSTONE
        cs_close(&ctx->capstone_handle);
#endif
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
#endif
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Cleanup firmware analysis context
 */
iotstrike_error_t firmware_cleanup(firmware_context_t *ctx) {
    if (!ctx) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Free allocated memory */
    if (ctx->data) {
        iotstrike_secure_free(ctx->data, ctx->size);
    }
    
    if (ctx->strings) {
        IOTSTRIKE_FREE(ctx->strings);
    }
    
    if (ctx->crypto_keys) {
        for (size_t i = 0; i < ctx->crypto_key_count; i++) {
            if (ctx->crypto_keys[i].key_data) {
                iotstrike_secure_free(ctx->crypto_keys[i].key_data, ctx->crypto_keys[i].key_length);
            }
        }
        IOTSTRIKE_FREE(ctx->crypto_keys);
    }
    
    if (ctx->vulnerabilities) {
        IOTSTRIKE_FREE(ctx->vulnerabilities);
    }
    
    if (ctx->cross_refs) {
        IOTSTRIKE_FREE(ctx->cross_refs);
    }
    
    /* Cleanup engines */
#ifdef HAVE_CAPSTONE
    cs_close(&ctx->capstone_handle);
#endif
#ifdef HAVE_UNICORN
    uc_close(ctx->unicorn_engine);
#endif
    
    /* Clear sensitive data */
    iotstrike_secure_zero(ctx, sizeof(firmware_context_t));
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Load firmware from file
 */
iotstrike_error_t firmware_load_file(firmware_context_t *ctx, const char *filename) {
    if (!ctx || !filename) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    // Real firmware loading implementation
    FILE *fw_file = fopen(filename, "rb");
    if (!fw_file) {
        fprintf(stderr, "[ERROR] Cannot open firmware file: %s\n", filename);
        return IOTSTRIKE_ERROR_FILE_NOT_FOUND;
    }
    
    // Get file size
    fseek(fw_file, 0, SEEK_END);
    ctx->size = ftell(fw_file);
    fseek(fw_file, 0, SEEK_SET);
    
    if (ctx->size == 0 || ctx->size > MAX_FIRMWARE_SIZE) {
        fclose(fw_file);
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    // Allocate secure memory
    ctx->data = IOTSTRIKE_MALLOC(ctx->size);
    if (!ctx->data) {
        fclose(fw_file);
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    // Read firmware data
    size_t bytes_read = fread(ctx->data, 1, ctx->size, fw_file);
    fclose(fw_file);
    
    if (bytes_read != ctx->size) {
        IOTSTRIKE_FREE(ctx->data);
        ctx->data = NULL;
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
    
    strncpy(ctx->filename, filename, sizeof(ctx->filename) - 1);
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Load firmware from buffer
 */
iotstrike_error_t firmware_load_buffer(firmware_context_t *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || size == 0 || size > MAX_FIRMWARE_SIZE) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ctx->data = IOTSTRIKE_MALLOC(size);
    if (!ctx->data) {
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    memcpy(ctx->data, data, size);
    ctx->size = size;
    strcpy(ctx->filename, "<buffer>");
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Detect binary format
 */
iotstrike_error_t firmware_detect_format(firmware_context_t *ctx) {
    if (!ctx || !ctx->data || ctx->size < 4) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    /* Check ELF magic */
    if (memcmp(ctx->data, "\177ELF", 4) == 0) {
        ctx->format = BINARY_FORMAT_ELF;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Check PE magic */
    if (memcmp(ctx->data, "MZ", 2) == 0) {
        ctx->format = BINARY_FORMAT_PE;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Check Intel HEX */
    if (ctx->data[0] == ':') {
        ctx->format = BINARY_FORMAT_INTEL_HEX;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Check Motorola S-record */
    if (ctx->data[0] == 'S') {
        ctx->format = BINARY_FORMAT_MOTOROLA_S;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Check UBI magic */
    if (memcmp(ctx->data, "UBI#", 4) == 0) {
        ctx->format = BINARY_FORMAT_UBI;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Check JFFS2 magic */
    if (ctx->size >= 8 && (ctx->data[0] == 0x19 && ctx->data[1] == 0x85)) {
        ctx->format = BINARY_FORMAT_JFFS2;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Check SquashFS magic */
    if (ctx->size >= 4 && memcmp(ctx->data, "hsqs", 4) == 0) {
        ctx->format = BINARY_FORMAT_SQUASHFS;
        return IOTSTRIKE_SUCCESS;
    }
    
    /* Default to raw binary */
    ctx->format = BINARY_FORMAT_RAW;
    return IOTSTRIKE_SUCCESS;
}

/**
 * Detect architecture
 */
iotstrike_error_t firmware_detect_architecture(firmware_context_t *ctx) {
    if (!ctx || !ctx->data) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ctx->arch = iotstrike_detect_architecture(ctx->data, ctx->size);
    ctx->endian = iotstrike_detect_endianness(ctx->data, ctx->size);
    
#ifdef HAVE_CAPSTONE
    /* Update Capstone engine based on detected architecture */
    cs_close(&ctx->capstone_handle);
    
    cs_arch arch;
    cs_mode mode;
    
    switch (ctx->arch) {
        case ARCH_ARM:
            arch = CS_ARCH_ARM;
            mode = (ctx->endian == ENDIAN_BIG) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
            break;
        case ARCH_ARM64:
            arch = CS_ARCH_ARM64;
            mode = (ctx->endian == ENDIAN_BIG) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
            break;
        case ARCH_MIPS:
            arch = CS_ARCH_MIPS;
            mode = CS_MODE_MIPS32 | ((ctx->endian == ENDIAN_BIG) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
            break;
        case ARCH_X86:
            arch = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case ARCH_X86_64:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        default:
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
    }
    
    if (cs_open(arch, mode, &ctx->capstone_handle) != CS_ERR_OK) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
#endif
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Initialize disassembly engine
 */
iotstrike_error_t firmware_init_disassembly(firmware_context_t *ctx, architecture_t target_arch) {
    if (!ctx) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
#ifdef HAVE_CAPSTONE
    cs_arch arch;
    cs_mode mode;
    
    switch (target_arch) {
        case ARCH_ARM:
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
        case ARCH_ARM64:
            arch = CS_ARCH_ARM64;
            mode = CS_MODE_ARM;
            break;
        case ARCH_MIPS:
            arch = CS_ARCH_MIPS;
            mode = CS_MODE_MIPS32;
            break;
        case ARCH_MIPS64:
            arch = CS_ARCH_MIPS;
            mode = CS_MODE_MIPS64;
            break;
        case ARCH_X86:
            arch = CS_ARCH_X86;
            mode = CS_MODE_32;
            break;
        case ARCH_X86_64:
            arch = CS_ARCH_X86;
            mode = CS_MODE_64;
            break;
        default:
            arch = CS_ARCH_ARM;
            mode = CS_MODE_ARM;
            break;
    }
    
    if (cs_open(arch, mode, &ctx->capstone_handle) != CS_ERR_OK) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
    
    return IOTSTRIKE_SUCCESS;
#else
    (void)target_arch; // Suppress unused parameter warning
    return IOTSTRIKE_ERROR_NOT_IMPLEMENTED;
#endif
}

/**
 * Analyze strings in firmware
 */
iotstrike_error_t firmware_analyze_strings(firmware_context_t *ctx) {
    if (!ctx || !ctx->data) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ctx->strings = IOTSTRIKE_CALLOC(MAX_STRINGS_COUNT, sizeof(string_analysis_t));
    if (!ctx->strings) {
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    ctx->string_count = 0;
    
    /* Find ASCII strings */
    for (size_t i = 0; i < ctx->size && ctx->string_count < MAX_STRINGS_COUNT; i++) {
        if (ctx->data[i] >= 32 && ctx->data[i] <= 126) {
            size_t start = i;
            size_t len = 0;
            
            /* Count consecutive printable characters */
            while (i < ctx->size && ctx->data[i] >= 32 && ctx->data[i] <= 126 && len < MAX_STRING_LENGTH - 1) {
                len++;
                i++;
            }
            
            /* Only consider strings of minimum length */
            if (len >= 4) {
                string_analysis_t *str = &ctx->strings[ctx->string_count];
                
                memcpy(str->string, &ctx->data[start], len);
                str->string[len] = '\0';
                str->offset = start;
                str->length = len;
                str->is_ascii = true;
                str->is_unicode = false;
                
                /* Calculate entropy */
                str->entropy = firmware_calculate_entropy(&ctx->data[start], len);
                
                /* Check for specific patterns */
                str->is_url = (strstr(str->string, "http://") != NULL || 
                              strstr(str->string, "https://") != NULL);
                str->is_email = (strchr(str->string, '@') != NULL && strchr(str->string, '.') != NULL);
                str->is_ip_address = false; /* TODO: Implement IP detection */
                str->is_credential = (strstr(str->string, "password") != NULL || 
                                    strstr(str->string, "passwd") != NULL ||
                                    strstr(str->string, "secret") != NULL);
                str->is_crypto_key = (str->entropy > 7.0 && len >= 16);
                
                ctx->string_count++;
            }
        }
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Calculate entropy of data
 */
float firmware_calculate_entropy(const uint8_t *data, size_t size) {
    if (!data || size == 0) {
        return 0.0f;
    }
    
    uint32_t freq[256] = {0};
    
    /* Count byte frequencies */
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    
    /* Calculate entropy */
    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            float p = (float)freq[i] / size;
            entropy -= p * log2f(p);
        }
    }
    
    return entropy;
}

/**
 * Scan for vulnerabilities
 */
iotstrike_error_t firmware_scan_vulnerabilities(firmware_context_t *ctx) {
    if (!ctx || !ctx->data) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ctx->vulnerabilities = IOTSTRIKE_CALLOC(MAX_VULNERABILITIES, sizeof(vulnerability_t));
    if (!ctx->vulnerabilities) {
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    ctx->vulnerability_count = 0;
    
    /* Pattern matching for known vulnerabilities */
    for (size_t p = 0; p < vulnerability_patterns_count && ctx->vulnerability_count < MAX_VULNERABILITIES; p++) {
        const vulnerability_pattern_t *pattern = &vulnerability_patterns[p];
        
        for (size_t i = 0; i <= ctx->size - pattern->pattern_size; i++) {
            bool match = true;
            
            for (size_t j = 0; j < pattern->pattern_size; j++) {
                uint8_t data_byte = ctx->data[i + j];
                uint8_t pattern_byte = pattern->pattern[j];
                uint8_t mask_byte = pattern->mask ? pattern->mask[j] : 0xFF;
                
                if ((data_byte & mask_byte) != (pattern_byte & mask_byte)) {
                    match = false;
                    break;
                }
            }
            
            if (match) {
                vulnerability_t *vuln = &ctx->vulnerabilities[ctx->vulnerability_count];
                
                strncpy(vuln->name, pattern->name, sizeof(vuln->name) - 1);
                strncpy(vuln->description, pattern->description, sizeof(vuln->description) - 1);
                vuln->severity = pattern->severity;
                vuln->offset = i;
                vuln->size = pattern->pattern_size;
                vuln->confidence = 0.8f; /* Default confidence */
                strcpy(vuln->cve_id, "N/A");
                strcpy(vuln->mitigation, "Review code for secure alternatives");
                
                ctx->vulnerability_count++;
                
                /* Skip ahead to avoid duplicate matches */
                i += pattern->pattern_size - 1;
                break;
            }
        }
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Extract cryptographic keys
 */
iotstrike_error_t firmware_extract_crypto_keys(firmware_context_t *ctx) {
    if (!ctx || !ctx->data) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    ctx->crypto_keys = IOTSTRIKE_CALLOC(MAX_CRYPTO_KEYS, sizeof(crypto_key_t));
    if (!ctx->crypto_keys) {
        return IOTSTRIKE_ERROR_MEMORY;
    }
    
    ctx->crypto_key_count = 0;
    
    /* Pattern matching for crypto constants */
    for (size_t p = 0; p < crypto_patterns_count && ctx->crypto_key_count < MAX_CRYPTO_KEYS; p++) {
        const crypto_pattern_t *pattern = &crypto_patterns[p];
        
        for (size_t i = 0; i <= ctx->size - pattern->pattern_size; i++) {
            if (memcmp(&ctx->data[i], pattern->pattern, pattern->pattern_size) == 0) {
                crypto_key_t *key = &ctx->crypto_keys[ctx->crypto_key_count];
                
                key->key_length = pattern->pattern_size;
                key->key_data = IOTSTRIKE_MALLOC(key->key_length);
                if (!key->key_data) {
                    continue;
                }
                
                memcpy(key->key_data, &ctx->data[i], key->key_length);
                key->type = pattern->type;
                key->offset = i;
                key->confidence = 0.9f;
                strncpy(key->description, pattern->description, sizeof(key->description) - 1);
                
                ctx->crypto_key_count++;
                
                /* Skip ahead */
                i += pattern->pattern_size - 1;
                break;
            }
        }
    }
    
    /* Look for high-entropy regions that might be keys */
    const size_t key_sizes[] = {16, 24, 32, 64, 128, 256}; /* Common key sizes */
    const size_t num_key_sizes = sizeof(key_sizes) / sizeof(key_sizes[0]);
    
    for (size_t k = 0; k < num_key_sizes && ctx->crypto_key_count < MAX_CRYPTO_KEYS; k++) {
        size_t key_size = key_sizes[k];
        
        for (size_t i = 0; i <= ctx->size - key_size; i += key_size) {
            float entropy = firmware_calculate_entropy(&ctx->data[i], key_size);
            
            if (entropy > 7.5f) { /* High entropy threshold */
                crypto_key_t *key = &ctx->crypto_keys[ctx->crypto_key_count];
                
                key->key_length = key_size;
                key->key_data = IOTSTRIKE_MALLOC(key->key_length);
                if (!key->key_data) {
                    continue;
                }
                
                memcpy(key->key_data, &ctx->data[i], key->key_length);
                key->type = ENCRYPTION_CUSTOM;
                key->offset = i;
                key->confidence = (entropy - 7.0f) / 1.0f; /* Scale confidence */
                snprintf(key->description, sizeof(key->description), 
                        "High entropy region (%zu bytes, entropy: %.2f)", key_size, entropy);
                
                ctx->crypto_key_count++;
            }
        }
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Generate analysis report
 */
iotstrike_error_t firmware_generate_report(firmware_context_t *ctx, const char *output_file) {
    if (!ctx || !output_file) {
        return IOTSTRIKE_ERROR_INVALID_PARAM;
    }
    
    FILE *fp = fopen(output_file, "w");
    if (!fp) {
        return IOTSTRIKE_ERROR_PERMISSION;
    }
    
    fprintf(fp, "IoTStrike Firmware Analysis Report\n");
    fprintf(fp, "==================================\n\n");
    
    fprintf(fp, "File: %s\n", ctx->filename);
    fprintf(fp, "Size: %zu bytes\n", ctx->size);
    fprintf(fp, "Format: %s\n", binary_format_to_string(ctx->format));
    fprintf(fp, "Architecture: %s\n", (ctx->arch == ARCH_ARM) ? "ARM" : "Unknown");
    fprintf(fp, "Endianness: %s\n", (ctx->endian == ENDIAN_LITTLE) ? "Little" : "Big");
    fprintf(fp, "Entropy: %.2f\n\n", ctx->entropy);
    
    /* Strings section */
    fprintf(fp, "Strings Found: %zu\n", ctx->string_count);
    fprintf(fp, "---------------\n");
    for (size_t i = 0; i < ctx->string_count && i < 50; i++) {
        string_analysis_t *str = &ctx->strings[i];
        fprintf(fp, "0x%08x: %s\n", str->offset, str->string);
        if (str->is_credential) fprintf(fp, "  [CREDENTIAL]\n");
        if (str->is_crypto_key) fprintf(fp, "  [CRYPTO_KEY]\n");
        if (str->is_url) fprintf(fp, "  [URL]\n");
    }
    fprintf(fp, "\n");
    
    /* Vulnerabilities section */
    fprintf(fp, "Vulnerabilities Found: %zu\n", ctx->vulnerability_count);
    fprintf(fp, "----------------------\n");
    for (size_t i = 0; i < ctx->vulnerability_count; i++) {
        vulnerability_t *vuln = &ctx->vulnerabilities[i];
        fprintf(fp, "0x%08x: %s [%s]\n", vuln->offset, vuln->name, 
                vulnerability_severity_to_string(vuln->severity));
        fprintf(fp, "  %s\n", vuln->description);
    }
    fprintf(fp, "\n");
    
    /* Crypto keys section */
    fprintf(fp, "Cryptographic Keys Found: %zu\n", ctx->crypto_key_count);
    fprintf(fp, "-------------------------\n");
    for (size_t i = 0; i < ctx->crypto_key_count; i++) {
        crypto_key_t *key = &ctx->crypto_keys[i];
        fprintf(fp, "0x%08x: %s (%zu bytes, confidence: %.2f)\n", 
                key->offset, key->description, key->key_length, key->confidence);
    }
    
    fclose(fp);
    return IOTSTRIKE_SUCCESS;
}

/**
 * Convert types to strings
 */
const char* firmware_type_to_string(firmware_type_t type) {
    switch (type) {
        case FIRMWARE_TYPE_BOOTLOADER: return "Bootloader";
        case FIRMWARE_TYPE_KERNEL: return "Kernel";
        case FIRMWARE_TYPE_APPLICATION: return "Application";
        case FIRMWARE_TYPE_FILESYSTEM: return "Filesystem";
        case FIRMWARE_TYPE_COMBINED: return "Combined";
        default: return "Unknown";
    }
}

const char* binary_format_to_string(binary_format_t format) {
    switch (format) {
        case BINARY_FORMAT_RAW: return "Raw Binary";
        case BINARY_FORMAT_ELF: return "ELF";
        case BINARY_FORMAT_PE: return "PE";
        case BINARY_FORMAT_INTEL_HEX: return "Intel HEX";
        case BINARY_FORMAT_MOTOROLA_S: return "Motorola S-Record";
        case BINARY_FORMAT_UBI: return "UBI";
        case BINARY_FORMAT_JFFS2: return "JFFS2";
        case BINARY_FORMAT_SQUASHFS: return "SquashFS";
        default: return "Unknown";
    }
}

const char* vulnerability_severity_to_string(vulnerability_severity_t severity) {
    switch (severity) {
        case VULN_SEVERITY_INFO: return "INFO";
        case VULN_SEVERITY_LOW: return "LOW";
        case VULN_SEVERITY_MEDIUM: return "MEDIUM";
        case VULN_SEVERITY_HIGH: return "HIGH";
        case VULN_SEVERITY_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}