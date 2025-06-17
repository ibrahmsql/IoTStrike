/**
 * IoTStrike Hardware Security Framework
 * Firmware Analysis Module Header
 * 
 * @file firmware.h
 * @author ibrahimsql
 * @brief IoTStrike Hardware Security Framework
 * @version 1.0.0
 */

#ifndef FIRMWARE_H
#define FIRMWARE_H

#include "iotstrike.h"

// Optional dependencies - disable if not available
#ifdef HAVE_CAPSTONE
#include <capstone/capstone.h>
#else
// Minimal capstone definitions for compilation
typedef size_t cs_arch;
typedef size_t cs_mode;
typedef size_t csh;
#define CS_ARCH_ARM 0
#define CS_ARCH_MIPS 1
#define CS_ARCH_X86 2
#define CS_MODE_LITTLE_ENDIAN 0
#define CS_MODE_BIG_ENDIAN 1
#endif

#ifdef HAVE_UNICORN
#include <unicorn/unicorn.h>
#else
// Minimal unicorn definitions for compilation
typedef size_t uc_engine;
typedef size_t uc_arch;
typedef size_t uc_mode;
#define UC_ARCH_ARM 0
#define UC_ARCH_MIPS 1
#define UC_ARCH_X86 2
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Firmware Analysis Constants */
#define MAX_FIRMWARE_SIZE (64 * 1024 * 1024)  // 64MB
#define MAX_STRINGS_COUNT 10000
#define MAX_STRING_LENGTH 256
#define MAX_CRYPTO_KEYS 100
#define MAX_VULNERABILITIES 1000

/* Firmware Types */
typedef enum {
    FIRMWARE_TYPE_UNKNOWN = 0,
    FIRMWARE_TYPE_BOOTLOADER,
    FIRMWARE_TYPE_KERNEL,
    FIRMWARE_TYPE_APPLICATION,
    FIRMWARE_TYPE_FILESYSTEM,
    FIRMWARE_TYPE_COMBINED
} firmware_type_t;

/* Binary Formats */
typedef enum {
    BINARY_FORMAT_UNKNOWN = 0,
    BINARY_FORMAT_RAW,
    BINARY_FORMAT_ELF,
    BINARY_FORMAT_PE,
    BINARY_FORMAT_MACH_O,
    BINARY_FORMAT_INTEL_HEX,
    BINARY_FORMAT_MOTOROLA_S,
    BINARY_FORMAT_UBI,
    BINARY_FORMAT_JFFS2,
    BINARY_FORMAT_CRAMFS,
    BINARY_FORMAT_SQUASHFS
} binary_format_t;

/* Compression Types */
typedef enum {
    COMPRESSION_NONE = 0,
    COMPRESSION_GZIP,
    COMPRESSION_BZIP2,
    COMPRESSION_LZMA,
    COMPRESSION_LZ4,
    COMPRESSION_ZSTD
} compression_type_t;

/* Encryption Types */
typedef enum {
    ENCRYPTION_NONE = 0,
    ENCRYPTION_AES,
    ENCRYPTION_DES,
    ENCRYPTION_3DES,
    ENCRYPTION_RC4,
    ENCRYPTION_CHACHA20,
    ENCRYPTION_CUSTOM
} encryption_type_t;

/* Vulnerability Severity */
typedef enum {
    VULN_SEVERITY_INFO = 0,
    VULN_SEVERITY_LOW,
    VULN_SEVERITY_MEDIUM,
    VULN_SEVERITY_HIGH,
    VULN_SEVERITY_CRITICAL
} vulnerability_severity_t;

/* String Analysis Result */
typedef struct {
    char string[MAX_STRING_LENGTH];
    uint32_t offset;
    uint32_t length;
    bool is_ascii;
    bool is_unicode;
    bool is_url;
    bool is_email;
    bool is_ip_address;
    bool is_credential;
    bool is_crypto_key;
    float entropy;
} string_analysis_t;

/* Cryptographic Key */
typedef struct {
    uint8_t *key_data;
    size_t key_length;
    encryption_type_t type;
    uint32_t offset;
    float confidence;
    char description[128];
} crypto_key_t;

/* Vulnerability Finding */
typedef struct {
    char name[128];
    char description[512];
    vulnerability_severity_t severity;
    uint32_t offset;
    uint32_t size;
    char cve_id[32];
    float confidence;
    char mitigation[256];
} vulnerability_t;

/* Cross-Reference */
typedef struct {
    uint32_t from_offset;
    uint32_t to_offset;
    char function_name[128];
    char reference_type[32];  // call, jump, data_ref
    architecture_t arch;
} cross_reference_t;

/* Firmware Analysis Context */
typedef struct {
    uint8_t *data;
    size_t size;
    char filename[MAX_PATH_LENGTH];
    
    /* Metadata */
    firmware_type_t type;
    binary_format_t format;
    architecture_t arch;
    endianness_t endian;
    compression_type_t compression;
    encryption_type_t encryption;
    
    /* Analysis Results */
    string_analysis_t *strings;
    size_t string_count;
    
    crypto_key_t *crypto_keys;
    size_t crypto_key_count;
    
    vulnerability_t *vulnerabilities;
    size_t vulnerability_count;
    
    cross_reference_t *cross_refs;
    size_t cross_ref_count;
    
    /* Disassembly Context */
    csh capstone_handle;
    uc_engine *unicorn_engine;
    
    /* Statistics */
    uint32_t entry_point;
    uint32_t code_sections;
    uint32_t data_sections;
    uint32_t function_count;
    float entropy;
    
    bool analyzed;
} firmware_context_t;

/* Function Prototypes - Core */
iotstrike_error_t firmware_init(firmware_context_t *ctx);
iotstrike_error_t firmware_cleanup(firmware_context_t *ctx);
iotstrike_error_t firmware_load_file(firmware_context_t *ctx, const char *filename);
iotstrike_error_t firmware_load_buffer(firmware_context_t *ctx, const uint8_t *data, size_t size);

/* Function Prototypes - Binary Analysis */
iotstrike_error_t firmware_detect_format(firmware_context_t *ctx);
iotstrike_error_t firmware_detect_architecture(firmware_context_t *ctx);
iotstrike_error_t firmware_detect_compression(firmware_context_t *ctx);
iotstrike_error_t firmware_detect_encryption(firmware_context_t *ctx);

/* Function Prototypes - Extraction */
iotstrike_error_t firmware_extract(firmware_context_t *ctx, const char *output_dir);
iotstrike_error_t firmware_decompress(firmware_context_t *ctx);
iotstrike_error_t firmware_decrypt(firmware_context_t *ctx, const uint8_t *key, size_t key_len);

/* Function Prototypes - String Analysis */
iotstrike_error_t firmware_analyze_strings(firmware_context_t *ctx);
iotstrike_error_t firmware_find_credentials(firmware_context_t *ctx);
iotstrike_error_t firmware_find_urls(firmware_context_t *ctx);
iotstrike_error_t firmware_find_ip_addresses(firmware_context_t *ctx);
float firmware_calculate_entropy(const uint8_t *data, size_t size);

/* Function Prototypes - Cryptographic Analysis */
iotstrike_error_t firmware_extract_crypto_keys(firmware_context_t *ctx);
iotstrike_error_t firmware_find_aes_keys(firmware_context_t *ctx);
iotstrike_error_t firmware_find_rsa_keys(firmware_context_t *ctx);
iotstrike_error_t firmware_find_certificates(firmware_context_t *ctx);

/* Function Prototypes - Vulnerability Analysis */
iotstrike_error_t firmware_scan_vulnerabilities(firmware_context_t *ctx);
iotstrike_error_t firmware_check_buffer_overflows(firmware_context_t *ctx);
iotstrike_error_t firmware_check_format_strings(firmware_context_t *ctx);
iotstrike_error_t firmware_check_weak_crypto(firmware_context_t *ctx);
iotstrike_error_t firmware_check_hardcoded_secrets(firmware_context_t *ctx);

/* Function Prototypes - Disassembly */
iotstrike_error_t firmware_disassemble(firmware_context_t *ctx, uint32_t address, size_t size);
iotstrike_error_t firmware_find_functions(firmware_context_t *ctx);
iotstrike_error_t firmware_analyze_control_flow(firmware_context_t *ctx);
iotstrike_error_t firmware_build_call_graph(firmware_context_t *ctx);

/* Function Prototypes - Cross-Reference Analysis */
iotstrike_error_t firmware_build_cross_references(firmware_context_t *ctx);
iotstrike_error_t firmware_find_function_calls(firmware_context_t *ctx);
iotstrike_error_t firmware_find_data_references(firmware_context_t *ctx);

/* Function Prototypes - Emulation */
iotstrike_error_t firmware_setup_emulation(firmware_context_t *ctx);
iotstrike_error_t firmware_emulate_function(firmware_context_t *ctx, uint32_t address);
iotstrike_error_t firmware_trace_execution(firmware_context_t *ctx, uint32_t start, uint32_t end);

/* Function Prototypes - Reporting */
iotstrike_error_t firmware_generate_report(firmware_context_t *ctx, const char *output_file);
iotstrike_error_t firmware_export_json(firmware_context_t *ctx, const char *output_file);
iotstrike_error_t firmware_export_xml(firmware_context_t *ctx, const char *output_file);

/* Function Prototypes - Utility */
const char* firmware_type_to_string(firmware_type_t type);
const char* binary_format_to_string(binary_format_t format);
const char* compression_type_to_string(compression_type_t type);
const char* encryption_type_to_string(encryption_type_t type);
const char* vulnerability_severity_to_string(vulnerability_severity_t severity);

/* Pattern Matching */
typedef struct {
    const char *name;
    const uint8_t *pattern;
    size_t pattern_size;
    const uint8_t *mask;
    vulnerability_severity_t severity;
    const char *description;
} vulnerability_pattern_t;

extern const vulnerability_pattern_t vulnerability_patterns[];
extern const size_t vulnerability_patterns_count;

/* Crypto Patterns */
typedef struct {
    const char *name;
    const uint8_t *pattern;
    size_t pattern_size;
    encryption_type_t type;
    const char *description;
} crypto_pattern_t;

extern const crypto_pattern_t crypto_patterns[];
extern const size_t crypto_patterns_count;

#ifdef __cplusplus
}
#endif

#endif /* FIRMWARE_H */