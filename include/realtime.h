/**
 * IoTStrike Hardware Security Framework
 * Real-Time System Attack Simulator Header
 * 
 * @file realtime.h
 * @author ibrahimsql
 * @version 1.0.0
 */

#ifndef IOTSTRIKE_REALTIME_H
#define IOTSTRIKE_REALTIME_H

#include "iotstrike.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants
#define MAX_TIMING_SAMPLES 10000
#define MAX_ROP_GADGETS 1000
#define MAX_ROP_CHAIN_LENGTH 256
#define MAX_SHELLCODE_SIZE 1024
#define MAX_INTERRUPT_HANDLERS 32
#define MAX_MEMORY_REGIONS 64

// Real-Time Attack Types
typedef enum {
    RT_ATTACK_INTERRUPT_TIMING,
    RT_ATTACK_RACE_CONDITION,
    RT_ATTACK_MEMORY_CORRUPTION,
    RT_ATTACK_ROP_CHAIN,
    RT_ATTACK_JOP_CHAIN,
    RT_ATTACK_BOOTLOADER_MANIPULATION,
    RT_ATTACK_CACHE_TIMING,
    RT_ATTACK_BRANCH_PREDICTION
} realtime_attack_type_t;

// Memory Corruption Types
typedef enum {
    CORRUPTION_BUFFER_OVERFLOW,
    CORRUPTION_HEAP_OVERFLOW,
    CORRUPTION_STACK_OVERFLOW,
    CORRUPTION_USE_AFTER_FREE,
    CORRUPTION_DOUBLE_FREE,
    CORRUPTION_FORMAT_STRING,
    CORRUPTION_INTEGER_OVERFLOW
} memory_corruption_type_t;

// ROP Gadget Types
typedef enum {
    ROP_TYPE_POP_REG,
    ROP_TYPE_MOV_REG,
    ROP_TYPE_ARITHMETIC,
    ROP_TYPE_LOAD,
    ROP_TYPE_STORE,
    ROP_TYPE_CALL,
    ROP_TYPE_SYSCALL,
    ROP_TYPE_OTHER
} rop_gadget_type_t;

// ROP Exploit Types
typedef enum {
    ROP_EXPLOIT_EXECVE,
    ROP_EXPLOIT_MPROTECT,
    ROP_EXPLOIT_MMAP,
    ROP_EXPLOIT_CUSTOM
} rop_exploit_type_t;

// Bootloader Attack Types
typedef enum {
    BOOTLOADER_ATTACK_UBOOT,
    BOOTLOADER_ATTACK_GRUB,
    BOOTLOADER_ATTACK_UEFI,
    BOOTLOADER_ATTACK_CUSTOM
} bootloader_attack_type_t;

// Interrupt Types
typedef enum {
    INTERRUPT_TYPE_TIMER,
    INTERRUPT_TYPE_EXTERNAL,
    INTERRUPT_TYPE_SOFTWARE,
    INTERRUPT_TYPE_NMI,
    INTERRUPT_TYPE_EXCEPTION
} interrupt_type_t;

// Timing Sample Structure
typedef struct {
    uint64_t timestamp;
    uint64_t duration_ns;
    uint32_t interrupt_count;
    uint32_t context_switches;
    uint32_t cache_misses;
} timing_sample_t;

// ROP Gadget Structure
typedef struct {
    uint64_t address;
    char instruction[64];
    uint8_t size;
    rop_gadget_type_t type;
    uint32_t usefulness_score;
} rop_gadget_t;

// ROP Chain Structure
typedef struct {
    rop_gadget_t gadgets[MAX_ROP_GADGETS];
    int gadget_count;
    uint64_t chain[MAX_ROP_CHAIN_LENGTH];
    int chain_length;
    uint64_t stack_pivot_address;
} rop_chain_t;

// Memory Region Structure
typedef struct {
    uint64_t start_address;
    uint64_t end_address;
    uint32_t permissions; // rwx bits
    bool executable;
    bool writable;
    bool readable;
    char name[64];
} memory_region_t;

// Interrupt Handler Structure
typedef struct {
    uint32_t interrupt_number;
    uint64_t handler_address;
    interrupt_type_t type;
    uint32_t priority;
    bool enabled;
    uint64_t call_count;
} interrupt_handler_t;

// Real-Time Configuration
typedef struct {
    bool use_realtime_scheduling;
    int rt_priority;
    bool lock_memory;
    uint32_t max_samples;
    uint32_t sample_rate_hz;
    bool enable_performance_counters;
} realtime_config_t;

// Interrupt Attack Configuration
typedef struct {
    interrupt_type_t interrupt_type;
    uint32_t interrupt_interval_us;
    uint32_t operation_count;
    uint32_t iterations;
    uint32_t delay_between_tests_us;
    double variance_threshold;
    bool measure_cache_effects;
} interrupt_attack_config_t;

// Race Condition Configuration
typedef struct {
    uint32_t thread_count;
    uint32_t iterations;
    uint32_t shared_resource_size;
    uint32_t access_delay_us;
    bool use_atomic_operations;
    bool enable_detection;
} race_condition_config_t;

// Memory Corruption Configuration
typedef struct {
    memory_corruption_type_t corruption_type;
    uint32_t buffer_size;
    uint32_t overflow_size;
    uint8_t *payload;
    size_t payload_size;
    bool enable_canary_bypass;
    bool enable_aslr_bypass;
} memory_corruption_config_t;

// ROP Exploit Configuration
typedef struct {
    rop_exploit_type_t exploit_type;
    uint64_t shell_address;
    uint64_t libc_base;
    uint64_t stack_address;
    uint64_t custom_chain[MAX_ROP_CHAIN_LENGTH];
    int custom_chain_length;
    bool enable_stack_pivot;
} rop_exploit_config_t;

// Bootloader Attack Configuration
typedef struct {
    bootloader_attack_type_t attack_type;
    char target_file[256];
    char target_variable[64];
    char new_value[256];
    uint32_t attack_delay_ms;
    bool persistent_modification;
} bootloader_attack_config_t;

// Cache Attack Configuration
typedef struct {
    uint64_t target_address;
    uint32_t cache_line_size;
    uint32_t cache_sets;
    uint32_t cache_ways;
    uint32_t probe_count;
    uint32_t prime_count;
    bool flush_reload;
    bool prime_probe;
} cache_attack_config_t;

// Real-Time Attack Context
typedef struct {
    realtime_config_t config;
    bool initialized;
    bool attack_active;
    
    // Timing measurements
    timing_sample_t *timing_samples;
    int sample_count;
    
    // Memory regions
    memory_region_t memory_regions[MAX_MEMORY_REGIONS];
    int region_count;
    
    // Interrupt handlers
    interrupt_handler_t interrupt_handlers[MAX_INTERRUPT_HANDLERS];
    int handler_count;
    
    // Synchronization
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    
    // Performance counters
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t branch_mispredictions;
    uint64_t context_switches;
} realtime_context_t;

// Shellcode Structure
typedef struct {
    uint8_t code[MAX_SHELLCODE_SIZE];
    size_t size;
    iotstrike_arch_t architecture;
    bool position_independent;
    bool null_byte_free;
    char description[128];
} shellcode_t;

// Exploit Payload Structure
typedef struct {
    uint8_t *payload;
    size_t payload_size;
    uint64_t return_address;
    uint64_t shellcode_address;
    rop_chain_t *rop_chain;
    shellcode_t *shellcode;
    bool use_rop;
    bool use_shellcode;
} exploit_payload_t;

// Real-Time Attack Statistics
typedef struct {
    uint32_t attacks_performed;
    uint32_t vulnerabilities_found;
    uint32_t timing_samples_collected;
    uint64_t avg_timing_ns;
    uint64_t min_timing_ns;
    uint64_t max_timing_ns;
    double timing_variance;
    uint32_t race_conditions_detected;
    uint32_t memory_corruptions_successful;
    uint32_t rop_chains_generated;
    uint32_t bootloader_attacks_successful;
} realtime_stats_t;

// Function Prototypes

// Core Real-Time Functions
iotstrike_error_t realtime_attack_init(realtime_context_t *ctx, realtime_config_t *config);
void realtime_attack_cleanup(realtime_context_t *ctx);
iotstrike_error_t realtime_set_priority(int priority);
iotstrike_error_t realtime_lock_memory(void);
iotstrike_error_t realtime_unlock_memory(void);

// Interrupt Timing Attacks
iotstrike_error_t interrupt_timing_attack(realtime_context_t *ctx, interrupt_attack_config_t *config);
iotstrike_error_t setup_interrupt_handler(realtime_context_t *ctx, uint32_t interrupt_num, void (*handler)(void));
iotstrike_error_t trigger_interrupt(uint32_t interrupt_num);
iotstrike_error_t measure_interrupt_latency(uint32_t interrupt_num, uint64_t *latency_ns);

// Race Condition Exploitation
iotstrike_error_t race_condition_exploit(realtime_context_t *ctx, race_condition_config_t *config);
iotstrike_error_t create_race_threads(race_condition_config_t *config, pthread_t *threads);
iotstrike_error_t detect_race_condition(realtime_context_t *ctx, bool *detected);

// Memory Corruption Techniques
iotstrike_error_t simulate_memory_corruption(realtime_context_t *ctx, memory_corruption_config_t *config);
iotstrike_error_t buffer_overflow_exploit(uint8_t *buffer, size_t buffer_size, exploit_payload_t *payload);
iotstrike_error_t heap_overflow_exploit(void *heap_chunk, size_t chunk_size, exploit_payload_t *payload);
iotstrike_error_t use_after_free_exploit(void *freed_ptr, exploit_payload_t *payload);
iotstrike_error_t format_string_exploit(const char *format_string, exploit_payload_t *payload);

// ROP/JOP Chain Generation
iotstrike_error_t find_rop_gadgets(const uint8_t *binary_data, size_t binary_size, iotstrike_arch_t arch, rop_chain_t *chain);
iotstrike_error_t generate_rop_chain(rop_chain_t *chain, rop_exploit_config_t *config);
iotstrike_error_t validate_rop_chain(rop_chain_t *chain, bool *valid);
iotstrike_error_t execute_rop_chain(rop_chain_t *chain, uint64_t stack_address);

// Shellcode Generation
iotstrike_error_t generate_shellcode(shellcode_t *shellcode, iotstrike_arch_t arch, const char *command);
iotstrike_error_t encode_shellcode(shellcode_t *input, shellcode_t *output, const char *encoder);
iotstrike_error_t validate_shellcode(shellcode_t *shellcode, bool *valid);

// Bootloader Manipulation
iotstrike_error_t bootloader_manipulation_attack(bootloader_attack_config_t *config);
iotstrike_error_t uboot_environment_attack(const char *variable, const char *value);
iotstrike_error_t grub_config_attack(const char *config_file, const char *payload);
iotstrike_error_t uefi_variable_attack(const char *variable, const uint8_t *data, size_t data_size);

// Cache Timing Attacks
iotstrike_error_t cache_timing_attack(realtime_context_t *ctx, cache_attack_config_t *config);
iotstrike_error_t flush_reload_attack(uint64_t target_address, uint64_t *timing);
iotstrike_error_t prime_probe_attack(uint64_t cache_set, uint64_t *timing);
iotstrike_error_t evict_time_attack(uint64_t target_address, uint64_t *timing);

// Memory Analysis
iotstrike_error_t analyze_memory_layout(realtime_context_t *ctx);
iotstrike_error_t find_executable_regions(realtime_context_t *ctx, memory_region_t *regions, int *count);
iotstrike_error_t bypass_aslr(realtime_context_t *ctx, uint64_t *base_address);
iotstrike_error_t bypass_stack_canary(uint8_t *canary_value);

// Performance Monitoring
iotstrike_error_t enable_performance_counters(realtime_context_t *ctx);
iotstrike_error_t read_performance_counters(realtime_context_t *ctx);
iotstrike_error_t analyze_performance_data(realtime_context_t *ctx);

// Assembly Utilities (from asm_utils.s)
extern void flush_cache_line(void *addr);
extern void memory_barrier(void);
extern int atomic_increment(int *value);
extern uint64_t get_cpu_cycles(void);
extern void get_cpu_features(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx);
extern uint64_t timing_attack_primitive(void *addr);
extern uint64_t cache_timing_attack_primitive(void *addr);
extern void speculative_execution_barrier(void);

// ARM-specific functions
#ifdef __aarch64__
extern void flush_cache_line_arm64(void *addr);
extern void memory_barrier_arm64(void);
extern int atomic_increment_arm64(int *value);
extern uint64_t get_cpu_cycles_arm64(void);
extern uint64_t timing_attack_primitive_arm64(void *addr);
extern uint64_t cache_timing_attack_arm64(void *addr);
#elif defined(__arm__)
extern void flush_cache_line_arm(void *addr);
extern void memory_barrier_arm(void);
extern int atomic_increment_arm(int *value);
extern uint64_t get_cpu_cycles_arm(void);
extern uint32_t timing_attack_primitive_arm(void *addr);
#endif

// Statistics and Reporting
iotstrike_error_t realtime_get_statistics(realtime_context_t *ctx, realtime_stats_t *stats);
iotstrike_error_t realtime_generate_report(realtime_context_t *ctx, const char *filename);
void realtime_stop_all_attacks(realtime_context_t *ctx);

// Utility Functions
const char *realtime_attack_type_to_string(realtime_attack_type_t type);
const char *memory_corruption_type_to_string(memory_corruption_type_t type);
const char *rop_gadget_type_to_string(rop_gadget_type_t type);
const char *bootloader_attack_type_to_string(bootloader_attack_type_t type);
const char *interrupt_type_to_string(interrupt_type_t type);

// Platform-specific timing functions
#ifdef __x86_64__
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#endif

#ifdef __aarch64__
static inline uint64_t read_cycle_counter(void) {
    uint64_t val;
    __asm__ __volatile__ ("mrs %0, cntvct_el0" : "=r" (val));
    return val;
}
#endif

#ifdef __cplusplus
}
#endif

#endif // IOTSTRIKE_REALTIME_H