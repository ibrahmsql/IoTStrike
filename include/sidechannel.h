/**
 * IoTStrike Hardware Security Framework
 * Side-Channel Attack Framework Header
 * 
 * @file sidechannel.h
 * @author ibrahimsql
 * @version 1.0.0
 */

#ifndef IOTSTRIKE_SIDECHANNEL_H
#define IOTSTRIKE_SIDECHANNEL_H

#include "iotstrike.h"
#include <stdint.h>
#include <stdbool.h>
#include <complex.h>

#ifdef __cplusplus
extern "C" {
#endif

// Complex number type definition
#ifdef __STDC_NO_COMPLEX__
typedef struct {
    double real;
    double imag;
} double_complex;
#else
typedef double complex double_complex;
#endif

// Constants
#define MAX_POWER_TRACES 10000
#define MAX_TRACE_LENGTH 100000
#define MAX_PLAINTEXTS 10000
#define MAX_CIPHERTEXTS 10000
#define MAX_TEMPLATES 256
#define MAX_POINTS_OF_INTEREST 1000
#define MAX_EM_PROBES 16
#define MAX_ACOUSTIC_SENSORS 8
#define MAX_FREQUENCY_BINS 8192

// Side-Channel Attack Types
typedef enum {
    SIDECHANNEL_POWER_ANALYSIS,
    SIDECHANNEL_EM_ANALYSIS,
    SIDECHANNEL_TIMING_ANALYSIS,
    SIDECHANNEL_CACHE_ANALYSIS,
    SIDECHANNEL_ACOUSTIC_ANALYSIS,
    SIDECHANNEL_FAULT_INJECTION,
    SIDECHANNEL_TEMPLATE_ATTACK
} sidechannel_attack_type_t;

// Power Analysis Types
typedef enum {
    POWER_ANALYSIS_SPA,  // Simple Power Analysis
    POWER_ANALYSIS_DPA,  // Differential Power Analysis
    POWER_ANALYSIS_CPA,  // Correlation Power Analysis
    POWER_ANALYSIS_MIA,  // Mutual Information Analysis
    POWER_ANALYSIS_TEMPLATE
} power_analysis_type_t;

// EM Analysis Types
typedef enum {
    EM_ANALYSIS_SIMPLE,
    EM_ANALYSIS_DIFFERENTIAL,
    EM_ANALYSIS_CORRELATION,
    EM_ANALYSIS_TEMPLATE,
    EM_ANALYSIS_FREQUENCY_DOMAIN
} em_analysis_type_t;

// Timing Attack Types
typedef enum {
    TIMING_ATTACK_SIMPLE,
    TIMING_ATTACK_STATISTICAL,
    TIMING_ATTACK_CORRELATION,
    TIMING_ATTACK_TEMPLATE
} timing_attack_type_t;

// Cache Attack Types
typedef enum {
    CACHE_ATTACK_FLUSH_RELOAD,
    CACHE_ATTACK_PRIME_PROBE,
    CACHE_ATTACK_EVICT_TIME,
    CACHE_ATTACK_FLUSH_FLUSH
} cache_attack_type_t;

// Fault Injection Types
typedef enum {
    FAULT_INJECTION_VOLTAGE_GLITCH,
    FAULT_INJECTION_CLOCK_GLITCH,
    FAULT_INJECTION_EM_PULSE,
    FAULT_INJECTION_LASER,
    FAULT_INJECTION_TEMPERATURE
} fault_injection_type_t;

// Cryptographic Algorithms
typedef enum {
    CRYPTO_ALGORITHM_AES,
    CRYPTO_ALGORITHM_DES,
    CRYPTO_ALGORITHM_RSA,
    CRYPTO_ALGORITHM_ECC,
    CRYPTO_ALGORITHM_CUSTOM
} crypto_algorithm_t;

// Power Sample Structure
typedef struct {
    uint64_t timestamp;
    double voltage;
    double current;
    double power;
} power_sample_t;

// EM Sample Structure
typedef struct {
    uint64_t timestamp;
    double amplitude;
    double phase;
    uint32_t frequency;
    uint8_t probe_id;
} em_sample_t;

// Timing Sample Structure (defined in realtime.h)
// typedef struct timing_sample_t is already defined in realtime.h

// Cache Sample Structure
typedef struct {
    uint64_t timestamp;
    uint64_t address;
    uint64_t access_time;
    bool cache_hit;
    uint32_t cache_set;
    uint32_t cache_way;
} cache_sample_t;

// Acoustic Sample Structure
typedef struct {
    uint64_t timestamp;
    double amplitude;
    uint32_t frequency;
    uint8_t sensor_id;
    double_complex fft_data[MAX_FREQUENCY_BINS];
} acoustic_sample_t;

// Simple Power Analysis Result
typedef struct {
    double max_power;
    double min_power;
    double avg_power;
    double variance;
    double std_deviation;
    uint32_t peak_count;
    double snr; // Signal-to-noise ratio
    uint64_t *peak_locations;
    uint32_t peak_location_count;
} spa_result_t;

// Differential Power Analysis Result
typedef struct {
    uint8_t recovered_key[32];
    uint8_t key_length;
    double confidence_scores[256];
    double max_differential;
    uint32_t best_key_hypothesis;
    uint32_t traces_used;
} dpa_result_t;

// Correlation Power Analysis Result
typedef struct {
    uint8_t recovered_key[32];
    uint8_t key_length;
    double correlation_coefficients[256];
    double max_correlation;
    uint32_t best_key_hypothesis;
    uint32_t point_of_interest;
    uint32_t traces_used;
} cpa_result_t;

// Template Attack Result
typedef struct {
    uint8_t recovered_key[32];
    uint8_t key_length;
    double likelihood_scores[256];
    double max_likelihood;
    uint32_t best_template;
    uint32_t templates_used;
} template_result_t;

// Power Template Structure
typedef struct {
    uint8_t key_hypothesis;
    double *mean_trace;
    double *covariance_matrix;
    uint32_t *points_of_interest;
    uint32_t point_count;
    uint32_t trace_count;
    crypto_algorithm_t algorithm;
} power_template_t;

// EM Analysis Configuration
typedef struct {
    uint32_t sampling_rate;
    uint32_t frequency_range_start;
    uint32_t frequency_range_end;
    uint8_t probe_count;
    double amplification_gain;
    bool enable_filtering;
    double filter_cutoff;
} em_analysis_config_t;

// EM Analysis Context
typedef struct {
    em_analysis_config_t config;
    em_sample_t *samples;
    uint32_t sample_count;
    uint32_t max_samples;
    bool recording_active;
    uint8_t active_probes[MAX_EM_PROBES];
    double probe_positions[MAX_EM_PROBES][3]; // x, y, z coordinates
} em_analysis_context_t;

// Timing Analysis Configuration
typedef struct {
    timing_attack_type_t attack_type;
    uint32_t measurement_count;
    uint32_t warmup_iterations;
    bool enable_statistical_analysis;
    double significance_threshold;
    bool enable_outlier_removal;
} timing_analysis_config_t;

// Timing Analysis Context
typedef struct {
    timing_analysis_config_t config;
    timing_sample_t *samples;
    uint32_t sample_count;
    uint32_t max_samples;
    bool measurement_active;
    double mean_timing;
    double timing_variance;
    double timing_std_dev;
} timing_analysis_context_t;

// Cache Analysis Configuration
typedef struct {
    cache_attack_type_t attack_type;
    uint32_t cache_line_size;
    uint32_t cache_sets;
    uint32_t cache_ways;
    uint64_t target_address;
    uint32_t probe_count;
    uint32_t measurement_rounds;
} cache_analysis_config_t;

// Cache Analysis Context
typedef struct {
    cache_analysis_config_t config;
    cache_sample_t *samples;
    uint32_t sample_count;
    uint32_t max_samples;
    bool analysis_active;
    uint64_t cache_hit_threshold;
    uint64_t cache_miss_threshold;
} cache_analysis_context_t;

// Acoustic Analysis Configuration
typedef struct {
    uint32_t sampling_rate;
    uint32_t fft_size;
    uint32_t overlap_ratio;
    double frequency_range_start;
    double frequency_range_end;
    uint8_t sensor_count;
    bool enable_noise_reduction;
    double noise_threshold;
} acoustic_analysis_config_t;

// Acoustic Analysis Context
typedef struct {
    acoustic_analysis_config_t config;
    acoustic_sample_t *samples;
    uint32_t sample_count;
    uint32_t max_samples;
    bool recording_active;
    double sensor_positions[MAX_ACOUSTIC_SENSORS][3]; // x, y, z coordinates
    double background_noise_level;
} acoustic_analysis_context_t;

// Fault Injection Configuration
typedef struct {
    fault_injection_type_t injection_type;
    uint64_t target_address;
    uint64_t trigger_time;
    double injection_voltage;
    uint32_t injection_duration_ns;
    uint32_t injection_width_ns;
    bool enable_feedback;
    uint32_t max_attempts;
} fault_injection_config_t;

// Fault Injection Context
typedef struct {
    fault_injection_config_t config;
    bool injection_active;
    uint32_t successful_faults;
    uint32_t total_attempts;
    uint64_t last_fault_time;
    bool target_crashed;
    uint8_t fault_response[1024];
    uint32_t response_length;
} fault_injection_context_t;

// Side-Channel Attack Statistics
typedef struct {
    uint32_t power_traces_collected;
    uint32_t em_traces_collected;
    uint32_t timing_measurements;
    uint32_t cache_measurements;
    uint32_t acoustic_samples;
    uint32_t successful_key_recoveries;
    uint32_t failed_attacks;
    double average_snr;
    double best_correlation;
    uint32_t templates_built;
    uint32_t fault_injections_attempted;
    uint32_t successful_fault_injections;
} sidechannel_stats_t;

// Function Prototypes

// Power Analysis Functions
iotstrike_error_t power_analysis_init(void);
void power_analysis_cleanup(void);
iotstrike_error_t collect_power_trace(power_sample_t *trace, uint32_t *trace_length, uint32_t max_length);
iotstrike_error_t perform_spa(const power_sample_t *trace, uint32_t trace_length, spa_result_t *result);
iotstrike_error_t perform_dpa(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                             uint8_t **plaintexts, uint8_t **ciphertexts, dpa_result_t *result);
iotstrike_error_t perform_cpa(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                             uint8_t **intermediate_values, cpa_result_t *result);
iotstrike_error_t build_power_templates(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                       uint8_t *known_keys, power_template_t *templates, uint32_t template_count);
iotstrike_error_t perform_template_attack(const power_template_t *templates, uint32_t template_count,
                                         const power_sample_t *target_trace, uint32_t trace_length,
                                         template_result_t *result);

// EM Analysis Functions
iotstrike_error_t em_analysis_init(em_analysis_context_t *ctx, em_analysis_config_t *config);
void em_analysis_cleanup(em_analysis_context_t *ctx);
iotstrike_error_t em_start_recording(em_analysis_context_t *ctx);
iotstrike_error_t em_stop_recording(em_analysis_context_t *ctx);
iotstrike_error_t em_collect_trace(em_analysis_context_t *ctx, em_sample_t *trace, uint32_t *trace_length);
iotstrike_error_t em_perform_analysis(em_analysis_context_t *ctx, em_analysis_type_t analysis_type);
iotstrike_error_t em_frequency_domain_analysis(em_analysis_context_t *ctx, double_complex *fft_result);

// Timing Analysis Functions
iotstrike_error_t timing_analysis_init(timing_analysis_context_t *ctx, timing_analysis_config_t *config);
void timing_analysis_cleanup(timing_analysis_context_t *ctx);
iotstrike_error_t timing_measure_operation(timing_analysis_context_t *ctx, void (*operation)(void), void *params);
iotstrike_error_t timing_statistical_analysis(timing_analysis_context_t *ctx);
iotstrike_error_t timing_correlation_analysis(timing_analysis_context_t *ctx, const uint8_t *secret_data);
iotstrike_error_t timing_detect_leakage(timing_analysis_context_t *ctx, bool *leakage_detected);

// Cache Analysis Functions
iotstrike_error_t cache_analysis_init(cache_analysis_context_t *ctx, cache_analysis_config_t *config);
void cache_analysis_cleanup(cache_analysis_context_t *ctx);
iotstrike_error_t cache_flush_reload_attack(cache_analysis_context_t *ctx, uint64_t target_address);
iotstrike_error_t cache_prime_probe_attack(cache_analysis_context_t *ctx, uint32_t cache_set);
iotstrike_error_t cache_evict_time_attack(cache_analysis_context_t *ctx, uint64_t target_address);
iotstrike_error_t cache_analyze_access_pattern(cache_analysis_context_t *ctx, uint64_t *recovered_data);

// Acoustic Analysis Functions
iotstrike_error_t acoustic_analysis_init(acoustic_analysis_context_t *ctx, acoustic_analysis_config_t *config);
void acoustic_analysis_cleanup(acoustic_analysis_context_t *ctx);
iotstrike_error_t acoustic_start_recording(acoustic_analysis_context_t *ctx);
iotstrike_error_t acoustic_stop_recording(acoustic_analysis_context_t *ctx);
iotstrike_error_t acoustic_perform_fft(acoustic_analysis_context_t *ctx, double_complex *fft_result);
iotstrike_error_t acoustic_analyze_keystroke_timing(acoustic_analysis_context_t *ctx, char *recovered_text);
iotstrike_error_t acoustic_analyze_cpu_operations(acoustic_analysis_context_t *ctx, uint8_t *recovered_data);

// Fault Injection Functions
iotstrike_error_t fault_injection_init(fault_injection_context_t *ctx, fault_injection_config_t *config);
void fault_injection_cleanup(fault_injection_context_t *ctx);
iotstrike_error_t fault_inject_voltage_glitch(fault_injection_context_t *ctx);
iotstrike_error_t fault_inject_clock_glitch(fault_injection_context_t *ctx);
iotstrike_error_t fault_inject_em_pulse(fault_injection_context_t *ctx);
iotstrike_error_t fault_inject_laser_pulse(fault_injection_context_t *ctx, uint64_t target_coordinate[2]);
iotstrike_error_t fault_analyze_response(fault_injection_context_t *ctx, bool *fault_successful);

// Template Attack Functions
iotstrike_error_t template_build_from_traces(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                           uint8_t *known_keys, power_template_t *templates);
iotstrike_error_t template_select_points_of_interest(power_sample_t **traces, uint32_t trace_count,
                                                   uint32_t trace_length, uint32_t *poi, uint32_t *poi_count);
iotstrike_error_t template_calculate_covariance(power_sample_t **traces, uint32_t trace_count,
                                               const double *mean_trace, double *covariance_matrix);
iotstrike_error_t template_attack_single_trace(const power_template_t *templates, uint32_t template_count,
                                              const power_sample_t *target_trace, uint8_t *recovered_key);

// Signal Processing Functions
iotstrike_error_t signal_apply_filter(double *signal, uint32_t signal_length, double cutoff_frequency, double sample_rate);
iotstrike_error_t signal_remove_dc_offset(double *signal, uint32_t signal_length);
iotstrike_error_t signal_normalize(double *signal, uint32_t signal_length);
iotstrike_error_t signal_calculate_snr(const double *signal, const double *noise, uint32_t length, double *snr);
iotstrike_error_t signal_cross_correlation(const double *signal1, const double *signal2, uint32_t length, double *correlation);
iotstrike_error_t signal_fft(const double *input, double_complex *output, uint32_t length);
iotstrike_error_t signal_ifft(const double_complex *input, double *output, uint32_t length);

// Statistical Analysis Functions
iotstrike_error_t stats_calculate_mean(const double *data, uint32_t length, double *mean);
iotstrike_error_t stats_calculate_variance(const double *data, uint32_t length, double mean, double *variance);
iotstrike_error_t stats_calculate_correlation(const double *x, const double *y, uint32_t length, double *correlation);
iotstrike_error_t stats_t_test(const double *sample1, uint32_t n1, const double *sample2, uint32_t n2, double *t_statistic);
iotstrike_error_t stats_chi_square_test(const uint32_t *observed, const uint32_t *expected, uint32_t bins, double *chi_square);
iotstrike_error_t stats_mutual_information(const double *x, const double *y, uint32_t length, double *mi);

// Leakage Assessment Functions
iotstrike_error_t leakage_test_first_order(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                          uint8_t **intermediate_values, bool *leakage_detected);
iotstrike_error_t leakage_test_second_order(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                           uint8_t **intermediate_values, bool *leakage_detected);
iotstrike_error_t leakage_test_higher_order(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                           uint8_t **intermediate_values, uint32_t order, bool *leakage_detected);
iotstrike_error_t leakage_welch_t_test(power_sample_t **group1, uint32_t count1, power_sample_t **group2, uint32_t count2,
                                      uint32_t trace_length, double *t_values);

// Countermeasure Analysis Functions
iotstrike_error_t analyze_masking_countermeasure(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                                uint8_t masking_order, bool *effective);
iotstrike_error_t analyze_hiding_countermeasure(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                               bool *effective);
iotstrike_error_t analyze_shuffling_countermeasure(power_sample_t **traces, uint32_t trace_count, uint32_t trace_length,
                                                  bool *effective);

// Hardware Interface Functions
iotstrike_error_t sidechannel_setup_oscilloscope(const char *device_path, uint32_t sample_rate, double voltage_range);
iotstrike_error_t sidechannel_setup_em_probe(uint8_t probe_id, double x, double y, double z);
iotstrike_error_t sidechannel_setup_acoustic_sensor(uint8_t sensor_id, double x, double y, double z);
iotstrike_error_t sidechannel_setup_fault_injector(fault_injection_type_t type, const char *device_path);
iotstrike_error_t sidechannel_trigger_acquisition(void);
iotstrike_error_t sidechannel_synchronize_measurement(void);

// Utility Functions
iotstrike_error_t sidechannel_get_statistics(sidechannel_stats_t *stats);
void sidechannel_stop_all_attacks(void);
const char *sidechannel_attack_type_to_string(sidechannel_attack_type_t type);
const char *power_analysis_type_to_string(power_analysis_type_t type);
const char *em_analysis_type_to_string(em_analysis_type_t type);
const char *timing_attack_type_to_string(timing_attack_type_t type);
const char *cache_attack_type_to_string(cache_attack_type_t type);
const char *fault_injection_type_to_string(fault_injection_type_t type);
const char *crypto_algorithm_to_string(crypto_algorithm_t algorithm);

// External declarations for Zig functions
extern iotstrike_error_t performSPA(const power_sample_t *trace_data, size_t trace_length, spa_result_t *result);
extern iotstrike_error_t performDPA(void *ctx, uint8_t byte_position, uint8_t key_byte_guess);
extern iotstrike_error_t performCPA(void *ctx, uint8_t byte_position);
extern iotstrike_error_t addTraceToDPA(void *ctx, const power_sample_t *trace, size_t trace_length,
                                      const uint8_t *plaintext, size_t plaintext_length,
                                      const uint8_t *ciphertext, size_t ciphertext_length);
extern iotstrike_error_t performTemplateAttack(const power_template_t *templates, size_t template_count,
                                              const power_sample_t *target_trace, size_t trace_length,
                                              uint8_t *result);
extern iotstrike_error_t calculateMutualInformation(const power_sample_t **traces, size_t trace_count,
                                                   size_t trace_length, const uint8_t *intermediate_values,
                                                   double *result);

// Timing analysis functions
extern uint64_t iotstrike_flush_and_reload(void *ctx, const void *target_addr);
extern uint8_t iotstrike_spectre_attack(uintptr_t target_addr, uint32_t iterations);
extern int32_t iotstrike_measure_timing(void *ctx, const void *addr, uint32_t operation_id);

#ifdef __cplusplus
}
#endif

#endif // IOTSTRIKE_SIDECHANNEL_H