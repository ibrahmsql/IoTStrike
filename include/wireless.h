/**
 * IoTStrike Hardware Security Framework
 * Wireless Protocol Exploitation Module Header
 * 
 * @file wireless.h
 * @author ibrahimsql
 * @version 1.0.0
 */

#ifndef IOTSTRIKE_WIRELESS_H
#define IOTSTRIKE_WIRELESS_H

#include "iotstrike.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants
#define MAX_WIFI_NETWORKS 64
#define MAX_BLE_SERVICES 16
#define MAX_ZIGBEE_NETWORKS 32
#define MAX_THREAD_NETWORKS 16
#define MAX_LORAWAN_FREQUENCIES 16
#define MAX_SSID_LENGTH 32
#define MAX_NETWORK_NAME_LENGTH 64
#define WPS_PIN_LENGTH 8
#define ZIGBEE_KEY_LENGTH 16
#define LORAWAN_KEY_LENGTH 16

// WiFi WPS Attack Types
typedef enum {
    WPS_ATTACK_PIN_BRUTEFORCE,
    WPS_ATTACK_PIXIE_DUST,
    WPS_ATTACK_NULL_PIN,
    WPS_ATTACK_REAVER
} wps_attack_type_t;

// Bluetooth LE Attack Types
typedef enum {
    BLE_ATTACK_GATT_FUZZING,
    BLE_ATTACK_PAIRING_BYPASS,
    BLE_ATTACK_MITM,
    BLE_ATTACK_JAMMING
} ble_attack_type_t;

// Zigbee Attack Types
typedef enum {
    ZIGBEE_ATTACK_KEY_EXTRACTION,
    ZIGBEE_ATTACK_NETWORK_INFILTRATION,
    ZIGBEE_ATTACK_REPLAY,
    ZIGBEE_ATTACK_JAMMING
} zigbee_attack_type_t;

// LoRaWAN Regions
typedef enum {
    LORAWAN_REGION_EU868,
    LORAWAN_REGION_US915,
    LORAWAN_REGION_AS923,
    LORAWAN_REGION_AU915,
    LORAWAN_REGION_CN470,
    LORAWAN_REGION_KR920,
    LORAWAN_REGION_IN865
} lorawan_region_t;

// Thread Network Types
typedef enum {
    THREAD_NETWORK_ROUTER,
    THREAD_NETWORK_END_DEVICE,
    THREAD_NETWORK_SLEEPY_END_DEVICE,
    THREAD_NETWORK_COMMISSIONER
} thread_device_type_t;

// WiFi Network Information
typedef struct {
    uint8_t bssid[6];
    char ssid[MAX_SSID_LENGTH];
    uint8_t channel;
    int8_t rssi;
    bool wps_enabled;
    bool wps_locked;
    uint32_t wps_pin;
    char encryption[16];
} wifi_network_info_t;

// WiFi WPS Attack Configuration
typedef struct {
    wps_attack_type_t attack_type;
    uint32_t start_pin;
    uint32_t end_pin;
    uint32_t delay_ms;
    uint32_t lockout_delay;
    bool use_common_pins;
    bool randomize_mac;
} wps_attack_config_t;

// WiFi WPS Context
typedef struct {
    char interface[16];
    uint8_t target_bssid[6];
    bool attack_active;
    uint32_t pins_tested;
    time_t start_time;
    pthread_mutex_t mutex;
} wifi_wps_context_t;

// Bluetooth LE Service
typedef struct {
    uint16_t uuid;
    uint16_t handle_start;
    uint16_t handle_end;
    char name[32];
} gatt_service_t;

// Bluetooth LE Device Information
typedef struct {
    uint8_t address[6];
    char name[32];
    int8_t rssi;
    bool connectable;
    bool scannable;
    uint16_t appearance;
} ble_device_info_t;

// GATT Fuzzing Configuration
typedef struct {
    uint32_t delay_ms;
    bool crash_detection;
    bool response_analysis;
    uint32_t max_payload_size;
    uint32_t iterations;
} gatt_fuzz_config_t;

// Bluetooth LE GATT Context
typedef struct {
    uint8_t target_address[6];
    bool connected;
    bool services_discovered;
    bool fuzzing_active;
    gatt_service_t services[MAX_BLE_SERVICES];
    int service_count;
    int crashes_found;
} ble_gatt_context_t;

// Zigbee Network Information
typedef struct {
    uint16_t pan_id;
    uint64_t extended_pan_id;
    uint8_t channel;
    bool permit_joining;
    char network_name[MAX_NETWORK_NAME_LENGTH];
    uint8_t network_key[ZIGBEE_KEY_LENGTH];
    int8_t rssi;
} zigbee_network_info_t;

// Zigbee Context
typedef struct {
    uint8_t channel;
    uint16_t pan_id;
    uint8_t network_key[ZIGBEE_KEY_LENGTH];
    bool network_joined;
    bool coordinator_found;
    zigbee_network_info_t networks[MAX_ZIGBEE_NETWORKS];
    int network_count;
} zigbee_context_t;

// LoRaWAN Frequency Plan
typedef struct {
    lorawan_region_t region;
    uint32_t frequencies[MAX_LORAWAN_FREQUENCIES];
    int frequency_count;
    uint8_t default_datarate;
    int8_t max_power;
} lorawan_frequency_plan_t;

// LoRaWAN Injection Configuration
typedef struct {
    uint32_t device_address;
    uint8_t network_session_key[LORAWAN_KEY_LENGTH];
    uint8_t app_session_key[LORAWAN_KEY_LENGTH];
    uint8_t *payload;
    size_t payload_length;
    uint32_t packet_count;
    uint32_t interval_ms;
} lorawan_injection_config_t;

// LoRaWAN Context
typedef struct {
    lorawan_region_t region;
    lorawan_frequency_plan_t frequency_plan;
    bool injection_active;
    uint32_t packets_sent;
    uint32_t packets_received;
} lorawan_context_t;

// Thread Network Information
typedef struct {
    uint16_t pan_id;
    uint8_t extended_pan_id[8];
    uint8_t channel;
    bool commissioner_active;
    char network_name[MAX_NETWORK_NAME_LENGTH];
    uint8_t master_key[16];
    thread_device_type_t device_type;
} thread_network_info_t;

// Thread Context
typedef struct {
    uint8_t channel;
    bool network_joined;
    bool commissioner_found;
    thread_network_info_t networks[MAX_THREAD_NETWORKS];
    int network_count;
    uint8_t network_key[16];
} thread_context_t;

// Matter/Thread Security Testing Configuration
typedef struct {
    bool test_commissioning;
    bool test_pairing;
    bool test_fabric_management;
    bool test_access_control;
    char setup_code[12];
    uint16_t discriminator;
} matter_test_config_t;

// Wireless Attack Statistics
typedef struct {
    uint32_t wifi_attacks_performed;
    uint32_t wifi_networks_cracked;
    uint32_t ble_devices_fuzzed;
    uint32_t ble_crashes_found;
    uint32_t zigbee_networks_infiltrated;
    uint32_t zigbee_keys_extracted;
    uint32_t lorawan_packets_injected;
    uint32_t lorawan_devices_spoofed;
    uint32_t thread_networks_attacked;
    uint32_t matter_devices_compromised;
} wireless_stats_t;

// Function Prototypes

// WiFi WPS Functions
iotstrike_error_t wifi_wps_init(wifi_wps_context_t *ctx, const char *interface, const char *target_bssid);
void wifi_wps_cleanup(wifi_wps_context_t *ctx);
iotstrike_error_t wifi_wps_scan_networks(wifi_wps_context_t *ctx, wifi_network_info_t *networks, int *count);
iotstrike_error_t wifi_wps_bruteforce(wifi_wps_context_t *ctx, wps_attack_config_t *config);
iotstrike_error_t wifi_wps_pixie_dust_attack(wifi_wps_context_t *ctx);
iotstrike_error_t wifi_wps_null_pin_attack(wifi_wps_context_t *ctx);

// Bluetooth LE Functions
iotstrike_error_t ble_gatt_fuzzer_init(ble_gatt_context_t *ctx, const char *target_address);
void ble_gatt_fuzzer_cleanup(ble_gatt_context_t *ctx);
iotstrike_error_t ble_scan_devices(ble_device_info_t *devices, int *count);
iotstrike_error_t ble_connect_device(ble_gatt_context_t *ctx);
iotstrike_error_t ble_gatt_discover_services(ble_gatt_context_t *ctx);
iotstrike_error_t ble_gatt_fuzz(ble_gatt_context_t *ctx, gatt_fuzz_config_t *config);
iotstrike_error_t ble_pairing_bypass_attack(ble_gatt_context_t *ctx);
iotstrike_error_t ble_mitm_attack(const char *target_address, const char *victim_address);

// Zigbee Functions
iotstrike_error_t zigbee_infiltration_init(zigbee_context_t *ctx, uint8_t channel);
void zigbee_infiltration_cleanup(zigbee_context_t *ctx);
iotstrike_error_t zigbee_scan_networks(zigbee_context_t *ctx);
iotstrike_error_t zigbee_join_network(zigbee_context_t *ctx, uint16_t pan_id);
iotstrike_error_t zigbee_extract_network_key(zigbee_context_t *ctx, uint16_t pan_id);
iotstrike_error_t zigbee_replay_attack(zigbee_context_t *ctx, const uint8_t *packet, size_t packet_len);
iotstrike_error_t zigbee_jamming_attack(uint8_t channel, uint32_t duration_ms);

// LoRaWAN Functions
iotstrike_error_t lorawan_injection_init(lorawan_context_t *ctx, lorawan_region_t region);
void lorawan_injection_cleanup(lorawan_context_t *ctx);
iotstrike_error_t lorawan_inject_packets(lorawan_context_t *ctx, lorawan_injection_config_t *config);
iotstrike_error_t lorawan_sniff_packets(lorawan_context_t *ctx, uint32_t frequency, uint32_t duration_ms);
iotstrike_error_t lorawan_replay_attack(lorawan_context_t *ctx, const uint8_t *packet, size_t packet_len);
iotstrike_error_t lorawan_jamming_attack(uint32_t frequency, uint32_t duration_ms);

// Thread Functions
iotstrike_error_t thread_attack_init(thread_context_t *ctx, uint8_t channel);
void thread_attack_cleanup(thread_context_t *ctx);
iotstrike_error_t thread_scan_networks(thread_context_t *ctx);
iotstrike_error_t thread_commissioning_attack(thread_context_t *ctx, const char *pskd);
iotstrike_error_t thread_network_infiltration(thread_context_t *ctx, uint16_t pan_id);
iotstrike_error_t thread_key_extraction(thread_context_t *ctx);

// Matter/Thread Security Testing
iotstrike_error_t matter_commissioning_test(matter_test_config_t *config);
iotstrike_error_t matter_pairing_test(matter_test_config_t *config);
iotstrike_error_t matter_fabric_test(matter_test_config_t *config);
iotstrike_error_t matter_access_control_test(matter_test_config_t *config);

// RF Protocol Analysis
iotstrike_error_t rf_protocol_analyze(uint32_t frequency, uint32_t bandwidth, uint32_t duration_ms);
iotstrike_error_t rf_signal_jamming(uint32_t frequency, uint32_t power_dbm, uint32_t duration_ms);
iotstrike_error_t rf_replay_attack(uint32_t frequency, const uint8_t *signal_data, size_t data_len);

// General Wireless Functions
iotstrike_error_t wireless_get_statistics(wireless_stats_t *stats);
void wireless_stop_all_attacks(void);
iotstrike_error_t wireless_set_interface(const char *interface);
iotstrike_error_t wireless_get_interface_info(char *interface, size_t interface_len);

// Utility Functions
const char *wireless_error_to_string(iotstrike_error_t error);
const char *wps_attack_type_to_string(wps_attack_type_t type);
const char *ble_attack_type_to_string(ble_attack_type_t type);
const char *zigbee_attack_type_to_string(zigbee_attack_type_t type);
const char *lorawan_region_to_string(lorawan_region_t region);
const char *thread_device_type_to_string(thread_device_type_t type);

#ifdef __cplusplus
}
#endif

#endif // IOTSTRIKE_WIRELESS_H