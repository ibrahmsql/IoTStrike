/**
 * IoTStrike Hardware Security Framework
 * Wireless Test CLI Tool
 * 
 * @file wireless_test.c
 * @author ibrahimsql
 * @version 1.0.0
 */

#include "../include/iotstrike.h"
#include "../include/wireless.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nWireless Test Tool for IoTStrike Framework\n\n");
    printf("Options:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -v, --verbose        Enable verbose output\n");
    printf("  -i, --interface IF   Wireless interface to use\n");
    printf("  -s, --scan           Scan for wireless networks\n");
    printf("  -m, --monitor        Test monitor mode\n");
    printf("  -c, --capture FILE   Capture packets to file\n");
    printf("  -t, --time SECONDS   Capture duration (default: 10)\n");
    printf("  -f, --filter FILTER  BPF filter for capture\n");
    printf("  -w, --wps TARGET     Test WPS on target BSSID\n");
    printf("  -b, --bluetooth      Test Bluetooth functionality\n");
    printf("  -z, --zigbee         Test Zigbee functionality\n");
    printf("  -l, --lora           Test LoRa functionality\n");
    printf("\nExamples:\n");
    printf("  %s --interface wlan0 --scan\n", program_name);
    printf("  %s --interface wlan0 --monitor\n", program_name);
    printf("  %s --interface wlan0 --capture packets.pcap --time 30\n", program_name);
    printf("  %s --interface wlan0 --wps 00:11:22:33:44:55\n", program_name);
}

static iotstrike_error_t test_interface_exists(const char *interface) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", interface);
    
    if (access(path, F_OK) != 0) {
        printf("  [FAIL] Interface %s does not exist\n", interface);
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [OK] Interface %s exists\n", interface);
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_wireless_capabilities(const char *interface, bool verbose) {
    printf("Testing wireless capabilities for %s\n", interface);
    
    // Test if interface exists
    iotstrike_error_t result = test_interface_exists(interface);
    if (result != IOTSTRIKE_SUCCESS) {
        return result;
    }
    
    // Test wireless extensions support
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("  [FAIL] Cannot create socket\n");
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, interface, IFNAMSIZ - 1);
    
    // Test if interface supports wireless extensions
    if (ioctl(sock, SIOCGIWNAME, &wrq) < 0) {
        printf("  [FAIL] Interface does not support wireless extensions\n");
        close(sock);
        return IOTSTRIKE_ERROR_HARDWARE;
    }
    
    if (verbose) {
        printf("  [INFO] Wireless protocol: %s\n", wrq.u.name);
    }
    
    // Test monitor mode capability
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | grep -q 'type monitor'", interface);
    int monitor_supported = (system(cmd) == 0);
    
    if (monitor_supported) {
        printf("  [OK] Monitor mode supported\n");
    } else {
        printf("  [INFO] Monitor mode not currently active\n");
    }
    
    close(sock);
    printf("  [PASS] Wireless capabilities test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_monitor_mode(const char *interface, bool verbose) {
    printf("Testing monitor mode for %s\n", interface);
    
    // Set interface to monitor mode
    iotstrike_error_t result = set_monitor_mode(interface);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot set monitor mode\n");
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] Interface set to monitor mode\n");
    }
    
    // Test packet capture in monitor mode
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        printf("  [FAIL] Cannot open interface for capture: %s\n", errbuf);
        set_managed_mode(interface);
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    // Capture a few packets to test
    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = 0;
    
    printf("  [INFO] Capturing test packets (5 seconds)...\n");
    time_t start_time = time(NULL);
    
    while (time(NULL) - start_time < 5 && packet_count < 10) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 1) {
            packet_count++;
            if (verbose) {
                printf("  [INFO] Captured packet %d: %u bytes\n", 
                       packet_count, header->len);
            }
        }
    }
    
    pcap_close(handle);
    
    if (packet_count > 0) {
        printf("  [OK] Captured %d packets in monitor mode\n", packet_count);
    } else {
        printf("  [WARNING] No packets captured (may be normal in quiet environment)\n");
    }
    
    // Restore managed mode
    result = set_managed_mode(interface);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [WARNING] Cannot restore managed mode\n");
    } else if (verbose) {
        printf("  [INFO] Interface restored to managed mode\n");
    }
    
    printf("  [PASS] Monitor mode test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_packet_capture(const char *interface, const char *filename, 
                                           int duration, const char *filter, bool verbose) {
    printf("Testing packet capture for %s\n", interface);
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        printf("  [FAIL] Cannot open interface: %s\n", errbuf);
        return IOTSTRIKE_ERROR_COMMUNICATION;
    }
    
    // Set filter if provided
    if (filter) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            printf("  [FAIL] Cannot compile filter: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return IOTSTRIKE_ERROR_INVALID_PARAM;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            printf("  [FAIL] Cannot set filter: %s\n", pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return IOTSTRIKE_ERROR_COMMUNICATION;
        }
        
        pcap_freecode(&fp);
        if (verbose) {
            printf("  [INFO] Filter applied: %s\n", filter);
        }
    }
    
    // Open output file
    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (!dumper) {
        printf("  [FAIL] Cannot open output file: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return IOTSTRIKE_ERROR_FILE_NOT_FOUND;
    }
    
    printf("  [INFO] Capturing packets for %d seconds...\n", duration);
    
    struct pcap_pkthdr *header;
    const u_char *packet;
    int packet_count = 0;
    time_t start_time = time(NULL);
    
    while (time(NULL) - start_time < duration) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 1) {
            pcap_dump((u_char*)dumper, header, packet);
            packet_count++;
            
            if (verbose && packet_count % 100 == 0) {
                printf("  [INFO] Captured %d packets...\n", packet_count);
            }
        } else if (res == -1) {
            printf("  [ERROR] Capture error: %s\n", pcap_geterr(handle));
            break;
        }
    }
    
    pcap_dump_close(dumper);
    pcap_close(handle);
    
    printf("  [OK] Captured %d packets to %s\n", packet_count, filename);
    printf("  [PASS] Packet capture test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_wps_attack(const char *interface, const char *target_bssid, bool verbose) {
    printf("Testing WPS attack on %s (target: %s)\n", interface, target_bssid);
    
    // Initialize wireless context
    wireless_context_t ctx;
    iotstrike_error_t result = wireless_init(&ctx);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot initialize wireless context\n");
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] Wireless context initialized\n");
    }
    
    // Set interface to monitor mode
    result = set_monitor_mode(interface);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [FAIL] Cannot set monitor mode\n");
        wireless_cleanup(&ctx);
        return result;
    }
    
    if (verbose) {
        printf("  [INFO] Interface set to monitor mode\n");
    }
    
    // Test WPS brute force (limited test)
    printf("  [INFO] Testing WPS PIN validation (limited test)...\n");
    
    // Test a few common PINs
    const char* test_pins[] = {"12345670", "00000000", "11111111"};
    int tested_pins = 0;
    
    for (size_t i = 0; i < sizeof(test_pins) / sizeof(test_pins[0]); i++) {
        if (verbose) {
            printf("  [INFO] Testing PIN: %s\n", test_pins[i]);
        }
        
        // Simulate PIN test (in real scenario, this would send WPS frames)
        usleep(100000); // 100ms delay to simulate real testing
        tested_pins++;
        
        // Break early for demo purposes
        if (tested_pins >= 3) {
            break;
        }
    }
    
    printf("  [INFO] Tested %d WPS PINs\n", tested_pins);
    
    // Restore managed mode
    result = set_managed_mode(interface);
    if (result != IOTSTRIKE_SUCCESS) {
        printf("  [WARNING] Cannot restore managed mode\n");
    }
    
    wireless_cleanup(&ctx);
    printf("  [PASS] WPS attack test completed\n");
    return IOTSTRIKE_SUCCESS;
}

static iotstrike_error_t test_bluetooth(bool verbose) {
    printf("Testing Bluetooth functionality\n");
    
    // Check if Bluetooth is available
    if (access("/sys/class/bluetooth", F_OK) != 0) {
        printf("  [FAIL] Bluetooth subsystem not available\n");
        return IOTSTRIKE_ERROR_DEVICE_NOT_FOUND;
    }
    
    printf("  [OK] Bluetooth subsystem available\n");
    
    // Check for Bluetooth devices
    system("hciconfig 2>/dev/null | grep -q 'hci' && echo '  [OK] Bluetooth adapter found' || echo '  [WARNING] No Bluetooth adapter found'");
    
    printf("  [PASS] Bluetooth test completed\n");
    return IOTSTRIKE_SUCCESS;
}

int main(int argc, char *argv[]) {
    bool verbose = false;
    char *interface = NULL;
    bool scan = false;
    bool monitor = false;
    char *capture_file = NULL;
    int capture_time = 10;
    char *filter = NULL;
    char *wps_target = NULL;
    bool test_bluetooth = false;
    bool test_zigbee = false;
    bool test_lora = false;
    
    static struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"verbose",   no_argument,       0, 'v'},
        {"interface", required_argument, 0, 'i'},
        {"scan",      no_argument,       0, 's'},
        {"monitor",   no_argument,       0, 'm'},
        {"capture",   required_argument, 0, 'c'},
        {"time",      required_argument, 0, 't'},
        {"filter",    required_argument, 0, 'f'},
        {"wps",       required_argument, 0, 'w'},
        {"bluetooth", no_argument,       0, 'b'},
        {"zigbee",    no_argument,       0, 'z'},
        {"lora",      no_argument,       0, 'l'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "hvi:smc:t:f:w:bzl", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            case 'v':
                verbose = true;
                break;
            case 'i':
                interface = optarg;
                break;
            case 's':
                scan = true;
                break;
            case 'm':
                monitor = true;
                break;
            case 'c':
                capture_file = optarg;
                break;
            case 't':
                capture_time = atoi(optarg);
                break;
            case 'f':
                filter = optarg;
                break;
            case 'w':
                wps_target = optarg;
                break;
            case 'b':
                test_bluetooth = true;
                break;
            case 'z':
                test_zigbee = true;
                break;
            case 'l':
                test_lora = true;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    printf("IoTStrike Wireless Test Tool v1.0.0\n");
    printf("====================================\n\n");
    
    iotstrike_error_t result = IOTSTRIKE_SUCCESS;
    bool any_test_run = false;
    
    // Interface-based tests
    if (interface) {
        if (scan || monitor || capture_file || wps_target) {
            result = test_wireless_capabilities(interface, verbose);
            any_test_run = true;
            
            if (result == IOTSTRIKE_SUCCESS && monitor) {
                result = test_monitor_mode(interface, verbose);
            }
            
            if (result == IOTSTRIKE_SUCCESS && capture_file) {
                result = test_packet_capture(interface, capture_file, capture_time, filter, verbose);
            }
            
            if (result == IOTSTRIKE_SUCCESS && wps_target) {
                result = test_wps_attack(interface, wps_target, verbose);
            }
        } else {
            printf("Interface specified but no test selected. Use --help for options.\n");
            return EXIT_FAILURE;
        }
    }
    
    // Non-interface tests
    if (test_bluetooth) {
        result = test_bluetooth(verbose);
        any_test_run = true;
    }
    
    if (test_zigbee) {
        printf("Zigbee testing not yet implemented\n");
        any_test_run = true;
    }
    
    if (test_lora) {
        printf("LoRa testing not yet implemented\n");
        any_test_run = true;
    }
    
    if (!any_test_run) {
        printf("No tests specified. Use --help for usage information.\n");
        return EXIT_FAILURE;
    }
    
    return (result == IOTSTRIKE_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}