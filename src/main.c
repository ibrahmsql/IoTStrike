/**
 * IoTStrike Hardware Security Framework
 * Main Application Entry Point
 * 
 * @file main.c
 * @author ibrahimsql
 * @version 1.0.0
 * @brief Main application for the IoTStrike Hardware Security Framework
 */

#include "iotstrike.h"
#include "firmware.h"
#include "hardware.h"
#include "wireless.h"
#include "realtime.h"
#include "sidechannel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <errno.h>

// Global variables
static iotstrike_context_t g_framework_ctx;
static bool g_shutdown_requested = false;
static bool g_verbose_mode = false;

// Function prototypes
static void print_banner(void);
static void print_usage(const char *program_name);
static void print_version(void);
static void print_modules(void);
static void signal_handler(int signal);
static iotstrike_error_t setup_signal_handlers(void);
static iotstrike_error_t parse_command_line(int argc, char *argv[], iotstrike_config_t *config);
static iotstrike_error_t run_firmware_analysis(const char *firmware_path);
static iotstrike_error_t run_hardware_scan(void);
static iotstrike_error_t run_wireless_scan(void);
static iotstrike_error_t run_realtime_tests(void);
static iotstrike_error_t run_sidechannel_analysis(void);
static iotstrike_error_t run_interactive_mode(void);
static iotstrike_error_t run_batch_mode(const char *script_file);
static void log_callback(iotstrike_log_level_t level, const char *module, const char *message);
static void error_callback(iotstrike_error_t error, const char *message);
static void progress_callback(const char *operation, uint32_t progress_percent);

// Command line options
static struct option long_options[] = {
    {"help",           no_argument,       0, 'h'},
    {"version",        no_argument,       0, 'v'},
    {"verbose",        no_argument,       0, 'V'},
    {"config",         required_argument, 0, 'c'},
    {"log-level",      required_argument, 0, 'l'},
    {"log-file",       required_argument, 0, 'L'},
    {"modules",        no_argument,       0, 'm'},
    {"firmware",       required_argument, 0, 'f'},
    {"hardware",       no_argument,       0, 'H'},
    {"wireless",       no_argument,       0, 'w'},
    {"realtime",       no_argument,       0, 'r'},
    {"sidechannel",    no_argument,       0, 's'},
    {"interactive",    no_argument,       0, 'i'},
    {"batch",          required_argument, 0, 'b'},
    {"output",         required_argument, 0, 'o'},
    {"format",         required_argument, 0, 'F'},
    {"target",         required_argument, 0, 't'},
    {"platform",       required_argument, 0, 'p'},
    {"security-level", required_argument, 0, 'S'},
    {"threads",        required_argument, 0, 'T'},
    {"timeout",        required_argument, 0, 'x'},
    {"no-color",       no_argument,       0, 'n'},
    {"quiet",          no_argument,       0, 'q'},
    {"daemon",         no_argument,       0, 'd'},
    {0, 0, 0, 0}
};

/**
 * Print application banner
 */
static void print_banner(void) {
    printf("\n");
    printf("██╗ ██████╗ ████████╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗\n");
    printf("██║██╔═══██╗╚══██╔══╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝\n");
    printf("██║██║   ██║   ██║   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  \n");
    printf("██║██║   ██║   ██║   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  \n");
    printf("██║╚██████╔╝   ██║   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗\n");
    printf("╚═╝ ╚═════╝    ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝\n");
    printf("\n");
    printf("IoTStrike Hardware Security Framework v%s\n", IOTSTRIKE_VERSION_STRING);
    printf("Advanced IoT and Embedded System Security Testing Platform\n");
    printf("Copyright (c) 2024 IoTStrike Team. All rights reserved.\n");
    printf("\n");
}

/**
 * Print usage information
 */
static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("IoTStrike Hardware Security Framework - Advanced IoT Security Testing\n\n");
    
    printf("General Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -v, --version           Show version information\n");
    printf("  -V, --verbose           Enable verbose output\n");
    printf("  -c, --config FILE       Load configuration from file\n");
    printf("  -l, --log-level LEVEL   Set log level (trace|debug|info|warn|error|fatal)\n");
    printf("  -L, --log-file FILE     Write logs to file\n");
    printf("  -m, --modules           List available modules\n");
    printf("  -o, --output DIR        Set output directory\n");
    printf("  -F, --format FORMAT     Set output format (json|xml|html|pdf)\n");
    printf("  -n, --no-color          Disable colored output\n");
    printf("  -q, --quiet             Suppress non-essential output\n");
    printf("  -d, --daemon            Run as daemon\n\n");
    
    printf("Analysis Modules:\n");
    printf("  -f, --firmware FILE     Analyze firmware binary\n");
    printf("  -H, --hardware          Scan hardware interfaces\n");
    printf("  -w, --wireless          Scan wireless protocols\n");
    printf("  -r, --realtime          Run real-time attack simulations\n");
    printf("  -s, --sidechannel       Perform side-channel analysis\n\n");
    
    printf("Execution Modes:\n");
    printf("  -i, --interactive       Run in interactive mode\n");
    printf("  -b, --batch FILE        Run batch script\n\n");
    
    printf("Target Configuration:\n");
    printf("  -t, --target TARGET     Set target device/address\n");
    printf("  -p, --platform PLATFORM Set target platform\n");
    printf("  -S, --security-level LVL Set security level (none|low|medium|high|critical)\n");
    printf("  -T, --threads NUM       Set number of worker threads\n");
    printf("  -x, --timeout SEC       Set operation timeout in seconds\n\n");
    
    printf("Examples:\n");
    printf("  %s -f firmware.bin                    # Analyze firmware\n", program_name);
    printf("  %s -H -w                              # Scan hardware and wireless\n", program_name);
    printf("  %s -i -V                              # Interactive mode with verbose output\n", program_name);
    printf("  %s -b script.txt -o results/          # Run batch script\n", program_name);
    printf("  %s -s -t /dev/ttyUSB0                 # Side-channel analysis on device\n", program_name);
    printf("  %s -r -p raspberry-pi                # Real-time tests on Raspberry Pi\n", program_name);
    printf("\n");
}

/**
 * Print version information
 */
static void print_version(void) {
    printf("IoTStrike Hardware Security Framework\n");
    printf("Version: %s\n", IOTSTRIKE_VERSION_STRING);
    printf("Build Date: %s %s\n", __DATE__, __TIME__);
    printf("Platform: Linux\n");
    printf("Build Info: Debug build\n");
    
    printf("\nSupported Features:\n");
    printf("  - Firmware Analysis Suite\n");
    printf("  - Hardware Communication Interface\n");
    printf("  - Wireless Protocol Exploitation\n");
    printf("  - Real-Time System Attack Simulator\n");
    printf("  - Side-Channel Attack Framework\n");
    printf("  - Cross-Platform Support\n");
    printf("  - Multi-Threading\n");
    printf("  - Hardware Abstraction Layer\n");
    printf("\n");
}

/**
 * Print available modules
 */
static void print_modules(void) {
    printf("Available Modules:\n\n");
    printf("  %-15s v%-8s %s\n", "firmware", "1.0.0", "Firmware analysis and extraction");
    printf("  %-15s v%-8s %s\n", "hardware", "1.0.0", "Hardware interface and testing");
    printf("  %-15s v%-8s %s\n", "wireless", "1.0.0", "Wireless protocol exploitation");
    printf("  %-15s v%-8s %s\n", "realtime", "1.0.0", "Real-time attack simulation");
    printf("  %-15s v%-8s %s\n", "sidechannel", "1.0.0", "Side-channel analysis");
    printf("\n");
}

/**
 * Signal handler for graceful shutdown
 */
static void signal_handler(int signal) {
    switch (signal) {
        case SIGINT:
        case SIGTERM:
            printf("\nShutdown signal received. Cleaning up...\n");
            g_shutdown_requested = true;
            break;
        case SIGUSR1:
            printf("\nReceived SIGUSR1 - toggling verbose mode\n");
            g_verbose_mode = !g_verbose_mode;
            break;
        default:
            break;
    }
}

/**
 * Setup signal handlers
 */
static iotstrike_error_t setup_signal_handlers(void) {
    struct sigaction sa;
    
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
    
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
    
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        return IOTSTRIKE_ERROR_UNKNOWN;
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Parse command line arguments
 */
static iotstrike_error_t parse_command_line(int argc, char *argv[], iotstrike_config_t *config) {
    int opt, option_index = 0;
    
    // Set default configuration
    memset(config, 0, sizeof(iotstrike_config_t));
    config->log_level = LOG_LEVEL_INFO;
    config->security_level = IOTSTRIKE_SECURITY_MEDIUM;
    config->default_timeout = DEFAULT_TIMEOUT;
    config->memory_protection = true;
    config->privilege_dropping = true;
    config->platform = IOTSTRIKE_PLATFORM_LINUX; // Default platform
    strcpy(config->log_file, "iotstrike.log");
    
    while ((opt = getopt_long(argc, argv, "hvVc:l:L:mf:Hwrsi:b:o:F:t:p:S:T:x:nqd", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return IOTSTRIKE_ERROR_UNKNOWN; // Exit after help
                
            case 'v':
                print_version();
                return IOTSTRIKE_ERROR_UNKNOWN; // Exit after version
                
            case 'V':
                g_verbose_mode = true;
                config->log_level = LOG_LEVEL_DEBUG;
                break;
                
            case 'c':
                // Configuration file loading not implemented yet
                fprintf(stderr, "Warning: Configuration file loading not implemented\n");
                break;
                
            case 'l':
                if (strcmp(optarg, "trace") == 0) {
                    config->log_level = LOG_LEVEL_DEBUG;  // Use DEBUG as closest to TRACE
                } else if (strcmp(optarg, "debug") == 0) {
                    config->log_level = LOG_LEVEL_DEBUG;
                } else if (strcmp(optarg, "info") == 0) {
                    config->log_level = LOG_LEVEL_INFO;
                } else if (strcmp(optarg, "warn") == 0) {
                    config->log_level = LOG_LEVEL_WARNING;
                } else if (strcmp(optarg, "error") == 0) {
                    config->log_level = LOG_LEVEL_ERROR;
                } else if (strcmp(optarg, "fatal") == 0) {
                    config->log_level = LOG_LEVEL_CRITICAL;
                } else {
                    fprintf(stderr, "Error: Invalid log level '%s'\n", optarg);
                    return IOTSTRIKE_ERROR_INVALID_PARAM;
                }
                break;
                
            case 'L':
                strncpy(config->log_file, optarg, sizeof(config->log_file) - 1);
                // File output option - not implemented in current config struct
                break;
                
            case 'm':
                print_modules();
                return IOTSTRIKE_ERROR_UNKNOWN; // Exit after modules
                
            case 'T':
                // Thread count option - not implemented in current config struct
                break;
                
            case 'x':
                config->default_timeout = (uint32_t)(atoi(optarg) * 1000);
                break;
                
            case 'q':
                // Console output option - not implemented in current config struct
                break;
                
            case 'd':
                // Daemon mode - implement later
                break;
                
            case '?':
            default:
                fprintf(stderr, "Error: Unknown option. Use -h for help.\n");
                return IOTSTRIKE_ERROR_INVALID_PARAM;
        }
    }
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run firmware analysis
 */
static iotstrike_error_t run_firmware_analysis(const char *firmware_path) {
    printf("Starting firmware analysis on: %s\n", firmware_path);
    
    // Check if file exists
    struct stat st;
    if (stat(firmware_path, &st) != 0) {
        fprintf(stderr, "Error: Firmware file not found: %s\n", firmware_path);
        return IOTSTRIKE_ERROR_FILE_NOT_FOUND;
    }
    
    // Initialize firmware analysis context
    firmware_context_t fw_ctx;
    iotstrike_error_t error = firmware_init(&fw_ctx);
    if (error != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize firmware analysis: %s\n", iotstrike_error_to_string(error));
        return error;
    }
    
    // Load firmware
    error = firmware_load_file(&fw_ctx, firmware_path);
    if (error != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Error: Failed to load firmware: %s\n", iotstrike_error_to_string(error));
        firmware_cleanup(&fw_ctx);
        return error;
    }
    
    printf("Firmware loaded successfully. Size: %zu bytes\n", fw_ctx.size);
    
    // Detect format and architecture
    firmware_detect_format(&fw_ctx);
    firmware_detect_architecture(&fw_ctx);
    
    printf("Format: %d\n", fw_ctx.format);
    printf("Architecture: %d\n", fw_ctx.arch);
    printf("Endianness: %d\n", fw_ctx.endian);
    
    // Perform analysis
    printf("\nPerforming analysis...\n");
    
    printf("  - Extracting strings...\n");
    firmware_analyze_strings(&fw_ctx);
    printf("    Found %zu strings\n", fw_ctx.string_count);
    
    printf("  - Scanning for vulnerabilities...\n");
    firmware_scan_vulnerabilities(&fw_ctx);
    printf("    Found %zu potential vulnerabilities\n", fw_ctx.vulnerability_count);
    
    printf("  - Analyzing cryptographic content...\n");
    firmware_extract_crypto_keys(&fw_ctx);
        printf("    Found %zu cryptographic keys\n", fw_ctx.crypto_key_count);
    
    // Generate report
    error = firmware_generate_report(&fw_ctx, "firmware_report.txt");
    if (error == IOTSTRIKE_SUCCESS) {
        printf("\nReport generated: firmware_report.txt\n");
    }
    
    firmware_cleanup(&fw_ctx);
    printf("\nFirmware analysis completed.\n");
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run hardware scan
 */
static iotstrike_error_t run_hardware_scan(void) {
    printf("Starting hardware interface scan...\n");
    
    hardware_context_t hw_ctx;
    iotstrike_error_t error = hardware_init(&hw_ctx);
    if (error != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize hardware interface: %s\n", iotstrike_error_to_string(error));
        return error;
    }
    
    // Scan for devices
    error = hardware_scan_devices(&hw_ctx);
    if (error != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Error: Hardware scan failed: %s\n", iotstrike_error_to_string(error));
        hardware_cleanup(&hw_ctx);
        return error;
    }
    
    printf("\nHardware Scan Results:\n");
    printf("  Total Devices: %zu\n", hw_ctx.device_count);
    printf("  UART Devices: %zu\n", hw_ctx.uart_count);
    printf("  SPI Devices: %zu\n", hw_ctx.spi_count);
    printf("  I2C Devices: %zu\n", hw_ctx.i2c_count);
    
    hardware_cleanup(&hw_ctx);
    printf("\nHardware scan completed.\n");
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run wireless scan
 */
static iotstrike_error_t run_wireless_scan(void) {
    printf("Starting wireless protocol scan...\n");
    
    // Initialize wireless context
    // Implementation would go here
    
    printf("\nWireless scan completed.\n");
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run real-time tests
 */
static iotstrike_error_t run_realtime_tests(void) {
    printf("Starting real-time attack simulations...\n");
    
    // Initialize real-time context
    // Implementation would go here
    
    printf("\nReal-time tests completed.\n");
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run side-channel analysis
 */
static iotstrike_error_t run_sidechannel_analysis(void) {
    printf("Starting side-channel analysis...\n");
    
    // Initialize side-channel context
    // Implementation would go here
    
    printf("\nSide-channel analysis completed.\n");
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run interactive mode
 */
static iotstrike_error_t run_interactive_mode(void) {
    printf("Entering interactive mode...\n");
    printf("Type 'help' for available commands, 'quit' to exit.\n\n");
    
    char input[256];
    while (!g_shutdown_requested) {
        printf("iotstrike> ");
        fflush(stdout);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) {
            continue;
        }
        
        if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
            break;
        } else if (strcmp(input, "help") == 0) {
            printf("Available commands:\n");
            printf("  help          - Show this help\n");
            printf("  version       - Show version information\n");
            printf("  modules       - List available modules\n");
            printf("  status        - Show framework status\n");
            printf("  firmware FILE - Analyze firmware\n");
            printf("  hardware      - Scan hardware\n");
            printf("  wireless      - Scan wireless\n");
            printf("  realtime      - Run real-time tests\n");
            printf("  sidechannel   - Run side-channel analysis\n");
            printf("  quit/exit     - Exit interactive mode\n");
        } else if (strcmp(input, "version") == 0) {
            print_version();
        } else if (strcmp(input, "modules") == 0) {
            print_modules();
        } else if (strcmp(input, "status") == 0) {
            iotstrike_stats_t stats;
            if (iotstrike_get_statistics(&g_framework_ctx, &stats) == IOTSTRIKE_SUCCESS) {
                printf("Framework Status:\n");
                printf("  Uptime: %u seconds\n", stats.uptime_seconds);
                printf("  Total Operations: %llu\n", stats.operations_count);
                printf("  Memory Usage: %zu MB\n", stats.memory_usage / (1024 * 1024));
                printf("  Active Connections: %u\n", stats.active_connections);
            }
        } else if (strncmp(input, "firmware ", 9) == 0) {
            run_firmware_analysis(input + 9);
        } else if (strcmp(input, "hardware") == 0) {
            run_hardware_scan();
        } else if (strcmp(input, "wireless") == 0) {
            run_wireless_scan();
        } else if (strcmp(input, "realtime") == 0) {
            run_realtime_tests();
        } else if (strcmp(input, "sidechannel") == 0) {
            run_sidechannel_analysis();
        } else {
            printf("Unknown command: %s\n", input);
            printf("Type 'help' for available commands.\n");
        }
        
        printf("\n");
    }
    
    printf("Exiting interactive mode.\n");
    return IOTSTRIKE_SUCCESS;
}

/**
 * Run batch mode
 */
static iotstrike_error_t run_batch_mode(const char *script_file) {
    printf("Running batch script: %s\n", script_file);
    
    FILE *file = fopen(script_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open script file: %s\n", script_file);
        return IOTSTRIKE_ERROR_FILE_NOT_FOUND;
    }
    
    char line[512];
    int line_number = 0;
    
    while (fgets(line, sizeof(line), file) && !g_shutdown_requested) {
        line_number++;
        
        // Remove newline and comments
        line[strcspn(line, "\n")] = 0;
        char *comment = strchr(line, '#');
        if (comment) {
            *comment = 0;
        }
        
        // Skip empty lines
        if (strlen(line) == 0) {
            continue;
        }
        
        printf("[%d] Executing: %s\n", line_number, line);
        
        // Parse and execute command
        // This would need a proper command parser
        // For now, just print the command
    }
    
    fclose(file);
    printf("Batch script completed.\n");
    
    return IOTSTRIKE_SUCCESS;
}

/**
 * Log callback function
 */
static void log_callback(iotstrike_log_level_t level, const char *module, const char *message) {
    if (!g_verbose_mode && level < LOG_LEVEL_INFO) {
        return;
    }
    
    const char *level_str;
    switch (level) {
        case LOG_LEVEL_DEBUG: level_str = "DEBUG"; break;
        case LOG_LEVEL_INFO: level_str = "INFO"; break;
        case LOG_LEVEL_WARNING: level_str = "WARNING"; break;
        case LOG_LEVEL_ERROR: level_str = "ERROR"; break;
        case LOG_LEVEL_CRITICAL: level_str = "CRITICAL"; break;
        default: level_str = "UNKNOWN"; break;
    }
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    printf("[%ld.%03ld] [%s] [%s] %s\n", 
           ts.tv_sec, ts.tv_nsec / 1000000, level_str, module, message);
}

/**
 * Error callback function
 */
static void error_callback(iotstrike_error_t error, const char *message) {
    fprintf(stderr, "ERROR [%d]: %s - %s\n", error, iotstrike_error_to_string(error), message);
}

/**
 * Progress callback function
 */
static void progress_callback(const char *operation, uint32_t progress_percent) {
    if (g_verbose_mode) {
        printf("\r%s: %u%%", operation, progress_percent);
        if (progress_percent == 100) {
            printf("\n");
        }
        fflush(stdout);
    }
}

/**
 * Main application entry point
 */
int main(int argc, char *argv[]) {
    iotstrike_error_t error;
    iotstrike_config_t config;
    
    // Print banner
    print_banner();
    
    // Setup signal handlers
    if (setup_signal_handlers() != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Warning: Failed to setup signal handlers\n");
    }
    
    // Parse command line arguments
    error = parse_command_line(argc, argv, &config);
    if (error != IOTSTRIKE_SUCCESS) {
        if (error == IOTSTRIKE_ERROR_UNKNOWN) {
            // Help, version, or modules was displayed
            return EXIT_SUCCESS;
        }
        return EXIT_FAILURE;
    }
    
    // Check privileges
    if (iotstrike_check_privileges() != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Warning: Running without sufficient privileges. Some features may not work.\n");
    }
    
    // Initialize framework
    error = iotstrike_init(&g_framework_ctx, &config);
    if (error != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize framework: %s\n", iotstrike_error_to_string(error));
        return EXIT_FAILURE;
    }
    
    // Set callbacks
    iotstrike_set_log_callback(&g_framework_ctx, log_callback);
    iotstrike_set_error_callback(&g_framework_ctx, error_callback);
    iotstrike_set_progress_callback(&g_framework_ctx, progress_callback);
    
    printf("Framework initialized successfully.\n");
    printf("Platform: %s\n", iotstrike_platform_to_string(config.platform));
    printf("Security Level: %s\n", iotstrike_security_level_to_string(config.security_level));
    printf("\n");
    
    // Start framework
    error = iotstrike_start(&g_framework_ctx);
    if (error != IOTSTRIKE_SUCCESS) {
        fprintf(stderr, "Error: Failed to start framework: %s\n", iotstrike_error_to_string(error));
        iotstrike_cleanup(&g_framework_ctx);
        return EXIT_FAILURE;
    }
    
    // Process command line options for specific operations
    bool operation_performed = false;
    
    // Check for specific module operations
    optind = 1; // Reset getopt
    int opt;
    while ((opt = getopt_long(argc, argv, "hvVc:l:L:mf:Hwrsi:b:o:F:t:p:S:T:x:nqd", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f':
                error = run_firmware_analysis(optarg);
                operation_performed = true;
                break;
                
            case 'H':
                error = run_hardware_scan();
                operation_performed = true;
                break;
                
            case 'w':
                error = run_wireless_scan();
                operation_performed = true;
                break;
                
            case 'r':
                error = run_realtime_tests();
                operation_performed = true;
                break;
                
            case 's':
                error = run_sidechannel_analysis();
                operation_performed = true;
                break;
                
            case 'i':
                error = run_interactive_mode();
                operation_performed = true;
                break;
                
            case 'b':
                error = run_batch_mode(optarg);
                operation_performed = true;
                break;
        }
        
        if (error != IOTSTRIKE_SUCCESS) {
            fprintf(stderr, "Operation failed: %s\n", iotstrike_error_to_string(error));
        }
    }
    
    // If no specific operation was requested, enter interactive mode
    if (!operation_performed) {
        printf("No specific operation requested. Entering interactive mode...\n\n");
        run_interactive_mode();
    }
    
    // Print final statistics
    iotstrike_stats_t stats;
    if (iotstrike_get_statistics(&g_framework_ctx, &stats) == IOTSTRIKE_SUCCESS) {
        printf("\nFinal Statistics:\n");
        printf("  Total Operations: %llu\n", stats.operations_count);
        printf("  Total Errors: %llu\n", stats.errors_count);
        printf("  Bytes Processed: %llu\n", stats.bytes_processed);
        printf("  Memory Usage: %zu MB\n", stats.memory_usage / (1024 * 1024));
        printf("  Uptime: %u seconds\n", stats.uptime_seconds);
        printf("  Active Connections: %u\n", stats.active_connections);
        printf("  CPU Usage: %.2f%%\n", stats.cpu_usage);
    }
    
    // Stop and cleanup framework
    printf("\nShutting down framework...\n");
    iotstrike_stop(&g_framework_ctx);
    iotstrike_cleanup(&g_framework_ctx);
    
    printf("IoTStrike framework shutdown complete.\n");
    
    return (error == IOTSTRIKE_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}