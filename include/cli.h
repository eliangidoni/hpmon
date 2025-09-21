#ifndef CLI_H
#define CLI_H

#include "hpmon.h"
#include <stdbool.h>

/* Configuration file paths */
#define DEFAULT_CONFIG_FILE "/etc/hpmon/hpmon.conf"
#define USER_CONFIG_FILE "~/.hpmon.conf"
#define LOCAL_CONFIG_FILE "./hpmon.conf"

/* CLI result codes */
#define CLI_SUCCESS 0
#define CLI_ERROR (-1)
#define CLI_EXIT_SUCCESS 1
#define CLI_EXIT_ERROR 2

/* CLI command structure */
struct cli_options {
    bool show_help;
    bool show_version;
    char *config_file;
    struct hpmon_config config;
};

/* Function declarations */

/**
 * Parse command-line arguments and populate configuration
 * @param argc Number of arguments
 * @param argv Argument array
 * @param options Output CLI options structure
 * @return CLI_SUCCESS on success, CLI_ERROR on error, CLI_EXIT_* for immediate exit
 */
int cli_parse_arguments(int argc, char *argv[], struct cli_options *options);

/**
 * Load configuration from file
 * @param filename Configuration file path (NULL for default search)
 * @param config Output configuration structure
 * @return 0 on success, -1 on error
 */
int cli_load_config_file(const char *filename, struct hpmon_config *config);

/**
 * Save configuration to file
 * @param filename Configuration file path
 * @param config Configuration structure to save
 * @return 0 on success, -1 on error
 */
int cli_save_config_file(const char *filename, const struct hpmon_config *config);

/**
 * Print usage information
 * @param program_name Program name from argv[0]
 */
void cli_print_usage(const char *program_name);

/**
 * Print version information
 */
void cli_print_version(void);

/**
 * Validate configuration parameters
 * @param config Configuration to validate
 * @return 0 if valid, -1 if invalid
 */
int cli_validate_config(const struct hpmon_config *config);

/**
 * Initialize CLI options with default values
 * @param options CLI options structure to initialize
 */
void cli_init_options(struct cli_options *options);

/**
 * Clean up CLI options (free allocated memory)
 * @param options CLI options structure to clean up
 */
void cli_cleanup_options(struct cli_options *options);

/**
 * Print current configuration
 * @param config Configuration to print
 */
void cli_print_config(const struct hpmon_config *config);

/**
 * Check if the current user has sufficient privileges
 * @return 0 if privileges are sufficient, -1 otherwise
 */
int cli_check_privileges(void);

/**
 * Find and load the first available configuration file
 * @param config Output configuration structure
 * @return 0 on success, -1 if no config file found
 */
int cli_auto_load_config(struct hpmon_config *config);

#endif /* CLI_H */