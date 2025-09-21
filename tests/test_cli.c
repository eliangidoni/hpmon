#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cli.h"

/* Test helper macros */
#define TEST_ASSERT(condition, message)                                                            \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "TEST FAILED: %s\n", message);                                         \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

#define TEST_SUCCESS()                                                                             \
    do {                                                                                           \
        printf("✓ %s\n", __func__);                                                                \
        return 0;                                                                                  \
    } while (0)

/* Test initialization and cleanup */
static int test_cli_init_cleanup(void)
{
    struct cli_options options;

    cli_init_options(&options);

    /* Check default values */
    TEST_ASSERT(options.config.monitor_cpu == true, "Default CPU monitoring should be enabled");
    TEST_ASSERT(options.config.monitor_syscalls == true,
                "Default syscall monitoring should be enabled");
    TEST_ASSERT(options.config.monitor_io == true, "Default I/O monitoring should be enabled");
    TEST_ASSERT(options.config.monitor_containers == false,
                "Default container monitoring should be disabled");
    TEST_ASSERT(options.config.poll_interval_ms == DEFAULT_POLL_INTERVAL,
                "Default poll interval incorrect");
    TEST_ASSERT(options.config.max_processes == MAX_PROCESSES, "Default max processes incorrect");
    TEST_ASSERT(options.show_help == false, "Default show_help should be false");
    TEST_ASSERT(options.show_version == false, "Default show_version should be false");
    TEST_ASSERT(options.config_file == NULL, "Default config_file should be NULL");

    cli_cleanup_options(&options);

    TEST_SUCCESS();
}

/* Test argument parsing - help and version */
static int test_cli_parse_help_version(void)
{
    struct cli_options options;
    char *argv_help[] = {"hpmon", "--help"};
    char *argv_version[] = {"hpmon", "--version"};
    int result;

    /* Test help */
    cli_init_options(&options);
    result = cli_parse_arguments(2, argv_help, &options);
    TEST_ASSERT(result == CLI_EXIT_SUCCESS, "Help should return CLI_EXIT_SUCCESS");
    cli_cleanup_options(&options);

    /* Test version */
    cli_init_options(&options);
    result = cli_parse_arguments(2, argv_version, &options);
    TEST_ASSERT(result == CLI_EXIT_SUCCESS, "Version should return CLI_EXIT_SUCCESS");
    cli_cleanup_options(&options);

    TEST_SUCCESS();
}

/* Test argument parsing - basic options */
static int test_cli_parse_basic_options(void)
{
    struct cli_options options;
    char *argv[] = {"hpmon", "-C", "-t", "-j", "-p", "200", "-m", "500"};
    int result;

    cli_init_options(&options);
    result = cli_parse_arguments(8, argv, &options);

    TEST_ASSERT(result == CLI_SUCCESS, "Basic options parsing should succeed");
    TEST_ASSERT(options.config.monitor_containers == true,
                "Container monitoring should be enabled");
    TEST_ASSERT(options.config.enable_tui == true, "TUI should be enabled");
    TEST_ASSERT(options.config.enable_json_output == true, "JSON output should be enabled");
    TEST_ASSERT(options.config.poll_interval_ms == 200, "Poll interval should be 200");
    TEST_ASSERT(options.config.max_processes == 500, "Max processes should be 500");

    cli_cleanup_options(&options);

    TEST_SUCCESS();
}

/* Test argument parsing - disable options */
static int test_cli_parse_disable_options(void)
{
    struct cli_options options;
    char *argv[] = {"hpmon", "--no-cpu", "--no-syscalls"};
    int result;

    cli_init_options(&options);
    result = cli_parse_arguments(3, argv, &options);

    TEST_ASSERT(result == CLI_SUCCESS, "Disable options parsing should succeed");
    TEST_ASSERT(options.config.monitor_cpu == false, "CPU monitoring should be disabled");
    TEST_ASSERT(options.config.monitor_syscalls == false, "Syscall monitoring should be disabled");
    TEST_ASSERT(options.config.monitor_io == true, "I/O monitoring should still be enabled");

    cli_cleanup_options(&options);

    TEST_SUCCESS();
}

/* Test configuration validation */
static int test_cli_validate_config(void)
{
    struct hpmon_config config;

    /* Valid configuration */
    config.monitor_cpu = true;
    config.monitor_syscalls = false;
    config.monitor_io = false;
    config.monitor_containers = false;
    config.poll_interval_ms = 100;
    config.aggregation_window_ms = 1000;
    config.max_processes = 1000;
    config.enable_tui = false;
    config.enable_json_output = false;
    config.output_file[0] = '\0';

    TEST_ASSERT(cli_validate_config(&config) == 0, "Valid config should pass validation");

    /* Invalid poll interval */
    config.poll_interval_ms = 5;
    TEST_ASSERT(cli_validate_config(&config) != 0, "Invalid poll interval should fail validation");
    config.poll_interval_ms = 100;

    /* Invalid aggregation window */
    config.aggregation_window_ms = 50;
    TEST_ASSERT(cli_validate_config(&config) != 0,
                "Invalid aggregation window should fail validation");
    config.aggregation_window_ms = 1000;

    /* Invalid max processes */
    config.max_processes = 5;
    TEST_ASSERT(cli_validate_config(&config) != 0, "Invalid max processes should fail validation");
    config.max_processes = 1000;

    /* No monitoring enabled */
    config.monitor_cpu = false;
    config.monitor_syscalls = false;
    config.monitor_io = false;
    config.monitor_memory = false;
    TEST_ASSERT(cli_validate_config(&config) != 0, "No monitoring enabled should fail validation");

    TEST_SUCCESS();
}

/* Test configuration file save and load */
static int test_cli_config_file(void)
{
    struct hpmon_config config1, config2;
    const char *test_file = "/tmp/hpmon_test.conf";

    /* Setup test configuration */
    config1.monitor_cpu = false;
    config1.monitor_syscalls = true;
    config1.monitor_io = true;
    config1.monitor_containers = true;
    config1.poll_interval_ms = 200;
    config1.aggregation_window_ms = 2000;
    config1.max_processes = 500;
    config1.enable_tui = true;
    config1.enable_json_output = false;
    strcpy(config1.output_file, "/tmp/test.json");

    /* Save configuration */
    TEST_ASSERT(cli_save_config_file(test_file, &config1) == 0, "Config save should succeed");

    /* Initialize config2 with different values */
    memset(&config2, 0, sizeof(config2));
    config2.monitor_cpu = true;
    config2.monitor_syscalls = false;
    config2.poll_interval_ms = 100;

    /* Load configuration */
    TEST_ASSERT(cli_load_config_file(test_file, &config2) == 0, "Config load should succeed");

    /* Verify loaded values */
    TEST_ASSERT(config2.monitor_cpu == false, "Loaded CPU monitoring should match saved");
    TEST_ASSERT(config2.monitor_syscalls == true, "Loaded syscall monitoring should match saved");
    TEST_ASSERT(config2.monitor_io == true, "Loaded I/O monitoring should match saved");
    TEST_ASSERT(config2.monitor_containers == true,
                "Loaded container monitoring should match saved");
    TEST_ASSERT(config2.poll_interval_ms == 200, "Loaded poll interval should match saved");
    TEST_ASSERT(config2.aggregation_window_ms == 2000,
                "Loaded aggregation window should match saved");
    TEST_ASSERT(config2.max_processes == 500, "Loaded max processes should match saved");
    TEST_ASSERT(config2.enable_tui == true, "Loaded TUI setting should match saved");
    TEST_ASSERT(strcmp(config2.output_file, "/tmp/test.json") == 0,
                "Loaded output file should match saved");

    /* Cleanup */
    unlink(test_file);

    TEST_SUCCESS();
}

/* Main test runner */
int main(void)
{
    printf("Running CLI tests...\n\n");

    if (test_cli_init_cleanup() != 0)
        return 1;
    if (test_cli_parse_help_version() != 0)
        return 1;
    if (test_cli_parse_basic_options() != 0)
        return 1;
    if (test_cli_parse_disable_options() != 0)
        return 1;
    if (test_cli_validate_config() != 0)
        return 1;
    if (test_cli_config_file() != 0)
        return 1;

    printf("\n✅ All CLI tests passed!\n");
    return 0;
}
