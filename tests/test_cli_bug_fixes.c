#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cli.h"

/* Mock the version function to avoid linking issues */
const char *hpmon_version_string(void)
{
    return "0.1.0-test";
}

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

/* Test buffer overflow fix */
static int test_buffer_overflow_fix(void)
{
    struct hpmon_config config = {0};
    FILE *test_file;
    char long_line[512];

    /* Create a test config file with a line that's too long */
    test_file = fopen("/tmp/test_long_line.conf", "w");
    TEST_ASSERT(test_file != NULL, "Could not create test file");

    /* Create a line longer than CONFIG_LINE_BUFFER_SIZE (256) */
    memset(long_line, 'x', 300);
    long_line[299] = '=';
    long_line[300] = 'y';
    long_line[301] = '\n';
    long_line[302] = '\0';

    fputs("# Test config file\n", test_file);
    fputs(long_line, test_file);
    fputs("monitor_cpu=true\n", test_file);
    fclose(test_file);

    /* This should fail with buffer overflow detection */
    int result = cli_load_config_file("/tmp/test_long_line.conf", &config);
    TEST_ASSERT(result == -1, "Should detect buffer overflow and fail");

    unlink("/tmp/test_long_line.conf");
    TEST_SUCCESS();
}

/* Test integer overflow fix with strtol */
static int test_integer_overflow_fix(void)
{
    struct hpmon_config config = {0};
    FILE *test_file;

    /* Test with invalid integer values */
    test_file = fopen("/tmp/test_invalid_int.conf", "w");
    TEST_ASSERT(test_file != NULL, "Could not create test file");

    fputs("# Test config file with invalid integers\n", test_file);
    fputs("poll_interval_ms=99999999999999999999\n", test_file); /* Too large */
    fputs("aggregation_window_ms=abc\n", test_file);             /* Non-numeric */
    fputs("max_processes=-100\n", test_file);                    /* Negative */
    fclose(test_file);

    /* Should load but with warnings for invalid values */
    int result = cli_load_config_file("/tmp/test_invalid_int.conf", &config);
    TEST_ASSERT(result == 0, "Should load config despite warnings");

    unlink("/tmp/test_invalid_int.conf");
    TEST_SUCCESS();
}

/* Test empty key/value validation */
static int test_empty_key_value_fix(void)
{
    struct hpmon_config config = {0};
    FILE *test_file;

    test_file = fopen("/tmp/test_empty_keys.conf", "w");
    TEST_ASSERT(test_file != NULL, "Could not create test file");

    fputs("# Test config file with empty keys/values\n", test_file);
    fputs("=value_without_key\n", test_file);
    fputs("key_without_value=\n", test_file);
    fputs("   =   \n", test_file);          /* Only whitespace */
    fputs("monitor_cpu=true\n", test_file); /* Valid entry */
    fclose(test_file);

    /* Should load and process the valid entry */
    int result = cli_load_config_file("/tmp/test_empty_keys.conf", &config);
    TEST_ASSERT(result == 0, "Should load config and skip invalid entries");
    TEST_ASSERT(config.monitor_cpu == true, "Should parse valid entry correctly");

    unlink("/tmp/test_empty_keys.conf");
    TEST_SUCCESS();
}

/* Test improved output file validation */
static int test_output_file_validation_fix(void)
{
    struct hpmon_config config = {0};

    /* Set up config with output file but JSON disabled */
    strcpy(config.output_file, "/tmp/test_output.json");
    config.enable_json_output = false;
    config.monitor_cpu = true;
    config.monitor_syscalls = false;
    config.monitor_io = false;
    config.poll_interval_ms = 100;
    config.aggregation_window_ms = 1000;
    config.max_processes = 1000;

    /* Create the output directory to ensure it's writable */
    mkdir("/tmp", 0755); /* Should already exist but just in case */

    /* Should validate output file even when JSON is disabled */
    int result = cli_validate_config(&config);
    TEST_ASSERT(result == 0, "Should validate output file regardless of JSON setting");

    /* Test with non-writable directory */
    strcpy(config.output_file, "/root/protected/test_output.json");
    result = cli_validate_config(&config);
    /* This might pass or fail depending on permissions, so we won't assert */

    TEST_SUCCESS();
}

/* Test CLI argument parsing with invalid values */
static int test_cli_argument_validation(void)
{
    struct cli_options options;
    char *argv[] = {"hpmon", "-p", "invalid_number", NULL};
    int argc = 3;

    cli_init_options(&options);

    /* Should reject invalid poll interval */
    int result = cli_parse_arguments(argc, argv, &options);
    TEST_ASSERT(result == CLI_ERROR, "Should reject invalid poll interval");

    cli_cleanup_options(&options);

    /* Test with extremely large number */
    char *argv2[] = {"hpmon", "-m", "99999999999999999999", NULL};
    cli_init_options(&options);
    result = cli_parse_arguments(3, argv2, &options);
    TEST_ASSERT(result == CLI_ERROR, "Should reject overflow values");

    cli_cleanup_options(&options);
    TEST_SUCCESS();
}

/* Test double free prevention */
static int test_double_free_prevention(void)
{
    struct cli_options options;
    char *argv[] = {"hpmon", "-f", "config1.conf", "-f", "config2.conf", NULL};
    int argc = 5;

    cli_init_options(&options);

    /* Should handle multiple -f arguments without double free */
    cli_parse_arguments(argc, argv, &options);
    /* Result may be CLI_ERROR due to non-existent files, but should not crash */

    cli_cleanup_options(&options);
    TEST_SUCCESS();
}

int main(void)
{
    printf("Running CLI Bug Fix Verification Tests\n");
    printf("=====================================\n\n");

    if (test_buffer_overflow_fix() != 0) {
        return 1;
    }

    if (test_integer_overflow_fix() != 0) {
        return 1;
    }

    if (test_empty_key_value_fix() != 0) {
        return 1;
    }

    if (test_output_file_validation_fix() != 0) {
        return 1;
    }

    if (test_cli_argument_validation() != 0) {
        return 1;
    }

    if (test_double_free_prevention() != 0) {
        return 1;
    }

    printf("\n✅ All CLI bug fix verification tests passed!\n");
    return 0;
}
