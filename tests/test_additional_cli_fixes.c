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

/* Test information disclosure fix - paths should be sanitized */
static int test_information_disclosure_fix(void)
{
    struct hpmon_config config = {0};
    FILE *test_file;

    /* Create a test config file with invalid line to trigger error */
    test_file = fopen("/tmp/test_info_disclosure.conf", "w");
    TEST_ASSERT(test_file != NULL, "Could not create test file");

    fputs("# Test config file\n", test_file);
    fputs("invalid_line_without_equals\n", test_file);
    fclose(test_file);

    /* Capture stderr to check that full path is not disclosed */
    TEST_ASSERT(freopen("/tmp/test_stderr.txt", "w", stderr) != NULL, "Failed to redirect stderr");
    cli_load_config_file("/tmp/test_info_disclosure.conf", &config);
    TEST_ASSERT(freopen("/dev/stderr", "w", stderr) != NULL, "Failed to restore stderr");

    /* Read the error output */
    FILE *stderr_file = fopen("/tmp/test_stderr.txt", "r");
    char error_line[512];
    if (stderr_file && fgets(error_line, sizeof(error_line), stderr_file)) {
        /* Error message should contain sanitized path, not full path */
        TEST_ASSERT(strstr(error_line, "/test_info_disclosure.conf") != NULL,
                    "Should show sanitized filename");
        TEST_ASSERT(strstr(error_line, "/tmp/test_info_disclosure.conf") == NULL,
                    "Should not show full path");
        fclose(stderr_file);
    }

    unlink("/tmp/test_info_disclosure.conf");
    unlink("/tmp/test_stderr.txt");
    TEST_SUCCESS();
}

/* Test resource leak fix - rollback on critical errors */
static int test_resource_leak_fix(void)
{
    struct hpmon_config config = {0};
    FILE *test_file;
    char long_line[512];

    /* Set initial config values */
    config.monitor_cpu = true;
    config.poll_interval_ms = 100;

    /* Create a test config file with critical error (buffer overflow) */
    test_file = fopen("/tmp/test_resource_leak.conf", "w");
    TEST_ASSERT(test_file != NULL, "Could not create test file");

    /* Create a line longer than CONFIG_LINE_BUFFER_SIZE (256) */
    memset(long_line, 'x', 300);
    long_line[299] = '=';
    long_line[300] = 'y';
    long_line[301] = '\n';
    long_line[302] = '\0';

    fputs("# Test config file with critical error\n", test_file);
    fputs("monitor_cpu=false\n", test_file); /* This should be rolled back */
    fputs(long_line, test_file);             /* This causes critical error */
    fclose(test_file);

    /* Load should fail and rollback changes */
    int result = cli_load_config_file("/tmp/test_resource_leak.conf", &config);
    TEST_ASSERT(result == -1, "Should fail due to critical error");
    TEST_ASSERT(config.monitor_cpu == true, "Should rollback to original value");
    TEST_ASSERT(config.poll_interval_ms == 100, "Should rollback to original value");

    unlink("/tmp/test_resource_leak.conf");
    TEST_SUCCESS();
}

/* Test thread safety documentation fix */
static int test_thread_safety_documentation(void)
{
    /* This is a documentation fix, so we just verify the function still works */
    struct cli_options options;
    char *argv[] = {"hpmon", "-h", NULL};
    int argc = 2;

    cli_init_options(&options);

    /* Should handle help request */
    int result = cli_parse_arguments(argc, argv, &options);
    TEST_ASSERT(result == CLI_EXIT_SUCCESS, "Should handle help request");

    cli_cleanup_options(&options);
    TEST_SUCCESS();
}

int main(void)
{
    printf("Running Additional CLI Bug Fix Verification Tests\n");
    printf("===============================================\n\n");

    if (test_information_disclosure_fix() != 0) {
        return 1;
    }

    if (test_resource_leak_fix() != 0) {
        return 1;
    }

    if (test_thread_safety_documentation() != 0) {
        return 1;
    }

    printf("\n✅ All additional CLI bug fix verification tests passed!\n");
    return 0;
}
