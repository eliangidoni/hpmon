#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpmon.h"

/* Test configuration */
static struct hpmon_config test_config = {
    .monitor_cpu = true,
    .monitor_syscalls = true,
    .monitor_io = true,
    .monitor_memory = true,
    .monitor_containers = true, /* Enable container monitoring for tests */
    .poll_interval_ms = 100,
    .aggregation_window_ms = 1000,
    .enable_tui = false,
    .enable_json_output = false,
    .output_file = "",
    .max_processes = 100,
};

/* Test counter */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                                                 \
    do {                                                                                           \
        printf("Running test: %s ... ", #name);                                                    \
        tests_run++;                                                                               \
        if (test_##name()) {                                                                       \
            printf("PASS\n");                                                                      \
            tests_passed++;                                                                        \
        } else {                                                                                   \
            printf("FAIL\n");                                                                      \
        }                                                                                          \
    } while (0)

/* Test functions */
static int test_version_string(void)
{
    const char *version = hpmon_version_string();
    return version != NULL && strlen(version) > 0;
}

static int test_init_and_cleanup(void)
{
    int ret;

    /* Test successful initialization */
    ret = hpmon_init(&test_config);
    if (ret != 0) {
        return 0;
    }

    /* Test cleanup */
    hpmon_cleanup();

    return 1;
}

static int test_start_stop_monitoring(void)
{
    int ret;

    /* Initialize first */
    ret = hpmon_init(&test_config);
    if (ret != 0) {
        return 0;
    }

    /* Test start monitoring */
    ret = hpmon_start();
    if (ret != 0) {
        hpmon_cleanup();
        return 0;
    }

    /* Test stop monitoring */
    ret = hpmon_stop();
    if (ret != 0) {
        hpmon_cleanup();
        return 0;
    }

    hpmon_cleanup();
    return 1;
}

static int test_json_export(void)
{
    int ret;

    /* Initialize */
    ret = hpmon_init(&test_config);
    if (ret != 0) {
        return 0;
    }

    /* Test JSON export to stdout (no file) */
    ret = hpmon_export_json(NULL);

    hpmon_cleanup();
    return ret == 0;
}

static int test_invalid_parameters(void)
{
    int ret;

    /* Test init with NULL config */
    ret = hpmon_init(NULL);
    if (ret >= 0) {
        return 0; /* Should have failed */
    }

    /* Test start without init */
    ret = hpmon_start();
    if (ret >= 0) {
        return 0; /* Should have failed */
    }

    /* Test stop without start */
    ret = hpmon_init(&test_config);
    if (ret != 0) {
        return 0;
    }

    ret = hpmon_stop();
    hpmon_cleanup();

    /* Stop without start should fail */
    return ret < 0;
}

int main(void)
{
    printf("HPMon Test Suite\n");
    printf("================\n\n");

    /* Run all tests */
    TEST(version_string);
    TEST(init_and_cleanup);
    TEST(start_stop_monitoring);
    TEST(json_export);
    TEST(invalid_parameters);

    /* Print results */
    printf("\nTest Results:\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);

    if (tests_passed == tests_run) {
        printf("\nAll tests PASSED!\n");
        return 0;
    } else {
        printf("\nSome tests FAILED!\n");
        return 1;
    }
}
