/* HPMon Container Integration Tests
 * Tests for Kubernetes support, container metrics, and lifecycle events.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "container_tracker.h"

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
static int test_k8s_info_extraction(void)
{
    int result = container_tracker_init();
    if (result != CONTAINER_SUCCESS) {
        return 0;
    }

    char pod_name[MAX_POD_NAME_LEN];
    char namespace_name[MAX_NAMESPACE_LEN];

    /* Test with current process (likely not a k8s pod) */
    pid_t current_pid = getpid();
    result =
        container_tracker_get_k8s_info(current_pid, pod_name, namespace_name, sizeof(pod_name));

    /* Should return CONTAINER_ERROR_NOT_FOUND for non-k8s processes */
    container_tracker_cleanup();
    return result == CONTAINER_ERROR_NOT_FOUND;
}

static int test_metrics_update(void)
{
    int result = container_tracker_init();
    if (result != 0) {
        return 0;
    }

    const char *container_id = "test_container_123456789";
    double cpu_percent = 15.5;
    unsigned long memory_bytes = 1024 * 1024; /* 1 MB */
    unsigned long io_read = 1000;
    unsigned long io_write = 2000;
    unsigned long syscalls = 500;

    /* Update metrics for a test container */
    result = container_tracker_update_metrics(container_id, cpu_percent, memory_bytes, io_read,
                                              io_write, syscalls);

    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    /* Get metrics back */
    struct container_summary metrics[MAX_CONTAINERS];
    size_t count;

    result = container_tracker_get_metrics(metrics, MAX_CONTAINERS, &count);
    if (result != 0 || count == 0) {
        container_tracker_cleanup();
        return 0;
    }

    /* Verify metrics */
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(metrics[i].container_id, container_id) == 0) {
            found = 1;
            if (metrics[i].cpu_usage_percent != cpu_percent ||
                metrics[i].memory_usage_bytes != memory_bytes ||
                metrics[i].io_read_bytes != io_read || metrics[i].io_write_bytes != io_write ||
                metrics[i].syscall_count != syscalls) {
                container_tracker_cleanup();
                return 0;
            }
            break;
        }
    }

    container_tracker_cleanup();
    return found;
}

static int test_lifecycle_events(void)
{
    int result = container_tracker_init();
    if (result != CONTAINER_SUCCESS) {
        return 0;
    }

    const char *container_id = "lifecycle_test_container";

    /* Track start event */
    result = container_tracker_track_event(container_id, "start");
    /* Should return CONTAINER_ERROR_NOT_FOUND because container doesn't exist yet */
    if (result != CONTAINER_ERROR_NOT_FOUND) {
        container_tracker_cleanup();
        return 0;
    }

    /* Test with invalid parameters */
    result = container_tracker_track_event(NULL, "start");
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0;
    }

    result = container_tracker_track_event(container_id, NULL);
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0;
    }

    container_tracker_cleanup();
    return 1;
}

static int test_container_summary(void)
{
    int result = container_tracker_init();
    if (result != 0) {
        return 0;
    }

    /* Get container summary with new fields */
    struct container_summary containers[MAX_CONTAINERS];
    size_t count;

    result = container_tracker_get_containers(containers, MAX_CONTAINERS, &count);
    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    /* Check that the summary structure has the new fields initialized */
    for (size_t i = 0; i < count; i++) {
        /* Metrics should be initialized to zero or positive values */
        if (containers[i].cpu_usage_percent < 0) {
            container_tracker_cleanup();
            return 0;
        }
    }

    container_tracker_cleanup();
    return 1;
}

static int test_error_handling(void)
{
    /* Test without initialization */
    const char *container_id = "test_container";
    int result;

    result = container_tracker_update_metrics(container_id, 10.0, 1000, 100, 200, 50);
    if (result != CONTAINER_ERROR_INVALID) {
        return 0; /* Should have failed */
    }

    result = container_tracker_track_event(container_id, "start");
    if (result != CONTAINER_ERROR_INVALID) {
        return 0; /* Should have failed */
    }

    struct container_summary metrics[MAX_CONTAINERS];
    size_t count;
    result = container_tracker_get_metrics(metrics, MAX_CONTAINERS, &count);
    if (result != CONTAINER_ERROR_INVALID) {
        return 0; /* Should have failed */
    }

    /* Test with NULL parameters */
    container_tracker_init();

    result = container_tracker_update_metrics(NULL, 10.0, 1000, 100, 200, 50);
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0; /* Should have failed */
    }

    result = container_tracker_get_metrics(NULL, MAX_CONTAINERS, &count);
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0; /* Should have failed */
    }

    result = container_tracker_get_metrics(metrics, MAX_CONTAINERS, NULL);
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0; /* Should have failed */
    }

    container_tracker_cleanup();
    return 1;
}

static int test_metrics_aggregation(void)
{
    int result = container_tracker_init();
    if (result != 0) {
        return 0;
    }

    /* Add metrics for multiple containers */
    result = container_tracker_update_metrics("container1", 10.0, 1000, 100, 200, 50);
    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    result = container_tracker_update_metrics("container2", 20.0, 2000, 200, 400, 100);
    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    /* Update first container again */
    result = container_tracker_update_metrics("container1", 15.0, 1500, 150, 300, 75);
    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    /* Get all metrics */
    struct container_summary metrics[MAX_CONTAINERS];
    size_t count;

    result = container_tracker_get_metrics(metrics, MAX_CONTAINERS, &count);
    if (result != 0 || count != 2) {
        container_tracker_cleanup();
        return 0;
    }

    /* Verify updated metrics for container1 */
    int found_container1 = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(metrics[i].container_id, "container1") == 0) {
            found_container1 = 1;
            if (metrics[i].cpu_usage_percent != 15.0 || metrics[i].memory_usage_bytes != 1500) {
                container_tracker_cleanup();
                return 0;
            }
        }
    }

    container_tracker_cleanup();
    return found_container1;
}

/* Basic container tracker tests moved from test_core.c */
static int test_container_tracker_init(void)
{
    /* Test container tracker initialization */
    int result = container_tracker_init();
    if (result != 0) {
        return 0;
    }

    /* Test cleanup */
    container_tracker_cleanup();
    return 1;
}

static int test_container_detection(void)
{
    int result = container_tracker_init();
    if (result != 0) {
        return 0;
    }

    /* Test with current process */
    pid_t current_pid = getpid();
    struct container_info info;

    result = container_tracker_get_info(current_pid, &info);
    if (result != 0 || info.pid != current_pid) {
        container_tracker_cleanup();
        return 0;
    }

    /* Test container detection convenience function */
    bool is_container = container_tracker_is_container(current_pid);
    if (is_container != info.is_container) {
        container_tracker_cleanup();
        return 0;
    }

    container_tracker_cleanup();
    return 1;
}

static int test_container_enumeration(void)
{
    int result = container_tracker_init();
    if (result != 0) {
        return 0;
    }

    /* Get info for current process to populate cache */
    pid_t current_pid = getpid();
    struct container_info info;
    result = container_tracker_get_info(current_pid, &info);
    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    /* Get container list */
    struct container_summary containers[MAX_CONTAINERS];
    size_t count;

    result = container_tracker_get_containers(containers, MAX_CONTAINERS, &count);
    if (result != 0) {
        container_tracker_cleanup();
        return 0;
    }

    container_tracker_cleanup();
    return 1;
}

static int test_container_error_handling_basic(void)
{
    /* Test without initialization */
    struct container_info info;
    int result = container_tracker_get_info(getpid(), &info);
    if (result != CONTAINER_ERROR_INVALID) {
        return 0; /* Should have failed */
    }

    /* Test invalid parameters */
    container_tracker_init();

    result = container_tracker_get_info(0, &info);
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0; /* Should have failed */
    }

    result = container_tracker_get_info(getpid(), NULL);
    if (result != CONTAINER_ERROR_INVALID) {
        container_tracker_cleanup();
        return 0; /* Should have failed */
    }

    container_tracker_cleanup();
    return 1;
}

int main(void)
{
    printf("HPMon Container Integration Test Suite\n");
    printf("===============================================\n\n");

    /* Run all tests */
    TEST(container_tracker_init);
    TEST(container_detection);
    TEST(container_enumeration);
    TEST(container_error_handling_basic);
    TEST(k8s_info_extraction);
    TEST(metrics_update);
    TEST(lifecycle_events);
    TEST(container_summary);
    TEST(error_handling);
    TEST(metrics_aggregation);

    /* Print results */
    printf("\nTest Results:\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_run - tests_passed);

    if (tests_passed == tests_run) {
        printf("\nAll container tests PASSED!\n");
        return 0;
    } else {
        printf("\nSome container tests FAILED!\n");
        return 1;
    }
}
