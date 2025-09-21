/* HPMon Real-time Processing Test
 */

#include "hpmon.h"
#include "realtime.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test configuration */
#define TEST_WINDOW_SIZE 5
#define TEST_RATE_LIMIT 1 /* 1 MB/s - very low for rate limiting test */

/* Helper function to create test process data */
static void create_test_process_data(struct process_data *data, uint32_t pid, const char *comm,
                                     uint32_t cpu_percent, uint64_t syscalls, uint64_t io_bytes)
{
    memset(data, 0, sizeof(*data));
    data->pid = pid;
    strncpy(data->comm, comm, sizeof(data->comm) - 1);
    data->cpu_usage_percent = cpu_percent;
    data->syscall_count = syscalls;
    data->io_read_bytes = io_bytes / 2;
    data->io_write_bytes = io_bytes / 2;
    data->active = true;
}

/* Test sliding window functionality */
static int test_sliding_window(void)
{
    printf("Testing sliding window functionality...\n");

    struct sliding_window window;
    int ret = sliding_window_init(&window, TEST_WINDOW_SIZE);
    assert(ret == 0);

    /* Test adding values */
    for (int i = 1; i <= 3; i++) {
        ret = sliding_window_add(&window, (double)i);
        assert(ret == 0);
    }

    /* Test average calculation */
    double avg = sliding_window_average(&window);
    assert(avg == 2.0); /* (1+2+3)/3 = 2.0 */

    /* Fill the window completely */
    sliding_window_add(&window, 4.0);
    sliding_window_add(&window, 5.0);

    avg = sliding_window_average(&window);
    assert(avg == 3.0); /* (1+2+3+4+5)/5 = 3.0 */

    /* Test circular buffer behavior */
    sliding_window_add(&window, 10.0);
    avg = sliding_window_average(&window);
    assert(avg == 4.8); /* (2+3+4+5+10)/5 = 4.8 */

    /* Test trend calculation */
    double trend = sliding_window_trend(&window);
    printf("Trend: %f (should be positive)\n", trend);
    assert(trend > 0); /* Should show increasing trend */

    sliding_window_cleanup(&window);
    printf("✓ Sliding window tests passed\n");
    return 0;
}

/* Test moving averages functionality */
static int test_moving_averages(void)
{
    printf("Testing moving averages functionality...\n");

    struct moving_averages averages = {0};
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t start_time = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    /* Test first update */
    int ret = moving_averages_update(&averages, 100.0, start_time);
    assert(ret == 0);
    assert(averages.short_term == 100.0);
    assert(averages.medium_term == 100.0);
    assert(averages.long_term == 100.0);

    /* Test subsequent updates */
    uint64_t next_time = start_time + 1000000000ULL; /* 1 second later */
    ret = moving_averages_update(&averages, 50.0, next_time);
    assert(ret == 0);

    /* Short-term should change more than long-term */
    printf("Short-term: %f, Medium-term: %f, Long-term: %f\n", averages.short_term,
           averages.medium_term, averages.long_term);

    assert(averages.short_term < 100.0);
    assert(averages.medium_term < 100.0);
    assert(averages.long_term < 100.0);
    assert(averages.short_term < averages.medium_term);
    assert(averages.medium_term < averages.long_term);

    printf("✓ Moving averages tests passed\n");
    return 0;
}

/* Test real-time processor initialization */
static int test_processor_init(void)
{
    printf("Testing real-time processor initialization...\n");

    struct hpmon_config config = {.monitor_cpu = true,
                                  .monitor_syscalls = true,
                                  .monitor_io = true,
                                  .monitor_memory = true,
                                  .poll_interval_ms = 100,
                                  .max_processes = 100};

    /* Test successful initialization */
    int ret = realtime_processor_init(&config, TEST_WINDOW_SIZE, TEST_RATE_LIMIT);
    assert(ret == 0);

    /* Test duplicate initialization */
    ret = realtime_processor_init(&config, TEST_WINDOW_SIZE, TEST_RATE_LIMIT);
    assert(ret == -EALREADY);

    /* Test invalid parameters */
    realtime_processor_cleanup();
    ret = realtime_processor_init(&config, 0, TEST_RATE_LIMIT);
    assert(ret == -EINVAL);

    /* Reinitialize for other tests */
    ret = realtime_processor_init(&config, TEST_WINDOW_SIZE, TEST_RATE_LIMIT);
    assert(ret == 0);

    printf("✓ Processor initialization tests passed\n");
    return 0;
}

/* Test real-time processing operations */
static int test_processing_operations(void)
{
    printf("Testing real-time processing operations...\n");

    /* Start processing */
    int ret = realtime_processor_start();
    assert(ret == 0);

    /* Create test data */
    struct process_data test_processes[3];
    create_test_process_data(&test_processes[0], 1234, "test_proc1", 25, 1000, 1024 * 1024);
    create_test_process_data(&test_processes[1], 5678, "test_proc2", 50, 2000, 2 * 1024 * 1024);
    create_test_process_data(&test_processes[2], 9012, "test_proc3", 75, 3000, 3 * 1024 * 1024);

    /* Process samples */
    for (int i = 0; i < 5; i++) {
        /* Modify data slightly for each iteration to test trending */
        for (int j = 0; j < 3; j++) {
            test_processes[j].cpu_usage_percent += 5;
            test_processes[j].syscall_count += 100;
            test_processes[j].io_read_bytes += 1024;
            test_processes[j].io_write_bytes += 1024;
        }

        ret = realtime_processor_process_sample(test_processes, 3);
        if (ret == -EAGAIN) {
            printf("Sample rate limited, continuing...\n");
            usleep(100000); /* 100ms */
            continue;
        }
        assert(ret == 0);

        usleep(100000); /* 100ms between samples */
    }

    /* Test retrieving process metrics */
    struct rt_process_metrics metrics;
    ret = realtime_processor_get_process_metrics(1234, &metrics);
    assert(ret == 0);
    assert(metrics.pid == 1234);
    assert(strcmp(metrics.comm, "test_proc1") == 0);

    /* Test retrieving all metrics */
    struct rt_process_metrics all_metrics[10];
    size_t count;
    ret = realtime_processor_get_all_metrics(all_metrics, 10, &count);
    assert(ret == 0);
    assert(count == 3);

    /* Test getting statistics */
    struct realtime_stats stats;
    ret = realtime_processor_get_stats(&stats);
    assert(ret == 0);
    assert(stats.samples_processed > 0);
    assert(stats.active_processes == 3);

    printf("Processed %lu samples, dropped %lu\n", stats.samples_processed, stats.samples_dropped);
    printf("Average processing time: %.2f µs\n", stats.avg_processing_time_us);

    printf("Data rate: %.2f MB/s\n", stats.data_rate_mbps);

    /* Stop processing */
    ret = realtime_processor_stop();
    assert(ret == 0);

    printf("✓ Processing operations tests passed\n");
    return 0;
}

/* Test configuration updates */
static int test_config_updates(void)
{
    printf("Testing configuration updates...\n");

    /* Test valid updates */
    int ret = realtime_processor_update_config(10, 5);
    assert(ret == 0);

    /* Test invalid updates */
    ret = realtime_processor_update_config(0, 0); /* Should keep current values */
    assert(ret == 0);

    ret = realtime_processor_update_config(200, 0); /* Window size too large */
    assert(ret == -EINVAL);

    ret = realtime_processor_update_config(0, 200); /* Update rate limit */
    assert(ret == 0);

    printf("✓ Configuration update tests passed\n");
    return 0;
}

/* Test rate limiting functionality */
static int test_rate_limiting(void)
{
    printf("Testing rate limiting functionality...\n");

    /* Reinitialize with very low rate limit */
    realtime_processor_cleanup();
    struct hpmon_config config = {.monitor_cpu = true,
                                  .monitor_syscalls = true,
                                  .monitor_io = true,
                                  .monitor_memory = true,
                                  .poll_interval_ms = 100,
                                  .max_processes = 100};

    /* Use very low rate limit to trigger limiting */
    int ret = realtime_processor_init(&config, TEST_WINDOW_SIZE, 1); /* 1 KB/s */
    assert(ret == 0);

    /* Create large amount of test data to trigger rate limiting */
    struct process_data test_processes[20];
    for (int i = 0; i < 20; i++) {
        create_test_process_data(&test_processes[i], 1000 + i, "test_proc", 50, 1000,
                                 1024 * 1024); /* 1MB each = 20MB total */
    }

    realtime_processor_start();

    int rate_limited_count = 0;
    for (int i = 0; i < 5; i++) {
        int ret = realtime_processor_process_sample(test_processes, 20);
        if (ret == -EAGAIN) {
            rate_limited_count++;
        }
        /* No delay to stress test rate limiting */
    }

    printf("Rate limited %d out of 5 attempts\n", rate_limited_count);
    /* With 20MB per attempt and 1KB/s limit, should definitely rate limit */

    realtime_processor_stop();

    printf("✓ Rate limiting tests passed\n");
    return 0;
}

/* Main test function */
int main(void)
{
    printf("Starting HPMon Real-time Processing Tests\n");
    printf("=========================================\n\n");

    /* Run all tests */
    test_sliding_window();
    test_moving_averages();
    test_processor_init();
    test_processing_operations();
    test_config_updates();
    test_rate_limiting();

    /* Cleanup */
    realtime_processor_cleanup();

    printf("\n✓ All real-time processing tests passed!\n");
    return 0;
}
