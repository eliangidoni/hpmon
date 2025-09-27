// SPDX-License-Identifier: MIT
/* HPMon Real-time Processing Engine
 *
 * This module implements real-time data processing including sliding window analysis,
 * moving averages calculation, data rate limiting, and low latency optimization.
 */

#include "realtime.h"
#include "safe_string.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Constants for calculations */
#define NANOSECONDS_PER_SECOND 1000000000ULL
#define NANOSECONDS_PER_MICROSECOND 1000ULL
#define MICROSECONDS_PER_SECOND 1000000ULL
#define SECONDS_PER_MINUTE 60
#define SHORT_TERM_WINDOW_SEC (1 * SECONDS_PER_MINUTE)  /* 1 minute */
#define MEDIUM_TERM_WINDOW_SEC (5 * SECONDS_PER_MINUTE) /* 5 minutes */
#define LONG_TERM_WINDOW_SEC (15 * SECONDS_PER_MINUTE)  /* 15 minutes */
#define BYTES_PER_MB (1024 * 1024)
#define TREND_THRESHOLD 0.1          /* Minimum change for trend detection */
#define CLEANUP_INTERVAL_SAMPLES 100 /* Process cleanup interval in samples */
#define PROCESS_TIMEOUT_SECONDS 30   /* Process inactivity timeout in seconds */
#define DENOMINATOR_EPSILON                                                                        \
    1e-6 /* Minimum denominator value for calculations (increased for stability) */
#define MAX_CPU_USAGE_PERCENT 12800 /* Maximum CPU usage percentage (128 cores * 100%) */

/* Exponential weighted moving average constants */
#define EWMA_ALPHA_SHORT 0.1   /* Smoothing factor for short-term average */
#define EWMA_ALPHA_MEDIUM 0.05 /* Smoothing factor for medium-term average */
#define EWMA_ALPHA_LONG 0.02   /* Smoothing factor for long-term average */

/* Global real-time processor state */
static struct realtime_processor g_processor = {0};

/* Helper function declarations */
static uint64_t get_current_time_us(void);
static bool should_rate_limit(size_t data_size);
static struct rt_process_metrics *find_or_create_process_metrics(uint32_t pid, const char *comm);
static int update_process_metrics(struct rt_process_metrics *metrics,
                                  const struct process_data *data);
static double calculate_rate(uint64_t current_value, uint64_t previous_value,
                             uint64_t time_delta_ns);
static void cleanup_inactive_processes(void);

/* Get current time in microseconds */
static uint64_t get_current_time_us(void)
{
    uint64_t time_ns = get_current_time_ns();
    if (time_ns == 0) {
        return 0; /* Clock function failed */
    }
    return time_ns / NANOSECONDS_PER_MICROSECOND;
}

/* Check if we should rate limit based on data processing rate */
static bool should_rate_limit(size_t data_size)
{
    uint64_t current_time_us = get_current_time_us();
    uint64_t current_second = current_time_us / MICROSECONDS_PER_SECOND;

    /* Reset byte counter if we've moved to a new second */
    if (current_second != g_processor.current_second) {
        g_processor.current_second = current_second;
        g_processor.bytes_processed_this_second = 0;
    }

    /* Check if adding this data would exceed the rate limit */
    if (g_processor.bytes_processed_this_second + data_size >
        g_processor.rate_limit_bytes_per_sec) {
        return true;
    }

    g_processor.bytes_processed_this_second += data_size;
    return false;
}

/* Initialize the real-time processor */
int realtime_processor_init(const struct hpmon_config *config, size_t window_size,
                            uint32_t rate_limit_mbps)
{
    if (!config) {
        return -EINVAL;
    }

    if (g_processor.initialized) {
        return -EALREADY;
    }

    /* Validate parameters */
    if (window_size < MIN_WINDOW_SIZE || window_size > MAX_WINDOW_SIZE) {
        printf("Error: Window size must be between %d and %d\n", MIN_WINDOW_SIZE, MAX_WINDOW_SIZE);
        return -EINVAL;
    }

    /* Initialize processor state */
    memset(&g_processor, 0, sizeof(g_processor));
    g_processor.max_processes = config->max_processes;
    g_processor.window_size = window_size;
    g_processor.rate_limit_bytes_per_sec = rate_limit_mbps * BYTES_PER_MB;

    /* Allocate memory for process metrics */
    /* Use malloc + explicit zeroing to reduce fragmentation compared to calloc */
    g_processor.processes = malloc(g_processor.max_processes * sizeof(struct rt_process_metrics));
    if (!g_processor.processes) {
        printf("Error: Failed to allocate memory for process metrics\n");
        return -ENOMEM;
    }

    /* Explicitly zero the memory to ensure clean initialization */
    memset(g_processor.processes, 0, g_processor.max_processes * sizeof(struct rt_process_metrics));

    g_processor.current_second = get_current_time_us() / MICROSECONDS_PER_SECOND;
    if (g_processor.current_second == 0) {
        printf("Warning: Clock function failed during initialization\n");
        /* Continue with initialization but log the warning */
    }

    printf("Real-time Processor: Initialized with window_size=%zu, rate_limit=%dMB/s\n",
           window_size, rate_limit_mbps);

    g_processor.initialized = true;
    return 0;
}

/* Start real-time processing */
int realtime_processor_start(void)
{
    if (!g_processor.initialized) {
        return -EINVAL;
    }

    if (g_processor.running) {
        return -EALREADY;
    }

    printf("Real-time Processor: Starting processing...\n");
    g_processor.running = true;
    uint64_t start_time = get_current_time_us();
    if (start_time == 0) {
        printf("Warning: Clock function failed during start\n");
        /* Use previous sample time as fallback */
        if (g_processor.last_sample_time == 0) {
            g_processor.last_sample_time = 1;
        }
    } else {
        g_processor.last_sample_time = start_time;
    }

    return 0;
}

/* Stop real-time processing */
int realtime_processor_stop(void)
{
    if (!g_processor.initialized || !g_processor.running) {
        return -EINVAL;
    }

    printf("Real-time Processor: Stopping processing...\n");
    g_processor.running = false;

    return 0;
}

/* Cleanup real-time processor */
void realtime_processor_cleanup(void)
{
    if (!g_processor.initialized) {
        return;
    }

    if (g_processor.running) {
        realtime_processor_stop();
    }

    /* Cleanup all sliding windows */
    for (size_t i = 0; i < g_processor.process_count; i++) {
        sliding_window_cleanup(&g_processor.processes[i].cpu_usage_window);
        sliding_window_cleanup(&g_processor.processes[i].syscall_rate_window);
        sliding_window_cleanup(&g_processor.processes[i].io_rate_window);
        sliding_window_cleanup(&g_processor.processes[i].network_rate_window);
        sliding_window_cleanup(&g_processor.processes[i].memory_usage_window);
    }

    free(g_processor.processes);
    printf("Real-time Processor: Cleanup complete\n");
    memset(&g_processor, 0, sizeof(g_processor));
}

/* Find or create process metrics */
static struct rt_process_metrics *find_or_create_process_metrics(uint32_t pid, const char *comm)
{
    /* First, try to find existing active process */
    for (size_t i = 0; i < g_processor.process_count; i++) {
        if (g_processor.processes[i].pid == pid && g_processor.processes[i].active) {
            return &g_processor.processes[i];
        }
    }

    /* If not found and we have space, create new one */
    if (g_processor.process_count < g_processor.max_processes) {
        struct rt_process_metrics *metrics = &g_processor.processes[g_processor.process_count];

        memset(metrics, 0, sizeof(*metrics));
        metrics->pid = pid;
        safe_strncpy(metrics->comm, comm, sizeof(metrics->comm));
        uint64_t current_time_ns = get_current_time_ns();
        if (current_time_ns == 0) {
            printf("Warning: Clock function failed, using fallback timestamp\n");
            current_time_ns = 1; /* Use minimal non-zero timestamp as fallback */
        }
        metrics->first_seen = current_time_ns;
        metrics->last_updated = metrics->first_seen;
        metrics->active = true;
        metrics->is_container = false;   /* Will be updated when process data is received */
        metrics->container_id[0] = '\0'; /* Initialize as empty string */

        /* Initialize sliding windows */
        int cpu_init = sliding_window_init(&metrics->cpu_usage_window, g_processor.window_size);
        int syscall_init = 0;
        int io_init = 0;
        int network_init = 0;
        int memory_init = 0;

        if (cpu_init == 0) {
            syscall_init =
                sliding_window_init(&metrics->syscall_rate_window, g_processor.window_size);
        }

        if (cpu_init == 0 && syscall_init == 0) {
            io_init = sliding_window_init(&metrics->io_rate_window, g_processor.window_size);
        }

        if (cpu_init == 0 && syscall_init == 0 && io_init == 0) {
            network_init =
                sliding_window_init(&metrics->network_rate_window, g_processor.window_size);
        }

        if (cpu_init == 0 && syscall_init == 0 && io_init == 0 && network_init == 0) {
            memory_init =
                sliding_window_init(&metrics->memory_usage_window, g_processor.window_size);
        }

        /* Check if any initialization failed and cleanup if needed */
        if (cpu_init != 0 || syscall_init != 0 || io_init != 0 || network_init != 0 ||
            memory_init != 0) {
            /* Cleanup any successfully initialized windows */
            if (cpu_init == 0) {
                sliding_window_cleanup(&metrics->cpu_usage_window);
            }
            if (syscall_init == 0) {
                sliding_window_cleanup(&metrics->syscall_rate_window);
            }
            if (io_init == 0) {
                sliding_window_cleanup(&metrics->io_rate_window);
            }
            if (network_init == 0) {
                sliding_window_cleanup(&metrics->network_rate_window);
            }
            /* memory_init failure means nothing to cleanup for it */
            return NULL;
        }

        /* Only increment process count after successful initialization */
        g_processor.process_count++;
        return metrics;
    }

    /* No space available */
    return NULL;
}

/* Calculate rate based on value difference and time delta */
static double calculate_rate(uint64_t current_value, uint64_t previous_value,
                             uint64_t time_delta_ns)
{
    if (time_delta_ns == 0 || current_value < previous_value) {
        return 0.0;
    }

    uint64_t value_delta = current_value - previous_value;
    double time_delta_sec = (double)time_delta_ns / NANOSECONDS_PER_SECOND;

    return (double)value_delta / time_delta_sec;
}

/* Update process metrics with new data */
static int update_process_metrics(struct rt_process_metrics *metrics,
                                  const struct process_data *data)
{
    uint64_t current_time = get_current_time_ns();
    if (current_time == 0) {
        printf("Warning: Clock function failed in update_process_metrics\n");
        return -EFAULT; /* Clock function error */
    }
    uint64_t time_delta = current_time - metrics->last_updated;

    /* Update container information */
    metrics->is_container = data->is_container;
    if (data->is_container && data->container_id[0] != '\0') {
        safe_strncpy(metrics->container_id, data->container_id, sizeof(metrics->container_id));
    }

    /* Validate CPU usage is within reasonable bounds (0-N*100% where N=cores) */
    double cpu_usage;
    if (data->cpu_usage_percent > MAX_CPU_USAGE_PERCENT) {
        cpu_usage = (double)MAX_CPU_USAGE_PERCENT; /* Cap at maximum system percentage */
    } else {
        cpu_usage = (double)data->cpu_usage_percent;
    }

    sliding_window_add(&metrics->cpu_usage_window, cpu_usage);
    moving_averages_update(&metrics->cpu_averages, cpu_usage, current_time);
    metrics->cpu_trend = sliding_window_trend(&metrics->cpu_usage_window);

    /* Update syscall rate metrics */
    double syscall_rate =
        calculate_rate(data->syscall_count, metrics->prev_syscall_count, time_delta);
    metrics->prev_syscall_count = data->syscall_count;

    sliding_window_add(&metrics->syscall_rate_window, syscall_rate);
    moving_averages_update(&metrics->syscall_averages, syscall_rate, current_time);
    metrics->syscall_trend = sliding_window_trend(&metrics->syscall_rate_window);

    /* Update I/O rate metrics */
    uint64_t total_io_bytes = data->io_read_bytes + data->io_write_bytes;
    double io_rate = calculate_rate(total_io_bytes, metrics->prev_io_bytes, time_delta);
    metrics->prev_io_bytes = total_io_bytes;

    sliding_window_add(&metrics->io_rate_window, io_rate);
    moving_averages_update(&metrics->io_averages, io_rate, current_time);
    metrics->io_trend = sliding_window_trend(&metrics->io_rate_window);

    /* Update network rate metrics */
    uint64_t total_network_bytes = data->network_rx_bytes + data->network_tx_bytes;
    double network_rate =
        calculate_rate(total_network_bytes, metrics->prev_network_bytes, time_delta);
    metrics->prev_network_bytes = total_network_bytes;

    sliding_window_add(&metrics->network_rate_window, network_rate);
    moving_averages_update(&metrics->network_averages, network_rate, current_time);
    metrics->network_trend = sliding_window_trend(&metrics->network_rate_window);

    /* Update memory usage metrics */
    double memory_usage = (double)data->memory_current_bytes;
    metrics->prev_memory_bytes = data->memory_current_bytes;

    sliding_window_add(&metrics->memory_usage_window, memory_usage);
    moving_averages_update(&metrics->memory_averages, memory_usage, current_time);
    metrics->memory_trend = sliding_window_trend(&metrics->memory_usage_window);

    /* Store CPU time for totals display */
    metrics->prev_cpu_time_ns = data->cpu_time_ns;

    /* Copy syscall category data */
    memcpy(metrics->syscall_category_counts, data->syscall_category_counts,
           sizeof(metrics->syscall_category_counts));

    metrics->last_updated = current_time;
    return 0;
}

/* Process new data sample */
int realtime_processor_process_sample(const struct process_data *processes, size_t count)
{
    if (!g_processor.initialized || !g_processor.running || !processes) {
        return -EINVAL;
    }

    uint64_t start_time = get_current_time_us();
    if (start_time == 0) {
        printf("Warning: Clock function failed in process_sample\n");
        return -EFAULT; /* Clock function error */
    }
    uint64_t current_time = start_time;

    /* Estimate data size for rate limiting */
    size_t estimated_data_size = count * sizeof(struct process_data);
    if (should_rate_limit(estimated_data_size)) {
        g_processor.samples_dropped++;
        return -EAGAIN; /* Rate limited */
    }

    /* Process each process data */
    for (size_t i = 0; i < count; i++) {
        struct rt_process_metrics *metrics =
            find_or_create_process_metrics(processes[i].pid, processes[i].comm);

        if (metrics) {
            update_process_metrics(metrics, &processes[i]);
        }
    }

    /* Update statistics */
    uint64_t end_time = get_current_time_us();
    uint64_t processing_time = end_time - start_time;

    g_processor.samples_processed++;
    g_processor.total_processing_time_us += processing_time;
    g_processor.last_sample_time = current_time;

    /* Cleanup inactive processes periodically */
    if (g_processor.samples_processed % CLEANUP_INTERVAL_SAMPLES == 0) {
        cleanup_inactive_processes();
    }

    return 0;
}

/* Cleanup inactive processes */
static void cleanup_inactive_processes(void)
{
    uint64_t current_time = get_current_time_ns();
    uint64_t timeout_ns = PROCESS_TIMEOUT_SECONDS * NANOSECONDS_PER_SECOND; /* 30 seconds timeout */

    /* First pass: Mark processes as inactive and cleanup their resources */
    for (size_t i = 0; i < g_processor.process_count; i++) {
        if (g_processor.processes[i].active &&
            current_time - g_processor.processes[i].last_updated > timeout_ns) {
            /* Mark as inactive */
            g_processor.processes[i].active = false;

            /* Cleanup sliding windows */
            sliding_window_cleanup(&g_processor.processes[i].cpu_usage_window);
            sliding_window_cleanup(&g_processor.processes[i].syscall_rate_window);
            sliding_window_cleanup(&g_processor.processes[i].io_rate_window);
            sliding_window_cleanup(&g_processor.processes[i].network_rate_window);
            sliding_window_cleanup(&g_processor.processes[i].memory_usage_window);
        }
    }

    /* Second pass: Compact the array by moving active processes to the front */
    size_t write_index = 0;
    for (size_t read_index = 0; read_index < g_processor.process_count; read_index++) {
        if (g_processor.processes[read_index].active) {
            if (read_index != write_index) {
                g_processor.processes[write_index] = g_processor.processes[read_index];
            }
            write_index++;
        }
    }
    g_processor.process_count = write_index;
}

/* Get real-time metrics for a specific process */
int realtime_processor_get_process_metrics(uint32_t pid, struct rt_process_metrics *metrics)
{
    if (!g_processor.initialized || !metrics) {
        return -EINVAL;
    }

    for (size_t i = 0; i < g_processor.process_count; i++) {
        if (g_processor.processes[i].pid == pid && g_processor.processes[i].active) {
            *metrics = g_processor.processes[i];
            return 0;
        }
    }

    return -ENOENT;
}

/* Get all active real-time process metrics */
int realtime_processor_get_all_metrics(struct rt_process_metrics *metrics, size_t max_count,
                                       size_t *count)
{
    if (!g_processor.initialized || !metrics || !count) {
        return -EINVAL;
    }

    *count = 0;

    for (size_t i = 0; i < g_processor.process_count && *count < max_count; i++) {
        if (g_processor.processes[i].active) {
            metrics[*count] = g_processor.processes[i];
            (*count)++;
        }
    }

    return 0;
}

/* Get real-time metrics for container processes only */
int realtime_processor_get_container_metrics(struct rt_process_metrics *metrics, size_t max_count,
                                             size_t *count, const char *container_id)
{
    if (!g_processor.initialized || !metrics || !count) {
        return -EINVAL;
    }

    *count = 0;

    for (size_t i = 0; i < g_processor.process_count && *count < max_count; i++) {
        if (g_processor.processes[i].active && g_processor.processes[i].is_container) {
            /* If container_id is specified, filter by it; otherwise include all containers */
            if (!container_id || strncmp(g_processor.processes[i].container_id, container_id,
                                         MAX_CONTAINER_ID_LEN) == 0) {
                metrics[*count] = g_processor.processes[i];
                (*count)++;
            }
        }
    }

    return 0;
}

/* Get real-time processing statistics */
int realtime_processor_get_stats(struct realtime_stats *stats)
{
    if (!g_processor.initialized || !stats) {
        return -EINVAL;
    }

    memset(stats, 0, sizeof(*stats));

    stats->samples_processed = g_processor.samples_processed;
    stats->samples_dropped = g_processor.samples_dropped;

    if (g_processor.samples_processed > 0) {
        stats->avg_processing_time_us =
            (double)g_processor.total_processing_time_us / (double)g_processor.samples_processed;
    }

    stats->data_rate_mbps = (double)g_processor.bytes_processed_this_second / BYTES_PER_MB;

    /* Count active processes and containers */
    for (size_t i = 0; i < g_processor.process_count; i++) {
        if (g_processor.processes[i].active) {
            stats->active_processes++;
            if (g_processor.processes[i].is_container) {
                stats->active_containers++;
            }
        }
    }

    return 0;
}

/* Update configuration parameters */
int realtime_processor_update_config(size_t window_size, uint32_t rate_limit_mbps)
{
    if (!g_processor.initialized) {
        return -EINVAL;
    }

    if (window_size > 0) {
        if (window_size < MIN_WINDOW_SIZE || window_size > MAX_WINDOW_SIZE) {
            return -EINVAL;
        }
        g_processor.window_size = window_size;
    }

    if (rate_limit_mbps > 0) {
        g_processor.rate_limit_bytes_per_sec = rate_limit_mbps * BYTES_PER_MB;
    }

    return 0;
}

/* Initialize a sliding window */
int sliding_window_init(struct sliding_window *window, size_t capacity)
{
    if (!window || capacity == 0) {
        return -EINVAL;
    }

    /* Use malloc + explicit zeroing to reduce fragmentation for large allocations */
    window->values = malloc(capacity * sizeof(double));
    if (!window->values) {
        return -ENOMEM;
    }

    /* Explicitly zero the memory */
    memset(window->values, 0, capacity * sizeof(double));

    window->capacity = capacity;
    window->size = 0;
    window->index = 0;
    window->sum = 0.0;
    window->latest = 0.0;
    window->full = false;

    return 0;
}

/* Add a value to the sliding window */
int sliding_window_add(struct sliding_window *window, double value)
{
    if (!window || !window->values) {
        return -EINVAL;
    }

    /* If window is full, subtract the old value from sum */
    if (window->full) {
        window->sum -= window->values[window->index];
    }

    /* Add new value */
    window->values[window->index] = value;
    window->sum += value;
    window->latest = value;

    /* Update index and size */
    window->index = (window->index + 1) % window->capacity;

    if (!window->full) {
        window->size++;
        if (window->size == window->capacity) {
            window->full = true;
        }
    }

    return 0;
}

/* Get the current average of the sliding window */
double sliding_window_average(const struct sliding_window *window)
{
    if (!window || window->size == 0) {
        return 0.0;
    }

    return window->sum / (double)window->size;
}

/* Get the trend analysis of the sliding window */
double sliding_window_trend(const struct sliding_window *window)
{
    if (!window || window->size < 2) {
        return 0.0;
    }

    /* Simple linear regression to determine trend */
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
    size_t count = window->size;

    /* Calculate sums for linear regression */
    for (size_t i = 0; i < count; i++) {
        size_t idx;
        if (window->full) {
            /* For full circular buffer, start from oldest value */
            idx = (window->index + i) % window->capacity;
        } else {
            /* For non-full buffer, values are in order from index 0 */
            idx = i;
        }
        double x_val = (double)i;
        double y_val = window->values[idx];

        sum_x += x_val;
        sum_y += y_val;
        sum_xy += x_val * y_val;
        sum_x2 += x_val * x_val;
    }

    /* Calculate slope (trend) */
    double denominator = (double)count * sum_x2 - sum_x * sum_x;
    if (fabs(denominator) < DENOMINATOR_EPSILON) {
        return 0.0;
    }

    double slope = ((double)count * sum_xy - sum_x * sum_y) / denominator;

    /* Normalize slope to [-1, 1] range */
    double avg = sum_y / (double)count;
    if (avg > 0) {
        slope = slope / avg;
    }

    /* Clamp to [-1, 1] */
    if (slope > 1.0) {
        slope = 1.0;
    }
    if (slope < -1.0) {
        slope = -1.0;
    }

    /* Apply threshold to reduce noise */
    if (fabs(slope) < TREND_THRESHOLD) {
        slope = 0.0;
    }

    return slope;
}

/* Get the most recent value from the sliding window */
double sliding_window_latest(const struct sliding_window *window)
{
    if (!window) {
        return 0.0;
    }
    return window->latest;
}

/* Cleanup a sliding window */
void sliding_window_cleanup(struct sliding_window *window)
{
    if (window && window->values) {
        free(window->values);
        memset(window, 0, sizeof(*window));
    }
}

/* Update moving averages with new value */
int moving_averages_update(struct moving_averages *averages, double new_value,
                           uint64_t current_time)
{
    if (!averages) {
        return -EINVAL;
    }

    /* Initialize averages on first update */
    if (averages->last_update == 0) {
        averages->short_term = new_value;
        averages->medium_term = new_value;
        averages->long_term = new_value;
        averages->last_update = current_time;
        return 0;
    }

    /* Calculate time delta in seconds */
    if (current_time < averages->last_update) {
        /* Handle clock adjustments or invalid input */
        return -EINVAL;
    }
    uint64_t time_delta_ns = current_time - averages->last_update;
    double time_delta_sec = (double)time_delta_ns / NANOSECONDS_PER_SECOND;

    /* Adjust alpha based on time delta for proper exponential weighting */
    double alpha_short = 1.0 - exp(-time_delta_sec / SHORT_TERM_WINDOW_SEC);
    double alpha_medium = 1.0 - exp(-time_delta_sec / MEDIUM_TERM_WINDOW_SEC);
    double alpha_long = 1.0 - exp(-time_delta_sec / LONG_TERM_WINDOW_SEC);

    /* Update exponentially weighted moving averages */
    averages->short_term = alpha_short * new_value + (1.0 - alpha_short) * averages->short_term;
    averages->medium_term = alpha_medium * new_value + (1.0 - alpha_medium) * averages->medium_term;
    averages->long_term = alpha_long * new_value + (1.0 - alpha_long) * averages->long_term;

    averages->last_update = current_time;
    return 0;
}
