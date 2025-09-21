/* HPMon Real-time Processing Engine Header
 *
 * This header defines the interface for real-time data processing,
 * including sliding window analysis, moving averages, and data rate limiting.
 */

#ifndef REALTIME_H
#define REALTIME_H

#include "bpf_common.h"
#include "data_collector.h"
#include "hpmon.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Real-time processing configuration */
#define DEFAULT_WINDOW_SIZE 10   /* Default sliding window size */
#define MAX_WINDOW_SIZE 100      /* Maximum sliding window size */
#define MIN_WINDOW_SIZE 2        /* Minimum sliding window size */
#define DEFAULT_RATE_LIMIT_MB 10 /* Default data rate limit in MB/s */
#define MICROSECONDS_PER_SECOND 1000000ULL

/* Sliding window data structure for a single metric */
struct sliding_window {
    double *values;  /* Array of values in the window */
    size_t size;     /* Current number of values */
    size_t capacity; /* Maximum window size */
    size_t index;    /* Current write index (circular buffer) */
    double sum;      /* Running sum for quick average calculation */
    double latest;   /* Most recently added value */
    bool full;       /* Whether window is full */
};

/* Moving averages for different time periods */
struct moving_averages {
    double short_term;    /* 1-minute average */
    double medium_term;   /* 5-minute average */
    double long_term;     /* 15-minute average */
    uint64_t last_update; /* Last update timestamp */
};

/* Process metrics with real-time analysis */
struct rt_process_metrics {
    /* Double and 64-bit fields first for optimal alignment */
    double cpu_trend; /* Trend analysis (-1.0 to 1.0) */
    double syscall_trend;
    double io_trend;
    double network_trend; /* Network activity trend */
    double memory_trend;  /* Memory usage trend */
    uint64_t first_seen;
    uint64_t last_updated;
    uint64_t prev_syscall_count; /* Previous syscall count for rate calculation */
    uint64_t prev_io_bytes;      /* Previous I/O bytes for rate calculation */
    uint64_t prev_network_bytes; /* Previous network bytes for rate calculation */
    uint64_t prev_memory_bytes;  /* Previous memory usage for rate calculation */
    uint64_t prev_cpu_time_ns;   /* Previous CPU time for rate calculation */

    /* Syscall category data */
    struct {
        uint64_t count;
        uint64_t total_latency_ns;
    } syscall_category_counts[SYSCALL_CAT_MAX];

    /* Struct fields */
    struct sliding_window cpu_usage_window;
    struct sliding_window syscall_rate_window;
    struct sliding_window io_rate_window;
    struct sliding_window network_rate_window; /* Network activity sliding window */
    struct sliding_window memory_usage_window; /* Memory usage sliding window */
    struct moving_averages cpu_averages;
    struct moving_averages syscall_averages;
    struct moving_averages io_averages;
    struct moving_averages network_averages; /* Network activity moving averages */
    struct moving_averages memory_averages;  /* Memory usage moving averages */

    /* 32-bit fields */
    uint32_t pid;

    /* Boolean fields */
    bool active;
    bool is_container;

    /* Character arrays at the end */
    char comm[MAX_COMM_LEN];
    char container_id[MAX_CONTAINER_ID_LEN];
};

/* Real-time processing engine state */
struct realtime_processor {
    struct rt_process_metrics *processes;
    size_t process_count;
    size_t max_processes;

    /* Configuration */
    size_t window_size; /* Sliding window size */
    uint32_t rate_limit_bytes_per_sec;

    /* Rate limiting state */
    uint64_t last_process_time;
    uint64_t bytes_processed_this_second;
    uint64_t current_second;

    /* Processing statistics */
    uint64_t samples_processed;
    uint64_t samples_dropped;
    uint64_t total_processing_time_us;
    uint64_t last_sample_time;

    bool initialized;
    bool running;
};

/* Real-time processing statistics */
struct realtime_stats {
    uint64_t samples_processed;
    uint64_t samples_dropped;
    uint64_t rate_limited_events;
    double avg_processing_time_us;
    double data_rate_mbps;
    uint64_t active_processes;
    uint64_t active_containers; /* Number of active container processes */
};

/* Function declarations */

/**
 * Initialize the real-time processor
 * @param config: HPMon configuration
 * @param window_size: Sliding window size for analysis
 * @param rate_limit_mbps: Data rate limit in MB/s
 * @returns 0 on success, negative on error
 */
int realtime_processor_init(const struct hpmon_config *config, size_t window_size,
                            uint32_t rate_limit_mbps);

/**
 * Start real-time processing
 * @returns 0 on success, negative on error
 */
int realtime_processor_start(void);

/**
 * Stop real-time processing
 * @returns 0 on success, negative on error
 */
int realtime_processor_stop(void);

/**
 * Cleanup real-time processor
 */
void realtime_processor_cleanup(void);

/**
 * Process new data sample
 * @param processes: Array of process data from data collector
 * @param count: Number of processes
 * @returns 0 on success, negative on error
 */
int realtime_processor_process_sample(const struct process_data *processes, size_t count);

/**
 * Get real-time metrics for a specific process
 * @param pid: Process ID
 * @param metrics: Output real-time metrics
 * @returns 0 on success, negative if not found
 */
int realtime_processor_get_process_metrics(uint32_t pid, struct rt_process_metrics *metrics);

/**
 * Get all active real-time process metrics
 * @param metrics: Array to store metrics
 * @param max_count: Maximum number of metrics to return
 * @param count: Pointer to store actual count returned
 * @returns 0 on success, negative on error
 */
int realtime_processor_get_all_metrics(struct rt_process_metrics *metrics, size_t max_count,
                                       size_t *count);

/**
 * Get real-time metrics for container processes only
 * @param metrics: Array to store metrics
 * @param max_count: Maximum number of metrics to return
 * @param count: Pointer to store actual count returned
 * @param container_id: Container ID to filter by (NULL for all containers)
 * @returns 0 on success, negative on error
 */
int realtime_processor_get_container_metrics(struct rt_process_metrics *metrics, size_t max_count,
                                             size_t *count, const char *container_id);

/**
 * Get real-time processing statistics
 * @param stats: Statistics structure to fill
 * @returns 0 on success, negative on error
 */
int realtime_processor_get_stats(struct realtime_stats *stats);

/**
 * Update configuration parameters
 * @param window_size: New sliding window size (0 to keep current)
 * @param rate_limit_mbps: New rate limit in MB/s (0 to keep current)
 * @returns 0 on success, negative on error
 */
int realtime_processor_update_config(size_t window_size, uint32_t rate_limit_mbps);

/* Utility functions for sliding window analysis */

/**
 * Initialize a sliding window
 * @param window: Window structure to initialize
 * @param capacity: Maximum window size
 * @returns 0 on success, negative on error
 */
int sliding_window_init(struct sliding_window *window, size_t capacity);

/**
 * Add a value to the sliding window
 * @param window: Window structure
 * @param value: Value to add
 * @returns 0 on success, negative on error
 */
int sliding_window_add(struct sliding_window *window, double value);

/**
 * Get the current average of the sliding window
 * @param window: Window structure
 * @returns Average value, or 0.0 if window is empty
 */
double sliding_window_average(const struct sliding_window *window);

/**
 * Get the trend analysis of the sliding window
 * @param window: Window structure
 * @returns Trend value (-1.0 = decreasing, 0.0 = stable, 1.0 = increasing)
 */
double sliding_window_trend(const struct sliding_window *window);

/**
 * Get the most recent value from the sliding window
 * @param window: Window structure
 * @returns Most recent value, or 0.0 if window is empty
 */
double sliding_window_latest(const struct sliding_window *window);

/**
 * Cleanup a sliding window
 * @param window: Window structure to cleanup
 */
void sliding_window_cleanup(struct sliding_window *window);

/**
 * Update moving averages with new value
 * @param averages: Moving averages structure
 * @param new_value: New value to incorporate
 * @param current_time: Current timestamp in nanoseconds
 * @returns 0 on success, negative on error
 */
int moving_averages_update(struct moving_averages *averages, double new_value,
                           uint64_t current_time);

#endif /* REALTIME_H */
