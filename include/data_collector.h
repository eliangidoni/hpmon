/* HPMon Data Collection Engine Header
 *
 * This header defines the interface for collecting data from eBPF maps
 * and aggregating it for analysis and presentation.
 */

#ifndef DATA_COLLECTOR_H
#define DATA_COLLECTOR_H

#include "bpf_common.h"
#include "hpmon.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Maximum number of processes to track */
#define MAX_TRACKED_PROCESSES 1000

/* Thresholds for high activity detection */
#define HIGH_IO_THRESHOLD_BYTES (10 * 1024 * 1024)      /* 10MB */
#define HIGH_NETWORK_THRESHOLD_BYTES (5 * 1024 * 1024)  /* 5MB */
#define HIGH_MEMORY_THRESHOLD_BYTES (100 * 1024 * 1024) /* 100MB */

/* Process data aggregation */
struct process_data {
    /* 64-bit fields first for optimal alignment */
    uint64_t cpu_time_ns;
    uint64_t last_cpu_time;
    uint64_t syscall_count;
    uint64_t syscall_latency_total_ns;
    uint64_t io_read_bytes;
    uint64_t io_write_bytes;
    uint64_t io_read_ops;
    uint64_t io_write_ops;
    uint64_t io_latency_total_ns;
    uint64_t memory_alloc_bytes;
    uint64_t memory_free_bytes;
    uint64_t memory_current_bytes;
    uint64_t memory_peak_bytes;
    uint64_t memory_page_faults;
    uint64_t network_rx_bytes;
    uint64_t network_tx_bytes;
    uint64_t network_rx_packets;
    uint64_t network_tx_packets;
    uint64_t network_tcp_connections;
    uint64_t network_udp_packets;
    uint64_t network_rx_latency_total_ns;
    uint64_t network_tx_latency_total_ns;
    uint64_t last_network_rx_bytes;
    uint64_t last_network_tx_bytes;
    uint64_t last_memory_alloc_bytes;
    uint64_t first_seen;
    uint64_t last_updated;

    struct {
        uint64_t count;
        uint64_t total_latency_ns;
    } syscall_category_counts[SYSCALL_CAT_MAX];

    /* 32-bit fields grouped together */
    uint32_t pid;
    uint32_t cpu_usage_percent;
    uint32_t most_frequent_syscall;
    uint32_t network_rx_rate_mbps;
    uint32_t network_tx_rate_mbps;
    uint32_t memory_alloc_rate_mbps;

    /* Boolean fields grouped together */
    bool is_container;
    bool active;

    /* Character arrays at the end */
    char comm[MAX_COMM_LEN];
    char container_id[MAX_CONTAINER_ID_LEN];
};

/* Data collector state */
struct data_collector {
    struct process_data processes[MAX_TRACKED_PROCESSES];
    int process_count;
    bool initialized;
    bool collecting;

    /* Collection statistics */
    uint64_t collections_performed;
    uint64_t total_processes_seen;
    uint64_t last_collection_time;
};

/* Collection statistics */
struct collection_stats {
    uint64_t active_processes;
    uint64_t total_processes;
    uint64_t container_processes;
    uint64_t high_cpu_processes;
    uint64_t high_io_processes;
    uint64_t high_network_processes;
    uint64_t high_memory_processes;
    uint64_t total_syscalls;
    uint64_t total_io_bytes;
    uint64_t total_network_bytes;
    uint64_t total_memory_bytes;
    uint64_t collections_performed;
    uint64_t last_collection_duration_us;
};

/* Function declarations */

/**
 * Initialize the data collector
 * @param config: HPMon configuration
 * @returns 0 on success, negative on error
 */
int data_collector_init(const struct hpmon_config *config);

/**
 * Start data collection
 * @returns 0 on success, negative on error
 */
int data_collector_start(void);

/**
 * Get current time in nanoseconds
 * @returns Current time in nanoseconds
 */
uint64_t get_current_time_ns(void);

/**
 * Stop data collection
 * @returns 0 on success, negative on error
 */
int data_collector_stop(void);

/**
 * Cleanup data collector
 */
void data_collector_cleanup(void);

/**
 * Perform one collection cycle
 * @returns 0 on success, negative on error
 */
int data_collector_collect(void);

/**
 * Get process data by PID
 * @param pid: Process ID
 * @param data: Output process data
 * @returns 0 on success, negative if not found
 */
int data_collector_get_process(uint32_t pid, struct process_data *data);

/**
 * Get all active processes
 * @param processes: Output array of process data
 * @param max_processes: Maximum number of processes to return
 * @param count: Output number of processes returned
 * @returns 0 on success, negative on error
 */
int data_collector_get_processes(struct process_data *processes, size_t max_processes,
                                 size_t *count);

/**
 * Get collection statistics
 * @param stats: Output statistics
 * @returns 0 on success, negative on error
 */
int data_collector_get_stats(struct collection_stats *stats);

/**
 * Clear old/inactive process data
 * @param max_age_ms: Maximum age for inactive processes
 * @returns Number of processes removed
 */
int data_collector_cleanup_old_processes(uint32_t max_age_ms);

#endif /* DATA_COLLECTOR_H */
