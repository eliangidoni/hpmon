// SPDX-License-Identifier: MIT
/* HPMon Data Collection Engine
 *
 * This module implements efficient data collection from eBPF maps,
 * data aggregation, and memory management for collected data.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "data_collector.h"
#include "bpf_manager.h"
#include "container_tracker.h"
#include "safe_string.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <math.h>
#include <stddef.h> /* For size_t */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Constants for magic numbers */
#define CLEANUP_FREQUENCY 100                      /* Cleanup every N collections */
#define DEFAULT_CLEANUP_AGE_MS 30000               /* 30 seconds */
#define MAX_COLLECTION_ERRORS 5                    /* Maximum errors before complete failure */
#define MEGABYTES_PER_SECOND_DIVISOR (1024 * 1024) /* 1024 * 1024 for MB conversion */
#define MEGABYTES_DIVISOR_FLOAT 1024.0             /* 1024.0 for floating point MB conversion */
#define NANOSECONDS_PER_MILLISECOND 1000000ULL     /* Convert ms to ns */
#define NANOSECONDS_PER_SECOND 1000000000ULL       /* Convert seconds to ns */
#define PERCENTAGE_MULTIPLIER 100                  /* For percentage calculations */
#define MAX_CPUS_FOR_PERCENTAGE 128                /* Maximum CPUs for percentage calculation */
#define MEGABYTE_THRESHOLD (1024U * 1024U)         /* 1MB threshold for I/O */
#define PROC_COMM_PATH_SIZE 256                    /* Size for /proc path buffer */
#define MAX_NETWORK_RATE_MBPS 200000               /* 200 Gbps cap - covers high-end InfiniBand */
#define MAX_MEMORY_RATE_MBPS 100000 /* 100 GB/s cap - covers DDR5 and high-end systems */
#define BITS_PER_BYTE 8             /* Convert bytes to bits */
#define MAX_CPUS 128                /* Maximum number of CPUs to handle */
#define PROC_PATH_BUFFER_SIZE 64

/* Global data collector state */
static struct data_collector g_collector = {0};

/* Helper functions */
static uint64_t get_current_time_ns(void);
static int collect_cpu_data(void);
static int collect_syscall_data(void);
static int collect_io_data(void);
static int collect_memory_data(void);
static int collect_network_data(void);
static struct process_data *find_or_create_process(uint32_t pid);
static void update_process_container_info(struct process_data *proc);
static void calculate_cpu_percentage(struct process_data *proc, uint64_t current_time_ns);
static void calculate_network_rates(struct process_data *proc, uint64_t current_time_ns);
static void calculate_memory_allocation_rate(struct process_data *proc, uint64_t current_time_ns);

/* Initialize data collector */
int data_collector_init(const struct hpmon_config *config)
{
    if (!config) {
        return -EINVAL;
    }

    if (g_collector.initialized) {
        return -EALREADY;
    }

    /* Initialize collector state */
    memset(&g_collector, 0, sizeof(g_collector));
    g_collector.process_count = 0;
    g_collector.collecting = false;
    g_collector.collections_performed = 0;
    g_collector.total_processes_seen = 0;

    printf("Data Collector: Initialized\n");

    g_collector.initialized = true;

    return 0;
}

/* Start data collection */
int data_collector_start(void)
{
    if (!g_collector.initialized) {
        return -EINVAL;
    }

    if (g_collector.collecting) {
        return -EALREADY;
    }

    printf("Data Collector: Starting data collection...\n");
    g_collector.collecting = true;
    g_collector.last_collection_time = get_current_time_ns();

    return 0;
}

/* Stop data collection */
int data_collector_stop(void)
{
    if (!g_collector.initialized || !g_collector.collecting) {
        return -EINVAL;
    }

    printf("Data Collector: Stopping data collection...\n");
    g_collector.collecting = false;

    return 0;
}

/* Cleanup data collector */
void data_collector_cleanup(void)
{
    if (!g_collector.initialized) {
        return;
    }

    if (g_collector.collecting) {
        g_collector.collecting = false;
    }

    printf("Data Collector: Cleanup complete\n");
    memset(&g_collector, 0, sizeof(g_collector));
}

/* Perform one collection cycle */
int data_collector_collect(void)
{
    uint64_t start_time, end_time;
    int ret = 0;
    int error_count = 0;

    if (!g_collector.initialized || !g_collector.collecting) {
        return -EINVAL;
    }

    start_time = get_current_time_ns();

    /* Collect data from different eBPF maps */
    ret = collect_cpu_data();
    if (ret != 0 && ret != -ENOENT) {
        printf("Warning: Failed to collect CPU data: %s\n", strerror(-ret));
        error_count++;
    }

    ret = collect_syscall_data();
    if (ret != 0 && ret != -ENOENT) {
        printf("Warning: Failed to collect syscall data: %s\n", strerror(-ret));
        error_count++;
    }

    ret = collect_io_data();
    if (ret != 0 && ret != -ENOENT) {
        printf("Warning: Failed to collect I/O data: %s\n", strerror(-ret));
        error_count++;
    }

    ret = collect_memory_data();
    if (ret != 0 && ret != -ENOENT) {
        printf("Warning: Failed to collect memory data: %s\n", strerror(-ret));
        error_count++;
    }

    ret = collect_network_data();
    if (ret != 0 && ret != -ENOENT) {
        printf("Warning: Failed to collect network data: %s\n", strerror(-ret));
        error_count++;
    }

    /* Update timestamps and counters */
    end_time = get_current_time_ns();
    g_collector.last_collection_time = end_time;
    g_collector.collections_performed++;

    /* Suppress unused variable warning */
    (void)start_time;

    int should_cleanup = (g_collector.collections_performed % CLEANUP_FREQUENCY) == 0;
    if (should_cleanup) {
        data_collector_cleanup_old_processes(DEFAULT_CLEANUP_AGE_MS); /* 30 seconds */
    }

    /* Return appropriate error code based on collection failures */
    if (error_count == MAX_COLLECTION_ERRORS) {
        return -EIO; /* All collections failed */
    }
    if (error_count > 0) {
        return -EAGAIN; /* Partial failure */
    }

    return 0;
}

/* Get process data by PID */
int data_collector_get_process(uint32_t pid, struct process_data *data)
{
    if (!data) {
        return -EINVAL;
    }

    if (!g_collector.initialized) {
        return -EINVAL;
    }

    for (int i = 0; i < g_collector.process_count; i++) {
        if (g_collector.processes[i].pid == pid && g_collector.processes[i].active) {
            *data = g_collector.processes[i];
            return 0;
        }
    }
    return -ENOENT;
}

/* Get all active processes */
int data_collector_get_processes(struct process_data *processes, size_t max_processes,
                                 size_t *count)
{
    if (!processes || !count) {
        return -EINVAL;
    }

    if (!g_collector.initialized) {
        return -EINVAL;
    }

    *count = 0;

    for (int i = 0; i < g_collector.process_count && *count < max_processes; i++) {
        if (g_collector.processes[i].active) {
            processes[*count] = g_collector.processes[i];
            (*count)++;
        }
    }

    return 0;
}

/* Get collection statistics */
int data_collector_get_stats(struct collection_stats *stats)
{
    if (!stats) {
        return -EINVAL;
    }

    if (!g_collector.initialized) {
        return -EINVAL;
    }

    memset(stats, 0, sizeof(*stats));

    /* Count different types of processes */
    for (int i = 0; i < g_collector.process_count; i++) {
        struct process_data *proc = &g_collector.processes[i];

        if (!proc->active) {
            continue;
        }

        stats->active_processes++;

        if (proc->is_container) {
            stats->container_processes++;
        }

        if (proc->cpu_usage_percent > (uint32_t)HIGH_CPU_THRESHOLD) {
            stats->high_cpu_processes++;
        }

        if (proc->io_read_bytes + proc->io_write_bytes > (uint64_t)HIGH_IO_THRESHOLD_BYTES) {
            stats->high_io_processes++;
        }

        if (proc->network_rx_bytes + proc->network_tx_bytes >
            (uint64_t)HIGH_NETWORK_THRESHOLD_BYTES) {
            stats->high_network_processes++;
        }

        if (proc->memory_current_bytes > (uint64_t)HIGH_MEMORY_THRESHOLD_BYTES) {
            stats->high_memory_processes++;
        }

        stats->total_syscalls += proc->syscall_count;
        stats->total_io_bytes += proc->io_read_bytes + proc->io_write_bytes;
        stats->total_network_bytes += proc->network_rx_bytes + proc->network_tx_bytes;
        stats->total_memory_bytes += proc->memory_current_bytes;
    }

    stats->total_processes = g_collector.total_processes_seen;
    stats->collections_performed = g_collector.collections_performed;

    return 0;
}

/* Clear old/inactive process data
 * This function marks old processes as inactive and then compacts the array
 * to keep all active processes at the beginning [0, process_count) */
int data_collector_cleanup_old_processes(uint32_t max_age_ms)
{
    uint64_t current_time = get_current_time_ns();
    uint64_t max_age_ns =
        (uint64_t)max_age_ms * NANOSECONDS_PER_MILLISECOND; /* Convert to nanoseconds */
    int removed = 0;

    if (max_age_ms == 0) {
        return -EINVAL;
    }

    if (!g_collector.initialized) {
        return -EINVAL;
    }

    /* First pass: mark old processes as inactive */
    for (int i = 0; i < g_collector.process_count; i++) {
        struct process_data *proc = &g_collector.processes[i];

        if (proc->active && (current_time - proc->last_updated) > max_age_ns) {
            proc->active = false;
            removed++;
        }
    }

    /* Second pass: compact the array by removing inactive processes */
    int write_index = 0;
    for (int read_index = 0; read_index < g_collector.process_count; read_index++) {
        if (g_collector.processes[read_index].active) {
            if (write_index != read_index) {
                g_collector.processes[write_index] = g_collector.processes[read_index];
            }
            write_index++;
        }
    }

    /* Update process count to reflect compacted array */
    g_collector.process_count = write_index;

    return removed;
}

/* Helper function to get current time in nanoseconds */
static uint64_t get_current_time_ns(void)
{
    struct timespec time_spec;
    clock_gettime(CLOCK_MONOTONIC, &time_spec);
    return (uint64_t)time_spec.tv_sec * NANOSECONDS_PER_SECOND + (uint64_t)time_spec.tv_nsec;
}

/* Collect CPU data from eBPF maps */
static int collect_cpu_data(void)
{
    int map_fd;
    struct cpu_key key = {0}, next_key;
    struct cpu_stats stats[MAX_CPUS]; /* Array for per-CPU values */
    int ret;
    int nr_cpus;

    /* Get number of possible CPUs */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs: %s\n", strerror(-nr_cpus));
        return nr_cpus;
    }
    if (nr_cpus > MAX_CPUS) {
        fprintf(stderr, "Too many CPUs (%d), limiting to %d\n", nr_cpus, MAX_CPUS);
        nr_cpus = MAX_CPUS;
    }

    /* Get CPU stats map file descriptor */
    map_fd = bpf_manager_get_map_fd("cpu_monitor", "cpu_stats_map");
    if (map_fd < 0) {
        return map_fd; /* Return error or -ENOENT */
    }

    /* Validate map file descriptor */
    if (map_fd <= 0) {
        return -EBADF;
    }

    /* Iterate through all entries in the map */
    ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0) {
        /* Read the per-CPU stats for this key */
        if (bpf_map_lookup_elem(map_fd, &key, stats) == 0) {
            /* Check if process still exists before updating */
            char proc_path[PROC_PATH_BUFFER_SIZE];
            snprintf(proc_path, sizeof(proc_path), "/proc/%u", key.pid);

            if (access(proc_path, F_OK) == 0) {
                struct process_data *proc = find_or_create_process(key.pid);
                if (proc) {
                    uint64_t current_time = get_current_time_ns();

                    /* Aggregate per-CPU statistics */
                    struct cpu_stats aggregated = {0};
                    for (int cpu = 0; cpu < nr_cpus; cpu++) {
                        aggregated.cpu_time_ns += stats[cpu].cpu_time_ns;
                        aggregated.user_time_ns += stats[cpu].user_time_ns;
                        aggregated.sys_time_ns += stats[cpu].sys_time_ns;
                        /* Use the most recent timestamp */
                        if (stats[cpu].timestamp > aggregated.timestamp) {
                            aggregated.timestamp = stats[cpu].timestamp;
                        }
                    }
                    aggregated.pid = key.pid;

                    /* Update CPU metrics */
                    proc->cpu_time_ns = aggregated.cpu_time_ns;
                    calculate_cpu_percentage(proc, current_time);
                    proc->last_updated = current_time;
                    proc->active = true;

                    /* Update container information */
                    update_process_container_info(proc);
                }
            }
        }

        /* Get next key */
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
            break;
        }
        key = next_key;
    }

    return 0;
}

/* Collect syscall data from eBPF maps */
static int collect_syscall_data(void)
{
    int map_fd;
    struct syscall_key key = {0}, next_key;
    struct syscall_stats stats[MAX_CPUS]; /* Array for per-CPU values */
    int ret;
    int nr_cpus;

    /* Get syscall stats map file descriptor */
    map_fd = bpf_manager_get_map_fd("syscall_monitor", "syscall_stats_map");
    if (map_fd < 0) {
        return map_fd; /* Return error or -ENOENT */
    }

    /* Validate map file descriptor */
    if (map_fd <= 0) {
        return -EBADF;
    }

    /* Get number of possible CPUs */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs: %s\n", strerror(-nr_cpus));
        return nr_cpus;
    }
    if (nr_cpus > MAX_CPUS) {
        nr_cpus = MAX_CPUS;
    }

    /* Track per-PID aggregated statistics to avoid resetting on each syscall type */
    struct {
        uint64_t total_count;
        uint64_t total_latency_ns;
        uint64_t max_syscall_count;
        uint32_t pid;
        uint32_t most_frequent_syscall;
        struct {
            uint64_t count;
            uint64_t total_latency_ns;
        } syscall_category_counts[SYSCALL_CAT_MAX];
        bool updated;
    } pid_stats[MAX_TRACKED_PROCESSES] = {0};
    int pid_count = 0;

    /* Iterate through all entries in the map */
    ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0) {
        /* Read the per-CPU stats for this key */
        if (bpf_map_lookup_elem(map_fd, &key, stats) == 0) {
            /* Check if process still exists before updating */
            char proc_path[PROC_PATH_BUFFER_SIZE];
            snprintf(proc_path, sizeof(proc_path), "/proc/%u", key.pid);

            if (access(proc_path, F_OK) == 0) {
                /* Aggregate per-CPU statistics for this syscall type */
                struct syscall_stats aggregated = {0};
                for (int cpu = 0; cpu < nr_cpus; cpu++) {
                    aggregated.count += stats[cpu].count;
                    aggregated.total_latency_ns += stats[cpu].total_latency_ns;

                    /* Track min/max latency across all CPUs */
                    if (stats[cpu].min_latency_ns > 0) {
                        if (aggregated.min_latency_ns == 0 ||
                            stats[cpu].min_latency_ns < aggregated.min_latency_ns) {
                            aggregated.min_latency_ns = stats[cpu].min_latency_ns;
                        }
                    }
                    if (stats[cpu].max_latency_ns > aggregated.max_latency_ns) {
                        aggregated.max_latency_ns = stats[cpu].max_latency_ns;
                    }

                    /* Use the most recent timestamp */
                    if (stats[cpu].timestamp > aggregated.timestamp) {
                        aggregated.timestamp = stats[cpu].timestamp;
                    }

                    /* Get category from the first non-zero entry (all should be the same for same
                     * syscall) */
                    if (aggregated.category == 0 && stats[cpu].category != 0) {
                        aggregated.category = stats[cpu].category;
                    }
                }

                /* Find or create entry in pid_stats for this PID */
                int pid_idx = -1;
                for (int i = 0; i < pid_count; i++) {
                    if (pid_stats[i].pid == key.pid) {
                        pid_idx = i;
                        break;
                    }
                }
                if (pid_idx == -1 && pid_count < MAX_TRACKED_PROCESSES) {
                    pid_idx = pid_count++;
                    pid_stats[pid_idx].pid = key.pid;
                }

                if (pid_idx >= 0) {
                    /* Accumulate total syscall statistics for this PID */
                    pid_stats[pid_idx].total_count += aggregated.count;
                    pid_stats[pid_idx].total_latency_ns += aggregated.total_latency_ns;
                    pid_stats[pid_idx].updated = true;

                    /* Accumulate category-specific statistics using the category from eBPF */
                    pid_stats[pid_idx].syscall_category_counts[aggregated.category].count +=
                        aggregated.count;
                    pid_stats[pid_idx]
                        .syscall_category_counts[aggregated.category]
                        .total_latency_ns += aggregated.total_latency_ns;

                    /* Track most frequent syscall (the one with highest count for this iteration)
                     */
                    if (aggregated.count > pid_stats[pid_idx].max_syscall_count) {
                        pid_stats[pid_idx].max_syscall_count = aggregated.count;
                        pid_stats[pid_idx].most_frequent_syscall = key.syscall_nr;
                    }
                }
            }
        }

        /* Get next key */
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
            break;
        }
        key = next_key;
    }

    /* Now update process data with aggregated per-PID statistics */
    uint64_t current_time = get_current_time_ns();
    for (int i = 0; i < pid_count; i++) {
        if (pid_stats[i].updated) {
            struct process_data *proc = find_or_create_process(pid_stats[i].pid);
            if (proc) {
                /* Update syscall metrics - eBPF maps contain cumulative counts, so set directly */
                proc->syscall_count = pid_stats[i].total_count;
                memcpy(proc->syscall_category_counts, pid_stats[i].syscall_category_counts,
                       sizeof(proc->syscall_category_counts));
                proc->syscall_latency_total_ns = pid_stats[i].total_latency_ns;
                proc->most_frequent_syscall = pid_stats[i].most_frequent_syscall;
                proc->last_updated = current_time;
                proc->active = true;
            }
        }
    }

    return 0;
}

/* Collect I/O data from eBPF maps */
static int collect_io_data(void)
{
    int map_fd;
    struct io_key key = {0}, next_key;
    struct io_stats stats[MAX_CPUS]; /* Array for per-CPU values */
    int ret;
    int nr_cpus;

    /* Get number of possible CPUs */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs: %s\n", strerror(-nr_cpus));
        return nr_cpus;
    }
    if (nr_cpus > MAX_CPUS) {
        fprintf(stderr, "Too many CPUs (%d), limiting to %d\n", nr_cpus, MAX_CPUS);
        nr_cpus = MAX_CPUS;
    }

    /* Get I/O stats map file descriptor */
    map_fd = bpf_manager_get_map_fd("io_monitor", "io_stats_map");
    if (map_fd < 0) {
        return map_fd; /* Return error or -ENOENT */
    }

    /* Validate map file descriptor */
    if (map_fd <= 0) {
        return -EBADF;
    }

    /* Iterate through all entries in the map */
    ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0) {
        /* Read the per-CPU stats for this key */
        if (bpf_map_lookup_elem(map_fd, &key, stats) == 0) {
            /* Check if process still exists before updating */
            char proc_path[PROC_PATH_BUFFER_SIZE];
            snprintf(proc_path, sizeof(proc_path), "/proc/%u", key.pid);

            if (access(proc_path, F_OK) == 0) {
                struct process_data *proc = find_or_create_process(key.pid);
                if (proc) {
                    /* Aggregate per-CPU statistics */
                    struct io_stats aggregated = {0};
                    for (int cpu = 0; cpu < nr_cpus; cpu++) {
                        aggregated.read_bytes += stats[cpu].read_bytes;
                        aggregated.write_bytes += stats[cpu].write_bytes;
                        aggregated.read_ops += stats[cpu].read_ops;
                        aggregated.write_ops += stats[cpu].write_ops;
                        aggregated.read_latency_ns += stats[cpu].read_latency_ns;
                        aggregated.write_latency_ns += stats[cpu].write_latency_ns;

                        /* Use the most recent timestamp */
                        if (stats[cpu].timestamp > aggregated.timestamp) {
                            aggregated.timestamp = stats[cpu].timestamp;
                        }
                    }
                    aggregated.pid = key.pid;

                    /* Update I/O metrics */
                    proc->io_read_bytes = aggregated.read_bytes;
                    proc->io_write_bytes = aggregated.write_bytes;
                    proc->io_read_ops = aggregated.read_ops;
                    proc->io_write_ops = aggregated.write_ops;
                    proc->io_latency_total_ns =
                        aggregated.read_latency_ns + aggregated.write_latency_ns;
                    proc->last_updated = get_current_time_ns();
                    proc->active = true;
                }
            }
        }

        /* Get next key */
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
            break;
        }
        key = next_key;
    }

    return 0;
}

/* Collect memory data from eBPF map */
static int collect_memory_data(void)
{
    int map_fd;
    struct memory_key key = {0}, next_key;
    struct memory_stats stats[MAX_CPUS]; /* Array for per-CPU values */
    int ret;
    int nr_cpus;

    /* Get number of possible CPUs */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs: %s\n", strerror(-nr_cpus));
        return nr_cpus;
    }
    if (nr_cpus > MAX_CPUS) {
        fprintf(stderr, "Too many CPUs (%d), limiting to %d\n", nr_cpus, MAX_CPUS);
        nr_cpus = MAX_CPUS;
    }

    /* Get memory stats map file descriptor */
    map_fd = bpf_manager_get_map_fd("memory_monitor", "memory_stats_map");
    if (map_fd < 0) {
        return map_fd; /* Return error or -ENOENT */
    }

    /* Validate map file descriptor */
    if (map_fd <= 0) {
        return -EBADF;
    }

    /* Iterate through all entries in the map */
    ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0) {
        /* Read the per-CPU stats for this key */
        if (bpf_map_lookup_elem(map_fd, &key, stats) == 0) {
            /* Check if process still exists before updating */
            char proc_path[PROC_PATH_BUFFER_SIZE];
            snprintf(proc_path, sizeof(proc_path), "/proc/%u", key.pid);

            if (access(proc_path, F_OK) == 0) {
                struct process_data *proc = find_or_create_process(key.pid);
                if (proc) {
                    uint64_t current_time = get_current_time_ns();

                    /* Aggregate per-CPU statistics */
                    struct memory_stats aggregated = {0};
                    for (int cpu = 0; cpu < nr_cpus; cpu++) {
                        aggregated.alloc_count += stats[cpu].alloc_count;
                        aggregated.free_count += stats[cpu].free_count;
                        aggregated.mmap_count += stats[cpu].mmap_count;
                        aggregated.munmap_count += stats[cpu].munmap_count;
                        aggregated.alloc_bytes += stats[cpu].alloc_bytes;
                        aggregated.free_bytes += stats[cpu].free_bytes;
                        aggregated.mmap_bytes += stats[cpu].mmap_bytes;
                        aggregated.munmap_bytes += stats[cpu].munmap_bytes;
                        aggregated.current_alloc_bytes += stats[cpu].current_alloc_bytes;
                        aggregated.current_mmap_bytes += stats[cpu].current_mmap_bytes;
                        aggregated.page_faults += stats[cpu].page_faults;
                        aggregated.alloc_latency_ns += stats[cpu].alloc_latency_ns;

                        /* Peak memory is the maximum across all CPUs */
                        if (stats[cpu].peak_memory_bytes > aggregated.peak_memory_bytes) {
                            aggregated.peak_memory_bytes = stats[cpu].peak_memory_bytes;
                        }

                        /* Use the most recent timestamp */
                        if (stats[cpu].timestamp > aggregated.timestamp) {
                            aggregated.timestamp = stats[cpu].timestamp;
                        }
                    }

                    /* Update memory metrics with aggregated values */
                    proc->memory_alloc_bytes = aggregated.alloc_bytes;
                    proc->memory_free_bytes = aggregated.free_bytes;
                    proc->memory_current_bytes =
                        aggregated.current_alloc_bytes + aggregated.current_mmap_bytes;
                    proc->memory_peak_bytes = aggregated.peak_memory_bytes;
                    proc->memory_page_faults = aggregated.page_faults;

                    /* Calculate memory allocation rate */
                    calculate_memory_allocation_rate(proc, current_time);

                    proc->last_updated = current_time;
                    proc->active = true;
                }
            }
        }

        /* Get next key */
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
            break;
        }
        key = next_key;
    }

    return 0;
}

/* Collect network data from eBPF map */
static int collect_network_data(void)
{
    int map_fd;
    struct network_key key = {0}, next_key;
    struct network_stats stats[MAX_CPUS]; /* Array for per-CPU values */
    int ret;
    int nr_cpus;

    /* Get number of possible CPUs */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs: %s\n", strerror(-nr_cpus));
        return nr_cpus;
    }
    if (nr_cpus > MAX_CPUS) {
        fprintf(stderr, "Too many CPUs (%d), limiting to %d\n", nr_cpus, MAX_CPUS);
        nr_cpus = MAX_CPUS;
    }

    /* Get network stats map file descriptor */
    map_fd = bpf_manager_get_map_fd("network_monitor", "network_stats_map");
    if (map_fd < 0) {
        return map_fd; /* Return error or -ENOENT */
    }

    /* Validate map file descriptor */
    if (map_fd <= 0) {
        return -EBADF;
    }

    /* Iterate through all entries in the map */
    ret = bpf_map_get_next_key(map_fd, NULL, &key);
    while (ret == 0) {
        /* Read the per-CPU stats for this key */
        if (bpf_map_lookup_elem(map_fd, &key, stats) == 0) {
            /* Check if process still exists before updating */
            char proc_path[PROC_PATH_BUFFER_SIZE];
            snprintf(proc_path, sizeof(proc_path), "/proc/%u", key.pid);

            if (access(proc_path, F_OK) == 0) {
                struct process_data *proc = find_or_create_process(key.pid);
                if (proc) {
                    /* Aggregate per-CPU statistics */
                    struct network_stats aggregated = {0};
                    for (int cpu = 0; cpu < nr_cpus; cpu++) {
                        aggregated.rx_bytes += stats[cpu].rx_bytes;
                        aggregated.tx_bytes += stats[cpu].tx_bytes;
                        aggregated.rx_packets += stats[cpu].rx_packets;
                        aggregated.tx_packets += stats[cpu].tx_packets;
                        aggregated.tcp_messages += stats[cpu].tcp_messages;
                        aggregated.udp_packets += stats[cpu].udp_packets;
                        aggregated.rx_latency_ns += stats[cpu].rx_latency_ns;
                        aggregated.tx_latency_ns += stats[cpu].tx_latency_ns;

                        /* Use the most recent timestamp */
                        if (stats[cpu].timestamp > aggregated.timestamp) {
                            aggregated.timestamp = stats[cpu].timestamp;
                        }
                    }
                    aggregated.pid = key.pid;

                    uint64_t current_time = get_current_time_ns();

                    /* Update network metrics */
                    proc->network_rx_bytes = aggregated.rx_bytes;
                    proc->network_tx_bytes = aggregated.tx_bytes;
                    proc->network_rx_packets = aggregated.rx_packets;
                    proc->network_tx_packets = aggregated.tx_packets;
                    proc->network_tcp_connections = aggregated.tcp_messages;
                    proc->network_udp_packets = aggregated.udp_packets;
                    proc->network_rx_latency_total_ns = aggregated.rx_latency_ns;
                    proc->network_tx_latency_total_ns = aggregated.tx_latency_ns;

                    /* Calculate network rates */
                    calculate_network_rates(proc, current_time);

                    proc->last_updated = current_time;
                    proc->active = true;
                }
            }
        }

        /* Get next key */
        if (bpf_map_get_next_key(map_fd, &key, &next_key) != 0) {
            break;
        }
        key = next_key;
    }

    return 0;
}

/* Find existing process or create new one */
static struct process_data *find_or_create_process(uint32_t pid)
{
    /* Search existing active entries for this PID
     * After compaction, all active processes are in range [0, process_count) */
    for (int i = 0; i < g_collector.process_count; i++) {
        if (g_collector.processes[i].pid == pid) {
            /* Found existing entry - should already be active after compaction */
            return &g_collector.processes[i];
        }
    }

    /* Not found - need to create new entry */
    if (g_collector.process_count >= MAX_TRACKED_PROCESSES) {
        return NULL; /* No space available */
    }

    /* If not found and we have space, create new process */
    struct process_data *proc = &g_collector.processes[g_collector.process_count];
    memset(proc, 0, sizeof(*proc));

    proc->pid = pid;
    proc->first_seen = get_current_time_ns();
    proc->last_updated = proc->first_seen;
    proc->active = true;

    /* Try to get process command name from /proc with input validation */
    if (pid > 0 && pid <= UINT32_MAX) {
        char comm_path[PROC_COMM_PATH_SIZE];
        FILE *comm_file;

        snprintf(comm_path, sizeof(comm_path), "/proc/%u/comm", pid);

        comm_file = fopen(comm_path, "r");
        if (comm_file) {
            /* Use safe string reading with bounds checking */
            memset(proc->comm, 0, sizeof(proc->comm));

            if (fgets(proc->comm, sizeof(proc->comm), comm_file)) {
                /* Ensure null termination */
                proc->comm[sizeof(proc->comm) - 1] = '\0';

                /* Remove trailing newline safely */
                size_t len = strlen(proc->comm);
                if (len > 0 && proc->comm[len - 1] == '\n') {
                    proc->comm[len - 1] = '\0';
                }

                /* Validate that we got a reasonable command name */
                if (len == 0 || proc->comm[0] == '\0') {
                    goto fallback_name;
                }
            } else {
                goto fallback_name;
            }
            fclose(comm_file);
        } else {
            goto fallback_name;
        }
    } else {
        goto fallback_name;
    }

    /* Success path */
    goto success;

fallback_name:
    snprintf(proc->comm, sizeof(proc->comm), "pid_%u", pid);

success:

    g_collector.process_count++;
    g_collector.total_processes_seen++;

    return proc;
}

/* Update process container information */
static void update_process_container_info(struct process_data *proc)
{
    struct container_info container_info;

    if (container_tracker_get_info((pid_t)proc->pid, &container_info) == 0) {
        proc->is_container = container_info.is_container;
        if (container_info.is_container) {
            safe_strcpy(proc->container_id, sizeof(proc->container_id),
                        container_info.container_id);
        }
    }
}

/* Calculate CPU percentage based on time delta */
static void calculate_cpu_percentage(struct process_data *proc, uint64_t current_time_ns)
{
    if (proc->last_cpu_time > 0 && proc->last_updated > 0) {
        uint64_t cpu_delta = proc->cpu_time_ns - proc->last_cpu_time;
        uint64_t time_delta = current_time_ns - proc->last_updated;

        if (time_delta > 0) {
            /* Check for potential overflow before multiplication */
            if (cpu_delta > UINT64_MAX / PERCENTAGE_MULTIPLIER) {
                /* If would overflow, calculate differently to avoid it */
                uint64_t ratio = cpu_delta / time_delta;
                proc->cpu_usage_percent = (uint32_t)(ratio * PERCENTAGE_MULTIPLIER);
            } else {
                /* Safe to multiply first */
                proc->cpu_usage_percent =
                    (uint32_t)((cpu_delta * PERCENTAGE_MULTIPLIER) / time_delta);
            }

            /* Cap at reasonable maximum to prevent overflow issues (MAX_CPUS * 100%) */
            uint32_t max_total_percentage = MAX_CPUS_FOR_PERCENTAGE * PERCENTAGE_MULTIPLIER;
            if (proc->cpu_usage_percent > max_total_percentage) {
                proc->cpu_usage_percent = max_total_percentage;
            }
        }
    }

    proc->last_cpu_time = proc->cpu_time_ns;
}

/* Calculate network bandwidth rates based on byte deltas */
static void calculate_network_rates(struct process_data *proc, uint64_t current_time_ns)
{
    if (proc->last_updated > 0) {
        uint64_t rx_delta = proc->network_rx_bytes - proc->last_network_rx_bytes;
        uint64_t tx_delta = proc->network_tx_bytes - proc->last_network_tx_bytes;
        uint64_t time_delta = current_time_ns - proc->last_updated;

        if (time_delta > 0) {
            /* Convert bytes per nanosecond to megabits per second */
            /* Calculate in a safe way to avoid overflow */
            uint64_t seconds_elapsed = time_delta / NANOSECONDS_PER_SECOND;
            if (seconds_elapsed > 0) {
                proc->network_rx_rate_mbps =
                    (uint32_t)((rx_delta * BITS_PER_BYTE) / (uint64_t)MEGABYTES_PER_SECOND_DIVISOR /
                               seconds_elapsed);
                proc->network_tx_rate_mbps =
                    (uint32_t)((tx_delta * BITS_PER_BYTE) / (uint64_t)MEGABYTES_PER_SECOND_DIVISOR /
                               seconds_elapsed);
            } else {
                /* For sub-second intervals, use fractional calculation */
                double time_seconds = (double)time_delta / NANOSECONDS_PER_SECOND;
                proc->network_rx_rate_mbps =
                    (uint32_t)((double)(rx_delta * BITS_PER_BYTE) /
                               (MEGABYTES_DIVISOR_FLOAT * MEGABYTES_DIVISOR_FLOAT) / time_seconds);
                proc->network_tx_rate_mbps =
                    (uint32_t)((double)(tx_delta * BITS_PER_BYTE) /
                               (MEGABYTES_DIVISOR_FLOAT * MEGABYTES_DIVISOR_FLOAT) / time_seconds);
            }

            /* Cap at reasonable maximums to prevent overflow display issues */
            if (proc->network_rx_rate_mbps > MAX_NETWORK_RATE_MBPS) {
                proc->network_rx_rate_mbps = MAX_NETWORK_RATE_MBPS;
            }
            if (proc->network_tx_rate_mbps > MAX_NETWORK_RATE_MBPS) {
                proc->network_tx_rate_mbps = MAX_NETWORK_RATE_MBPS;
            }
        }
    }

    proc->last_network_rx_bytes = proc->network_rx_bytes;
    proc->last_network_tx_bytes = proc->network_tx_bytes;
}

/* Calculate memory allocation rate based on allocation deltas */
static void calculate_memory_allocation_rate(struct process_data *proc, uint64_t current_time_ns)
{
    if (proc->last_updated > 0) {
        uint64_t alloc_delta = proc->memory_alloc_bytes - proc->last_memory_alloc_bytes;
        uint64_t time_delta = current_time_ns - proc->last_updated;

        if (time_delta > 0) {
            /* Convert bytes per nanosecond to megabytes per second */
            uint64_t seconds_elapsed = time_delta / NANOSECONDS_PER_SECOND;
            if (seconds_elapsed > 0) {
                proc->memory_alloc_rate_mbps =
                    (uint32_t)(alloc_delta / (uint64_t)MEGABYTES_PER_SECOND_DIVISOR /
                               seconds_elapsed);
            } else {
                /* For sub-second intervals, use fractional calculation */
                double time_seconds = (double)time_delta / NANOSECONDS_PER_SECOND;
                proc->memory_alloc_rate_mbps =
                    (uint32_t)((double)alloc_delta /
                               (MEGABYTES_DIVISOR_FLOAT * MEGABYTES_DIVISOR_FLOAT) / time_seconds);
            }

            /* Cap at reasonable maximum */
            if (proc->memory_alloc_rate_mbps > MAX_MEMORY_RATE_MBPS) {
                proc->memory_alloc_rate_mbps = MAX_MEMORY_RATE_MBPS;
            }
        }
    }

    proc->last_memory_alloc_bytes = proc->memory_alloc_bytes;
}
