#ifndef HPMON_H
#define HPMON_H

#include "bpf_common.h"
#include <linux/types.h>
#include <stdbool.h>
#include <stdint.h>

/* Project version */
#define HPMON_VERSION_MAJOR 0
#define HPMON_VERSION_MINOR 1
#define HPMON_VERSION_PATCH 0

/* Maximum limits */
#define MAX_PROCESSES 1000
#define MAX_CONTAINERS 100
#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_CONTAINER_ID_LEN 64
#define MAX_VERSION_LEN 64

/* BPF map sizes */
#define CPU_MAP_SIZE 8192
#define SYSCALL_MAP_SIZE 4096
#define IO_MAP_SIZE 4096

/* Data collection intervals (milliseconds) */
#define DEFAULT_POLL_INTERVAL 100
#define DEFAULT_AGGREGATION_WINDOW 1000

/* Real-time processing defaults */
#define DEFAULT_WINDOW_SIZE 10
#define DEFAULT_RATE_LIMIT_MB 10

/* Configuration limits */
#define MIN_POLL_INTERVAL 10
#define MAX_POLL_INTERVAL 10000
#define MIN_AGGREGATION_WINDOW 100
#define MAX_AGGREGATION_WINDOW 60000
#define MIN_MAX_PROCESSES 10
#define MAX_MAX_PROCESSES 10000

/* Performance thresholds */
#define HIGH_CPU_THRESHOLD 80.0

/* Export and snapshot constants */
#define HISTORICAL_SNAPSHOT_INTERVAL 10             /* Store snapshot every 10 collections */
#define SECONDS_PER_HOUR 3600                       /* Seconds in one hour */
#define HOURS_PER_YEAR 8760                         /* Hours in one year (365 * 24) */
#define EXPORT_TIMESTAMP_BUFFER_SIZE 64             /* Buffer size for timestamp formatting */
#define EXPORT_BASE_SIZE_BYTES 1024                 /* Base size estimate for exports */
#define PROMETHEUS_TIMESTAMP_MULTIPLIER 1000        /* Convert seconds to milliseconds */
#define INFLUXDB_TIMESTAMP_MULTIPLIER 1000000000ULL /* Convert seconds to nanoseconds */
#define DEFAULT_DIRECTORY_PERMISSIONS 0755          /* Standard directory permissions */

/* Configuration structure */
struct hpmon_config {
    struct {
        struct cpu_config cpu;
        struct memory_config mem;
        struct io_config io;
        struct network_config net;
        struct syscall_config sys;
    } bpf;
    bool monitor_cpu;
    bool monitor_syscalls;
    bool monitor_io;
    bool monitor_memory;
    bool monitor_network;
    bool monitor_containers;
    bool track_tcp_only; /* Track only TCP network operations */
    __u32 poll_interval_ms;
    __u32 aggregation_window_ms;
    bool enable_tui;
    bool enable_json_output;
    char output_file[MAX_PATH_LEN];
    /* Optional: path to event log file, if set. If empty, events go to stdout. */
    char event_log_file[MAX_PATH_LEN];
    __u32 max_processes;
    /* Process filtering configuration */
    __u32 pid; /* Filter by specific PID (0 = disabled, monitor all) */
    __u32
        sample_rate; /* Sample rate for processes (0 = sample all, N = sample every Nth process) */
    /* BPF map cleanup configuration */
    __u32 bpf_cleanup_interval_seconds; /* How often to run cleanup (default: 30) */
    bool bpf_stats;                     /* Show BPF statistics (default: false) */
    /* IO/Network filtering configuration */
    __u64 min_bytes;       /* Minimum bytes to track for IO/network operations (default: 0) */
    __u64 syscall_bitmask; /* Bitmask for syscall categories to monitor */
};

/* Function declarations */
int hpmon_init(struct hpmon_config *config);
int hpmon_start(void);
int hpmon_stop(void);
void hpmon_cleanup(void);

/* Utility functions */
const char *hpmon_version_string(void);
void hpmon_print_stats(void);
void hpmon_print_container_stats(void);
int hpmon_export_json(const char *filename);

#endif /* HPMON_H */
