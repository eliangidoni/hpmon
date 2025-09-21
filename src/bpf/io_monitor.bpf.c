// SPDX-License-Identifier: MIT
/* HPMon I/O Monitor eBPF Program
 *
 * This program hooks into block I/O tracepoints to track read/write operations.
 * It monitors I/O latency and throughput and correlates I/O with processes
 * to provide insights into storage performance bottlenecks.
 *
 */

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include "bpf_common.h"

/* I/O operation types */
#define IO_OP_READ 0
#define IO_OP_WRITE 1

/* BPF maps for I/O statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct io_key);
    __type(value, struct io_stats);
} io_stats_map SEC(".maps");

/* Map to track I/O request start times for latency calculation
 * FIX: Use combination of PID + timestamp as unique key instead of sector
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);   /* PID */
    __type(value, __u64); /* start timestamp */
} io_request_times SEC(".maps");

/* Ring buffer for I/O events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} io_events SEC(".maps");

/* Configuration map for I/O monitoring */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct io_config);
} config_map SEC(".maps");

/* Error counters for debugging */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ERROR_MAX);
    __type(key, __u32);
    __type(value, __u64);
} error_counters SEC(".maps");

/* Helper function to get current timestamp */
static __always_inline __u64 get_timestamp_ns(void)
{
    return bpf_ktime_get_ns();
}

/* Helper function to increment error counters */
static __always_inline void increment_error_counter(enum error_counter error_type)
{
    __u64 *count = bpf_map_lookup_elem(&error_counters, &error_type);
    if (count) {
        __atomic_fetch_add(count, 1, __ATOMIC_RELAXED);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&error_counters, &error_type, &initial_count, BPF_ANY);
    }
}

/* Helper function to check if we should track this I/O */
static __always_inline int should_sample_io(__u64 bytes, __u32 pid, __u32 tgid)
{
    __u32 key = 0;
    struct io_config *config = bpf_map_lookup_elem(&config_map, &key);

    if (!config) {
        increment_error_counter(ERROR_CONFIG_MISSING);
        return 0;
    }

    if (config->tgid != 0 && config->tgid != tgid)
        return 0; /* TGID filter */

    /* Check minimum bytes threshold */
    if (bytes < config->min_bytes_threshold) {
        return 0;
    }

    /* Apply sampling rate */
    if (config->sample_rate > 1) {
        return (pid % config->sample_rate) == 0;
    }

    return 1;
}

/* Helper function to update I/O statistics */
static __always_inline void update_io_stats(__u32 pid, __u32 tgid, __u32 operation, __u64 bytes,
                                            __u64 latency_ns)
{
    struct io_key key = {
        .pid = pid,
    };

    struct io_stats *stats = bpf_map_lookup_elem(&io_stats_map, &key);
    if (stats) {
        /* Update existing stats */
        if (operation == IO_OP_READ) {
            stats->read_bytes += bytes;
            stats->read_ops++;
            stats->read_latency_ns += latency_ns;
        } else {
            stats->write_bytes += bytes;
            stats->write_ops++;
            stats->write_latency_ns += latency_ns;
        }
        stats->timestamp = get_timestamp_ns();
    } else {
        /* Create new stats entry */
        struct io_stats new_stats = {
            .pid = pid,
            .tgid = tgid,
            .read_bytes = (operation == IO_OP_READ) ? bytes : 0,
            .write_bytes = (operation == IO_OP_WRITE) ? bytes : 0,
            .read_ops = (operation == IO_OP_READ) ? 1 : 0,
            .write_ops = (operation == IO_OP_WRITE) ? 1 : 0,
            .read_latency_ns = (operation == IO_OP_READ) ? latency_ns : 0,
            .write_latency_ns = (operation == IO_OP_WRITE) ? latency_ns : 0,
            .timestamp = get_timestamp_ns(),
            .exited = 0,
        };
        int ret = bpf_map_update_elem(&io_stats_map, &key, &new_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter *args)
{
    __u64 count;
    unsigned long syscall_args[6];

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CORE to read syscall arguments safely */
    if (bpf_core_read(syscall_args, sizeof(syscall_args), &args->args) != 0)
        return 0;

    /* Get read size from syscall arguments (third argument) */
    count = syscall_args[2];

    /* Check if we should track this I/O */
    if (!should_sample_io(count, pid, tgid))
        return 0;

    __u64 now = get_timestamp_ns();
    int ret = bpf_map_update_elem(&io_request_times, &pid, &now, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit *args)
{
    __u64 now;
    __u64 latency_ns;
    __u64 *timestamp;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Check if we should track this I/O */
    if (!should_sample_io(0, pid, tgid))
        return 0;

    timestamp = bpf_map_lookup_elem(&io_request_times, &pid);
    if (!timestamp) {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }

    /* Calculate latency */
    now = get_timestamp_ns();
    latency_ns = now - (*timestamp);
    bpf_map_delete_elem(&io_request_times, &pid);

    __u64 bytes = BPF_CORE_READ(args, ret);
    if (bytes == (__u64)-1) {
        return 0;
    }

    /* Update statistics */
    update_io_stats(pid, tgid, IO_OP_READ, bytes, latency_ns);

    /* Send event to user space */
    struct hpmon_io_event *event =
        bpf_ringbuf_reserve(&io_events, sizeof(struct hpmon_io_event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = now;
    event->bytes = bytes;
    event->operation = IO_OP_READ;
    event->latency_ns = latency_ns;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *args)
{
    __u64 count;
    unsigned long syscall_args[6];

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CORE to read syscall arguments safely */
    if (bpf_core_read(syscall_args, sizeof(syscall_args), &args->args) != 0)
        return 0;

    count = syscall_args[2];

    /* Check if we should track this I/O */
    if (!should_sample_io(count, pid, tgid))
        return 0;

    __u64 now = get_timestamp_ns();
    int ret = bpf_map_update_elem(&io_request_times, &pid, &now, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *args)
{
    __u64 now;
    __u64 latency_ns;
    __u64 *timestamp;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Check if we should track this I/O */
    if (!should_sample_io(0, pid, tgid))
        return 0;

    timestamp = bpf_map_lookup_elem(&io_request_times, &pid);
    if (!timestamp) {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }

    /* Calculate latency */
    now = get_timestamp_ns();
    latency_ns = now - (*timestamp);
    bpf_map_delete_elem(&io_request_times, &pid);

    __u64 bytes = BPF_CORE_READ(args, ret);
    if (bytes == (__u64)-1) {
        return 0;
    }

    /* Update statistics */
    update_io_stats(pid, tgid, IO_OP_WRITE, bytes, latency_ns);

    /* Send event to user space */
    struct hpmon_io_event *event =
        bpf_ringbuf_reserve(&io_events, sizeof(struct hpmon_io_event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = now;
    event->bytes = bytes;
    event->operation = IO_OP_WRITE;
    event->latency_ns = latency_ns;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/* FIX: Enhanced process exit handler with better cleanup */
SEC("tracepoint/sched/sched_process_exit")
int trace_io_process_exit(struct trace_event_raw_sched_process_template *args)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Mark I/O stats for cleanup by setting a special timestamp */
    /* Similar approach to CPU monitor - mark for user space cleanup */
    struct io_key key = {
        .pid = pid,
    };

    struct io_stats *stats = bpf_map_lookup_elem(&io_stats_map, &key);
    if (stats) {
        stats->exited = 1;
    }

    /* Note: User space should periodically clean up I/O entries for this PID */
    /* by checking process existence and removing stale entries */

    return 0;
}

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
