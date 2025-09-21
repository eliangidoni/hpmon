// SPDX-License-Identifier: MIT
/* HPMon CPU Monitor eBPF Program
 *
 * This program hooks into scheduler events to track CPU usage per process.
 * It monitors sched_switch and sched_wakeup events to calculate CPU time
 * and utilization percentages for processes across multiple cores.
 */

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include "bpf_common.h"

/* BPF maps for CPU statistics - using per-CPU to reduce contention */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct cpu_key);
    __type(value, struct cpu_stats);
} cpu_stats_map SEC(".maps");

/* Map to track process start times for delta calculations */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32); /* PID */
    __type(value, struct cpu_start_request);
} process_start_times SEC(".maps");

/* Ring buffer for CPU events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} cpu_events SEC(".maps");

/* Configuration map for CPU monitoring */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cpu_config);
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

static __always_inline int should_sample_cpu(__u32 pid, __u32 tgid)
{
    __u32 key = 0;
    struct cpu_config *config = bpf_map_lookup_elem(&config_map, &key);

    if (!config) {
        increment_error_counter(ERROR_CONFIG_MISSING);
        return 0;
    }

    if (config->tgid != 0 && config->tgid != tgid)
        return 0; /* TGID filter */

    /* Apply consistent sampling rate */
    if (config->sample_rate > 1) {
        return (pid % config->sample_rate) == 0;
    }
    return 1;
}

/* Helper function to update CPU statistics */
static __always_inline void update_cpu_stats(__u32 pid, __u32 tgid, __u64 delta_ns)
{
    struct cpu_key key = {
        .pid = pid,
    };

    struct cpu_stats *stats = bpf_map_lookup_elem(&cpu_stats_map, &key);
    if (stats) {
        /* Update existing stats */
        stats->cpu_time_ns += delta_ns;
        stats->timestamp = get_timestamp_ns();
        /* Note: CPU percentage calculation will be done in user space */
    } else {
        /* Create new stats entry */
        struct cpu_stats new_stats = {
            .pid = pid,
            .tgid = tgid,
            .cpu_time_ns = delta_ns,
            .user_time_ns = 0, /* Will be updated by other tracepoints */
            .sys_time_ns = 0,  /* Will be updated by other tracepoints */
            .cpu_percent = 0,  /* Calculated in user space */
            .timestamp = get_timestamp_ns(),
            .exited = 0,
        };
        int ret = bpf_map_update_elem(&cpu_stats_map, &key, &new_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }
}

/* Tracepoint for scheduler switch events */
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *args)
{
    __u32 prev_pid, next_pid;
    __u32 cpu;
    __u64 now;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;

    /* Get the previous and next process IDs using CO-RE */
    prev_pid = BPF_CORE_READ(args, prev_pid);
    next_pid = BPF_CORE_READ(args, next_pid);

    /* Get current CPU and timestamp */
    cpu = bpf_get_smp_processor_id();
    now = get_timestamp_ns();

    /* Handle the process being switched out (prev_pid) */
    if (prev_pid != 0 && tgid != 0 && /* Ignore kernel threads */
        should_sample_cpu(prev_pid, tgid)) {
        struct cpu_start_request *req = bpf_map_lookup_elem(&process_start_times, &prev_pid);
        if (req) {
            __u64 delta_ns = now - req->start_time_ns;
            if (delta_ns > 0) {
                update_cpu_stats(prev_pid, tgid, delta_ns);
                /* Send event to user space */
                struct cpu_event *event =
                    bpf_ringbuf_reserve(&cpu_events, sizeof(struct cpu_event), 0);
                if (!event) {
                    increment_error_counter(ERROR_RING_BUFFER_FULL);
                } else {
                    event->pid = prev_pid;
                    event->tgid = tgid;
                    event->cpu = cpu;
                    event->timestamp = now;
                    event->delta_ns = delta_ns;

                    /* Copy process name using CO-RE */
                    bpf_get_current_comm(event->comm, COMM_LEN);

                    bpf_ringbuf_submit(event, 0);
                }
            }
            bpf_map_delete_elem(&process_start_times, &prev_pid);
        } else {
            /* No start time found, possibly first switch out */
            increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        }
    }

    /* Handle the process being switched in (next_pid) */
    if (next_pid != 0) { /* Ignore idle process */
        struct cpu_start_request req = {
            .start_time_ns = now,
        };
        int ret = bpf_map_update_elem(&process_start_times, &next_pid, &req, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }

    return 0;
}

/* Track process exit to clean up maps and mark for post-mortem cleanup */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(struct trace_event_raw_sched_process_template *args)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Mark CPU stats for cleanup by setting a special timestamp */
    /* Since we can't efficiently iterate all CPUs in eBPF, we mark the entry */
    /* for the current CPU and let user space handle comprehensive cleanup */
    struct cpu_key key = {
        .pid = pid,
    };

    struct cpu_stats *stats = bpf_map_lookup_elem(&cpu_stats_map, &key);
    if (stats) {
        stats->exited = 1;
    }

    /* Note: User space should periodically clean up all CPU entries for this PID */
    /* by checking process existence and removing stale entries */

    return 0;
}

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
