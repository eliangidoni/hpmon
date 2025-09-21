// SPDX-License-Identifier: MIT
/* HPMon System Call Monitor eBPF Program
 *
 * This program hooks into sys_enter/sys_exit tracepoints to track system call
 * frequency and latency. It filters and categorizes system calls and handles
 * high-frequency syscalls efficiently to minimize performance impact.
 */

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include "bpf_common.h"

/* BPF maps for system call statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct syscall_key);
    __type(value, struct syscall_stats);
} syscall_stats_map SEC(".maps");

/* Map to track syscall entry times for latency calculation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct syscall_key);
    __type(value, __u64); /* entry timestamp */
} syscall_entry_times SEC(".maps");

/* Ring buffer for syscall events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} syscall_events SEC(".maps");

/* Configuration map for filtering syscalls */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syscall_config);
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

/* Helper function to categorize system calls - Architecture aware */
static __always_inline enum syscall_category categorize_syscall(__u32 syscall_nr)
{
    /* Architecture-specific syscall categorization
     * ARM64 and x86-64 have different syscall numbers */

#if defined(__aarch64__) || defined(__TARGET_ARCH_arm64)
    /* ARM64 syscall numbers */
    switch (syscall_nr) {
    /* File I/O operations */
    case 63: /* read */
    case 64: /* write */
    case 56: /* openat */
    case 57: /* close */
    case 80: /* fstat */
    case 79: /* fstatat/newfstatat */
    case 62: /* lseek */
    case 25: /* fcntl */
    case 78: /* readlinkat */
    case 48: /* faccessat */
        return SYSCALL_CAT_FILE_IO;

    /* Memory operations */
    case 222: /* mmap */
    case 226: /* mprotect */
    case 215: /* munmap */
    case 214: /* brk */
    case 227: /* madvise */
        return SYSCALL_CAT_MEMORY;

    /* Process operations */
    case 220: /* clone */
    case 221: /* execve */
    case 260: /* wait4 */
    case 281: /* execveat */
    case 172: /* getpid */
    case 173: /* getppid */
        return SYSCALL_CAT_PROCESS;

    /* Network operations */
    case 198: /* socket */
    case 203: /* connect */
    case 202: /* accept */
    case 206: /* sendto */
    case 207: /* recvfrom */
    case 211: /* sendmsg */
    case 212: /* recvmsg */
    case 199: /* bind */
    case 201: /* listen */
        return SYSCALL_CAT_NETWORK;

    /* Time operations */
    case 169: /* gettimeofday */
    case 113: /* clock_gettime */
    case 115: /* clock_nanosleep */
    case 101: /* nanosleep */
    case 112: /* clock_getres */
        return SYSCALL_CAT_TIME;

    /* Signal operations */
    case 129: /* kill */
    case 134: /* rt_sigaction */
    case 135: /* rt_sigprocmask */
    case 136: /* rt_sigpending */
    case 137: /* rt_sigtimedwait */
        return SYSCALL_CAT_SIGNAL;

    default:
        return SYSCALL_CAT_OTHER;
    }

#elif defined(__x86_64__) || defined(__TARGET_ARCH_x86)
    /* x86-64 syscall numbers */
    switch (syscall_nr) {
    /* File I/O operations */
    case 0:   /* read */
    case 1:   /* write */
    case 2:   /* open */
    case 3:   /* close */
    case 4:   /* stat */
    case 5:   /* fstat */
    case 6:   /* lstat */
    case 8:   /* lseek */
    case 257: /* openat */
    case 262: /* newfstatat */
        return SYSCALL_CAT_FILE_IO;

    /* Memory operations */
    case 9:  /* mmap */
    case 10: /* mprotect */
    case 11: /* munmap */
    case 12: /* brk */
        return SYSCALL_CAT_MEMORY;

    /* Process operations */
    case 57:  /* fork */
    case 58:  /* vfork */
    case 59:  /* execve */
    case 61:  /* wait4 */
    case 322: /* execveat */
        return SYSCALL_CAT_PROCESS;

    /* Network operations */
    case 41: /* socket */
    case 42: /* connect */
    case 43: /* accept */
    case 44: /* sendto */
    case 45: /* recvfrom */
    case 46: /* sendmsg */
    case 47: /* recvmsg */
        return SYSCALL_CAT_NETWORK;

    /* Time operations */
    case 96:  /* gettimeofday */
    case 228: /* clock_gettime */
    case 230: /* clock_nanosleep */
    case 35:  /* nanosleep */
        return SYSCALL_CAT_TIME;

    /* Signal operations */
    case 62: /* kill */
    case 13: /* rt_sigaction */
    case 14: /* rt_sigprocmask */
        return SYSCALL_CAT_SIGNAL;

    default:
        return SYSCALL_CAT_OTHER;
    }

#else
    /* Generic/unknown architecture - categorize based on common patterns */
    /* For unknown architectures, we'll use heuristics or treat all as OTHER */
    return SYSCALL_CAT_OTHER;
#endif
}

/* Helper function to should we sample this syscall for performance */
static __always_inline int should_sample_syscall(__u32 syscall_nr, __u32 pid, __u32 tgid)
{
    __u32 key = 0;
    struct syscall_config *config = bpf_map_lookup_elem(&config_map, &key);

    if (!config) {
        increment_error_counter(ERROR_CONFIG_MISSING);
        return 0;
    }

    if (config->tgid != 0 && config->tgid != tgid)
        return 0;

    if (config->syscall_bitmask == 0) {
        /* No filtering - sample all */
        return 1;
    }
    enum syscall_category cat = categorize_syscall(syscall_nr);
    return (config->syscall_bitmask & (1ULL << cat)) != 0;
}

/* Helper function to update syscall statistics */
static __always_inline void update_syscall_stats(__u32 pid, __u32 tgid, __u32 syscall_nr,
                                                 __u64 latency_ns)
{
    struct syscall_key key = {
        .pid = pid,
        .syscall_nr = syscall_nr,
    };

    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &key);
    if (stats) {
        /* Update existing stats */
        stats->count++;
        stats->total_latency_ns += latency_ns;

        /* Update min/max latency */
        if (latency_ns < stats->min_latency_ns || stats->min_latency_ns == 0) {
            stats->min_latency_ns = latency_ns;
        }
        if (latency_ns > stats->max_latency_ns) {
            stats->max_latency_ns = latency_ns;
        }

        stats->timestamp = get_timestamp_ns();
    } else {
        /* Create new stats entry */
        struct syscall_stats new_stats = {
            .pid = pid,
            .tgid = tgid,
            .syscall_nr = syscall_nr,
            .category = categorize_syscall(syscall_nr),
            .count = 1,
            .total_latency_ns = latency_ns,
            .min_latency_ns = latency_ns,
            .max_latency_ns = latency_ns,
            .timestamp = get_timestamp_ns(),
            .exited = 0,
        };
        int ret = bpf_map_update_elem(&syscall_stats_map, &key, &new_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }
}

/* Tracepoint for system call entry */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid;
    __u32 syscall_nr;
    __u64 now, pid_tgid;

    /* Get current process and CPU info */
    pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    pid = (__u32)pid_tgid;
    syscall_nr = (__u32)BPF_CORE_READ(ctx, id);
    struct syscall_key key = {.pid = pid, .syscall_nr = syscall_nr};

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Check if we should sample this syscall */
    if (!should_sample_syscall(syscall_nr, pid, tgid))
        return 0;

    now = get_timestamp_ns();
    /* Store entry timestamp for latency calculation */
    int ret = bpf_map_update_elem(&syscall_entry_times, &key, &now, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }

    return 0;
}

/* Tracepoint for system call exit */
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid, tgid;
    __u32 syscall_nr;
    __u64 now, *entry_time;
    __u64 pid_tgid;
    __u64 latency_ns;

    /* Get current process and CPU info */
    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    pid = (__u32)pid_tgid;
    syscall_nr = (__u32)BPF_CORE_READ(ctx, id);
    struct syscall_key key = {.pid = pid, .syscall_nr = syscall_nr};

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    if (!should_sample_syscall(syscall_nr, pid, tgid))
        return 0;

    now = get_timestamp_ns();

    /* Look up entry time */
    entry_time = bpf_map_lookup_elem(&syscall_entry_times, &key);
    if (!entry_time) {
        /* No entry time found - syscall started before tracing began */
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }

    /* Calculate latency */
    if (now < *entry_time) {
        /* Time went backwards or overflow occurred - skip this sample */
        bpf_map_delete_elem(&syscall_entry_times, &key);
        return 0;
    }

    latency_ns = now - *entry_time;

    /* Clean up entry time */
    bpf_map_delete_elem(&syscall_entry_times, &key);

    /* Update statistics */
    update_syscall_stats(pid, tgid, syscall_nr, latency_ns);

    /* Reserve space in ring buffer for the event */
    struct syscall_event *event = bpf_ringbuf_reserve(&syscall_events, sizeof(*event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    /* Fill event data */
    event->pid = pid;
    event->tgid = tgid;
    event->syscall_nr = syscall_nr;
    event->timestamp = now;
    event->latency_ns = latency_ns;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);

    /* Submit the event to the ring buffer */
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/* Track process exit to clean up maps and mark for post-mortem cleanup */
SEC("tracepoint/sched/sched_process_exit")
int trace_syscall_process_exit(struct trace_event_raw_sched_process_template *args)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Clean up syscall stats entries for this process */
    /* Since we can't efficiently iterate all syscalls in eBPF, we use a common */
    /* syscall number to mark an entry for cleanup and let user space handle */
    /* comprehensive cleanup of all syscall stats for this PID */
    struct syscall_key stats_key = {
        .pid = pid, .syscall_nr = 0, /* Use syscall 0 as a marker entry */
    };

    struct syscall_stats *stats = bpf_map_lookup_elem(&syscall_stats_map, &stats_key);
    if (stats) {
        /* Mark as exited with special timestamp pattern */
        stats->exited = 1;
    } else {
        /* Filter by TGID before creating a marker entry */
        __u32 key = 0;
        struct syscall_config *config = bpf_map_lookup_elem(&config_map, &key);
        if (!config)
            return 0;
        if (config->tgid != 0 && config->tgid != tgid)
            return 0;

        /* Create marker entry for cleanup */
        struct syscall_stats marker_stats = {
            .pid = pid,
            .tgid = tgid,
            .syscall_nr = 0,
            .exited = 1,
        };
        int ret = bpf_map_update_elem(&syscall_stats_map, &stats_key, &marker_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }

    /* Note: User space should periodically clean up all syscall entries for this PID */
    /* by checking process existence and removing stale entries */

    return 0;
}

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
