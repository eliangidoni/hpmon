// SPDX-License-Identifier: MIT
/* HPMon Memory Monitor eBPF Program
 *
 * This program hooks into memory-related tracepoints and syscalls to track
 * memory allocation operations. It monitors malloc/free operations, tracks
 * memory allocation patterns and leaks, monitors page faults and memory
 * pressure, and collects memory usage statistics per process.
 */

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include "bpf_common.h"

/* Memory operation types */
#define MEM_OP_ALLOC 0
#define MEM_OP_FREE 1
#define MEM_OP_MMAP 2
#define MEM_OP_MUNMAP 3
#define MEM_OP_PAGE_FAULT 4

/* BPF maps for memory statistics - using per-CPU to reduce contention */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct memory_key);
    __type(value, struct memory_stats);
} memory_stats_map SEC(".maps");

/* Map to store request ID and size between enter and exit tracepoints */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); /* PID */
    __type(value, struct memory_pending_request);
} memory_request_times SEC(".maps");

/* Ring buffer for memory events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} memory_events SEC(".maps");

/* Configuration map for memory monitoring */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct memory_config);
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

/* Helper function to check if we should track this memory operation */
static __always_inline int should_sample_memory(__u32 pid, __u32 tgid)
{
    __u32 key = 0;
    struct memory_config *config = bpf_map_lookup_elem(&config_map, &key);

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

/* Helper function to update memory statistics */
static __always_inline void update_memory_stats(__u32 pid, __u32 tgid, __u32 operation, __u64 size,
                                                __u64 latency_ns)
{
    struct memory_key key = {
        .pid = pid,
    };

    struct memory_stats *stats = bpf_map_lookup_elem(&memory_stats_map, &key);
    if (stats) {
        /* Update existing stats */
        if (operation == MEM_OP_ALLOC) {
            stats->alloc_count++;
            stats->alloc_bytes += size;
            stats->alloc_latency_ns += latency_ns;
            stats->current_alloc_bytes += size;
        } else if (operation == MEM_OP_FREE) {
            stats->free_count++;
            stats->free_bytes += size;
            if (stats->current_alloc_bytes > size) {
                stats->current_alloc_bytes -= size;
            } else {
                stats->current_alloc_bytes = 0; // Prevent underflow
            }
        } else if (operation == MEM_OP_MMAP) {
            stats->mmap_count++;
            stats->mmap_bytes += size;
            stats->current_mmap_bytes += size;
        } else if (operation == MEM_OP_MUNMAP) {
            stats->munmap_count++;
            stats->munmap_bytes += size;
            if (stats->current_mmap_bytes > size) {
                stats->current_mmap_bytes -= size;
            } else {
                stats->current_mmap_bytes = 0; // Prevent underflow
            }
        }

        /* Update peak memory usage */
        __u64 total_current = stats->current_alloc_bytes + stats->current_mmap_bytes;
        if (total_current > stats->peak_memory_bytes) {
            stats->peak_memory_bytes = total_current;
        }

        stats->timestamp = get_timestamp_ns();
    } else {
        /* Create new stats entry */
        struct memory_stats new_stats = {
            .pid = pid,
            .tgid = tgid,
            .alloc_count = (operation == MEM_OP_ALLOC) ? 1 : 0,
            .free_count = (operation == MEM_OP_FREE) ? 1 : 0,
            .mmap_count = (operation == MEM_OP_MMAP) ? 1 : 0,
            .munmap_count = (operation == MEM_OP_MUNMAP) ? 1 : 0,
            .alloc_bytes = (operation == MEM_OP_ALLOC) ? size : 0,
            .free_bytes = (operation == MEM_OP_FREE) ? size : 0,
            .mmap_bytes = (operation == MEM_OP_MMAP) ? size : 0,
            .munmap_bytes = (operation == MEM_OP_MUNMAP) ? size : 0,
            .current_alloc_bytes = (operation == MEM_OP_ALLOC) ? size : 0,
            .current_mmap_bytes = (operation == MEM_OP_MMAP) ? size : 0,
            .peak_memory_bytes = size,
            .page_faults = 0,
            .alloc_latency_ns = (operation == MEM_OP_ALLOC) ? latency_ns : 0,
            .timestamp = get_timestamp_ns(),
            .exited = 0,
        };
        int ret = bpf_map_update_elem(&memory_stats_map, &key, &new_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }
}

/* Syscall tracepoint for brk system call (heap management) */
SEC("tracepoint/syscalls/sys_enter_brk")
int trace_sys_enter_brk(struct trace_event_raw_sys_enter *args)
{
    __u64 now;
    __u64 addr, brk_addr;
    unsigned long syscall_args[6];

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    struct task_struct *task = (void *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        return 0;
    }
    brk_addr = BPF_CORE_READ(mm, brk);
    if (bpf_core_read(syscall_args, sizeof(syscall_args), &args->args) != 0)
        return 0;

    /* Get brk address from syscall arguments (first argument) */
    addr = syscall_args[0];

    now = get_timestamp_ns();
    /* Store request ID and brk address for exit tracepoint */
    struct memory_pending_request pending = {
        .request_id = pid,
        .size = 0,
        .address = addr,
        .brk = brk_addr,
        .timestamp = now,
    };

    int ret = bpf_map_update_elem(&memory_request_times, &pid, &pending, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }
    return 0;
}

/* Syscall tracepoint for brk system call completion */
SEC("tracepoint/syscalls/sys_exit_brk")
int trace_sys_exit_brk(struct trace_event_raw_sys_exit *args)
{
    __u64 now;
    __u64 latency_ns = 0;
    __u64 addr, size;
    struct memory_pending_request *pending;
    __u32 op;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CO-RE to read syscall return value safely */
    addr = (__u64)BPF_CORE_READ(args, ret);

    now = get_timestamp_ns();

    /* Look up pending request */
    pending = bpf_map_lookup_elem(&memory_request_times, &pid);
    if (!pending) {
        /* No pending request found - this shouldn't happen for matched enter/exit pairs */
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }
    latency_ns = now - pending->timestamp;
    if (addr != pending->address) {
        // brk failed or no change
        bpf_map_delete_elem(&memory_request_times, &pid);
        return 0;
    }
    if (addr > pending->brk) {
        op = MEM_OP_ALLOC;
        size = addr - pending->brk;
    } else {
        op = MEM_OP_FREE;
        size = pending->brk - addr;
    }
    bpf_map_delete_elem(&memory_request_times, &pid);

    /* Check if we should track this memory operation */
    if (!should_sample_memory(pid, tgid)) {
        return 0;
    }
    /* Update statistics */
    update_memory_stats(pid, tgid, op, size, latency_ns);

    /* Send event to user space */
    struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = now;
    event->size = size;
    event->address = addr;
    event->operation = op;
    event->latency_ns = latency_ns;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/* Syscall tracepoint for mmap system call */
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 now;
    __u64 size;
    unsigned long syscall_args[6];

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CORE to read syscall arguments safely */
    if (bpf_core_read(syscall_args, sizeof(syscall_args), &ctx->args) != 0)
        return 0;

    size = syscall_args[1]; /* Second argument: len */

    now = get_timestamp_ns();
    /* Store request ID and size for exit tracepoint */
    struct memory_pending_request pending = {
        .request_id = pid,
        .size = size,
        .timestamp = now,
    };
    int ret = bpf_map_update_elem(&memory_request_times, &pid, &pending, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }
    return 0;
}

/* Syscall tracepoint for mmap system call completion */
SEC("tracepoint/syscalls/sys_exit_mmap")
int trace_sys_exit_mmap(struct trace_event_raw_sys_exit *ctx)
{
    __u64 now;
    __u64 latency_ns;
    __u64 addr;
    __u64 size;
    struct memory_pending_request *pending;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CORE to read syscall return value safely */
    addr = (__u64)BPF_CORE_READ(ctx, ret);

    now = get_timestamp_ns();

    /* Look up pending request to get actual size */
    pending = bpf_map_lookup_elem(&memory_request_times, &pid);
    if (!pending) {
        /* No pending request found - this shouldn't happen for matched enter/exit pairs */
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }
    size = pending->size; /* Use actual size from enter tracepoint */
    latency_ns = now - pending->timestamp;
    bpf_map_delete_elem(&memory_request_times, &pid);

    /* Check if syscall succeeded (mmap returns the mapped address) */
    if (addr == (__u64)-1) /* MAP_FAILED */
        return 0;

    /* Check if we should track this memory operation */
    if (!should_sample_memory(pid, tgid))
        return 0;

    /* Update statistics */
    update_memory_stats(pid, tgid, MEM_OP_MMAP, size, latency_ns);

    /* Send event to user space */
    struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = now;
    event->size = size;
    event->address = addr;
    event->operation = MEM_OP_MMAP;
    event->latency_ns = latency_ns;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/* Syscall tracepoint for munmap system call entry */
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_sys_enter_munmap(struct trace_event_raw_sys_enter *ctx)
{
    __u64 addr;
    __u64 size;
    __u64 now;
    unsigned long syscall_args[6];

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CORE to read syscall arguments safely */
    if (bpf_core_read(syscall_args, sizeof(syscall_args), &ctx->args) != 0)
        return 0;

    /* Get munmap address and size from syscall arguments */
    addr = syscall_args[0]; /* First argument: addr */
    size = syscall_args[1]; /* Second argument: len */

    now = get_timestamp_ns();
    /* Store address and size for exit tracepoint */
    struct memory_pending_request pending = {
        .request_id = pid,
        .size = size,
        .address = addr,
        .timestamp = now,
    };
    int ret = bpf_map_update_elem(&memory_request_times, &pid, &pending, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }

    return 0;
}

/* Syscall tracepoint for munmap system call completion */
SEC("tracepoint/syscalls/sys_exit_munmap")
int trace_sys_exit_munmap(struct trace_event_raw_sys_exit *ctx)
{
    __u64 now, latency_ns;
    __u64 size;
    __u64 addr;
    struct memory_pending_request *pending;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    now = get_timestamp_ns();

    /* Look up pending request to get actual size and address */
    pending = bpf_map_lookup_elem(&memory_request_times, &pid);
    if (!pending) {
        /* No pending request found - this shouldn't happen for matched enter/exit pairs */
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }
    /* Look up request start time */
    latency_ns = now - pending->timestamp;
    size = pending->size;
    addr = pending->address;
    bpf_map_delete_elem(&memory_request_times, &pid);

    /* Check if syscall succeeded */
    if (BPF_CORE_READ(ctx, ret) != 0)
        return 0;

    /* Check if we should track this memory operation */
    if (!should_sample_memory(pid, tgid))
        return 0;

    /* Update statistics */
    update_memory_stats(pid, tgid, MEM_OP_MUNMAP, size, latency_ns);

    /* Send event to user space */
    struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = now;
    event->size = size;
    event->address = addr;
    event->operation = MEM_OP_MUNMAP;
    event->latency_ns = latency_ns;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/* Alternative page fault monitoring using fentry - more efficient than kprobe */
SEC("fentry/handle_mm_fault")
int BPF_PROG(trace_page_fault_fentry)
{
    struct memory_key key;
    struct memory_stats *stats;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Check if we should track this memory operation */
    if (!should_sample_memory(pid, tgid))
        return 0;

    key.pid = pid;

    __u64 now = get_timestamp_ns();

    /* Update page fault counter */
    stats = bpf_map_lookup_elem(&memory_stats_map, &key);
    if (stats) {
        stats->page_faults++;
        stats->timestamp = now;
    } else {
        /* Create new stats entry for page fault */
        struct memory_stats new_stats = {
            .pid = pid,
            .tgid = tgid,
            .page_faults = 1,
            .timestamp = now,
            .exited = 0,
        };
        int ret = bpf_map_update_elem(&memory_stats_map, &key, &new_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }

    /* Send page fault event to user space */
    struct memory_event *event = bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = now;
    event->size = 0;
    event->address = 0;
    event->operation = MEM_OP_PAGE_FAULT; /* Special operation code for page faults */
    event->latency_ns = 0;

    /* Get process name */
    bpf_get_current_comm(event->comm, COMM_LEN);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/* Process exit handler to clean up memory tracking */
SEC("tracepoint/sched/sched_process_exit")
int trace_memory_process_exit(struct trace_event_raw_sched_process_template *args)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    struct memory_key key;
    key.pid = pid;

    /* Mark memory stats for cleanup by setting a special timestamp */
    /* User space should periodically clean up old entries */
    struct memory_stats *stats = bpf_map_lookup_elem(&memory_stats_map, &key);
    if (stats) {
        stats->exited = 1;
    }

    /* Note: We cannot efficiently iterate through allocation map here in eBPF */
    /* User space should handle cleanup of allocation tracking periodically */
    /* by checking process existence and removing stale entries */

    return 0;
}

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
