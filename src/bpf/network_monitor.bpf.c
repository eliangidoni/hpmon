// SPDX-License-Identifier: MIT
/* HPMon Network Monitor eBPF Program
 *
 * This program hooks into network-related tracepoints and syscalls to track
 * network socket operations. It monitors TCP/UDP send/receive operations,
 * tracks network bandwidth per process/container, and collects connection
 * statistics and latency metrics.
 *
 * LIMITATIONS:
 * - This implementation focuses on per-process network I/O statistics
 */

// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#include "bpf_common.h"

/* Network operation types */
#define NET_OP_RECEIVE 0
#define NET_OP_SEND 1

/* Protocol types */
#define NET_PROTO_TCP 0
#define NET_PROTO_UDP 1
#define NET_PROTO_UNIX 2

/* IP Protocol numbers (from IANA) */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Network address constants */
#define LOOPBACK_ADDR_IPV4 0x0100007F /* 127.0.0.1 in network byte order */
#define DEFAULT_MIN_BYTES_THRESHOLD 64
#define DEFAULT_SAMPLE_RATE 3

/* Socket type constants for protocol detection */
#define SOCK_STREAM 1 /* TCP */
#define SOCK_DGRAM 2  /* UDP */
#define AF_UNIX 1

/* BPF maps for network statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct network_key);
    __type(value, struct network_stats);
} network_stats_map SEC(".maps");

/* Map to track network request start times for latency calculation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); /* PID */
    __type(value, struct network_request);
} network_request_times SEC(".maps");

/* Map to track socket file descriptors and their protocol */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64); /* tgid << 32 | fd */
    __type(value, struct socket_info);
} socket_fd_map SEC(".maps");

/* Ring buffer for network events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} network_events SEC(".maps");

/* Configuration map for network monitoring */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct network_config);
} config_map SEC(".maps");

/* Error counters for debugging */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ERROR_MAX);
    __type(key, __u32);
    __type(value, __u64);
} error_counters SEC(".maps");

/* Helper function to check if file descriptor is a socket and get protocol */
static __always_inline int is_socket_fd(__u32 tgid, __u32 fd)
{
    __u64 key = ((__u64)tgid << 32) | fd;
    struct socket_info *info = bpf_map_lookup_elem(&socket_fd_map, &key);

    /* If not found in map, assume it's not a socket (conservative approach) */
    return info ? info->is_socket : 0;
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

/* Helper function to get current timestamp */
static __always_inline __u64 get_timestamp_ns(void)
{
    return bpf_ktime_get_ns();
}

/* Helper function to check if we should track this network operation */
static __always_inline int should_sample_network(__u64 bytes, __u32 pid, __u32 tgid, __u32 protocol)
{
    __u32 key = 0;
    struct network_config *config = bpf_map_lookup_elem(&config_map, &key);

    if (!config) {
        /* Configuration missing - increment error counter and use defaults */
        increment_error_counter(ERROR_CONFIG_MISSING);
        return 0;
    }

    if (config->tgid != 0 && config->tgid != tgid) {
        return 0; /* TGID filter */
    }

    /* Check minimum bytes threshold */
    if (bytes < config->min_bytes_threshold) {
        return 0;
    }

    /* Check protocol filter */
    if (config->track_tcp_only && protocol != NET_PROTO_TCP) {
        return 0;
    }

    /* Apply sampling rate */
    if (config->sample_rate > 1) {
        return (pid % config->sample_rate) == 0;
    }

    return 1;
}

/* Helper function to update network statistics with better error handling */
static __always_inline void update_network_stats(__u32 pid, __u32 tgid, __u32 operation,
                                                 __u32 protocol, __u64 bytes, __u64 latency_ns)
{
    struct network_key key = {
        .pid = pid,
    };

    struct network_stats *stats = bpf_map_lookup_elem(&network_stats_map, &key);
    if (stats) {
        /* Update existing stats - no need for atomic operations with PERCPU */
        if (operation == NET_OP_RECEIVE) {
            stats->rx_bytes += bytes;
            stats->rx_packets += 1;
            stats->rx_latency_ns += latency_ns;
        } else {
            stats->tx_bytes += bytes;
            stats->tx_packets += 1;
            stats->tx_latency_ns += latency_ns;
        }

        if (protocol == NET_PROTO_TCP) {
            stats->tcp_messages += 1;
        } else if (protocol == NET_PROTO_UDP) {
            stats->udp_packets += 1;
        }
        stats->timestamp = get_timestamp_ns();
    } else {
        /* Create new stats entry */
        struct network_stats new_stats = {
            .pid = pid,
            .tgid = tgid,
            .rx_bytes = (operation == NET_OP_RECEIVE) ? bytes : 0,
            .tx_bytes = (operation == NET_OP_SEND) ? bytes : 0,
            .rx_packets = (operation == NET_OP_RECEIVE) ? 1 : 0,
            .tx_packets = (operation == NET_OP_SEND) ? 1 : 0,
            .tcp_messages = (protocol == NET_PROTO_TCP) ? 1 : 0,
            .udp_packets = (protocol == NET_PROTO_UDP) ? 1 : 0,
            .rx_latency_ns = (operation == NET_OP_RECEIVE) ? latency_ns : 0,
            .tx_latency_ns = (operation == NET_OP_SEND) ? latency_ns : 0,
            .timestamp = get_timestamp_ns(),
            .exited = 0,
        };
        int ret = bpf_map_update_elem(&network_stats_map, &key, &new_stats, BPF_ANY);
        if (ret != 0) {
            increment_error_counter(ERROR_MAP_UPDATE_FAILED);
        }
    }
}

/* Enhanced tracepoint for network send operations - only track actual sockets */
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter *args)
{
    __u64 now;
    __u32 fd;
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

    /* Extract fd from syscall arguments (first argument) */
    fd = (__u32)syscall_args[0];

    /* Only track if this is actually a socket */
    if (!is_socket_fd(pid, fd))
        return 0;

    now = get_timestamp_ns();
    struct network_request req = {
        .timestamp = now,
        .fd = fd,
    };
    /* Store request start time for latency calculation */
    int ret = bpf_map_update_elem(&network_request_times, &pid, &req, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }

    return 0;
}

/* Syscall tracepoint for socket send operations completion */
SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct trace_event_raw_sys_exit *args)
{
    __u64 now;
    __u64 latency_ns = 0;
    __u64 bytes;
    __u32 protocol = NET_PROTO_TCP; /* Default to TCP */
    struct network_request *req;
    long ret_value;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Look up request start time */
    req = bpf_map_lookup_elem(&network_request_times, &pid);
    if (!req) {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }
    now = get_timestamp_ns();
    latency_ns = now - req->timestamp;
    __u64 sock_key = ((__u64)tgid << 32) | req->fd;
    bpf_map_delete_elem(&network_request_times, &pid);

    /* Use BPF CORE to read return value safely */
    ret_value = BPF_CORE_READ(args, ret);
    /* Check if syscall succeeded */
    if (ret_value < 0)
        return 0;
    bytes = ret_value; /* Return value is bytes sent */

    /* Get actual protocol from socket info instead of assuming TCP */
    struct socket_info *info = bpf_map_lookup_elem(&socket_fd_map, &sock_key);
    if (info) {
        protocol = info->protocol;
    } else {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
    }

    /* Check if we should track this network operation */
    if (!should_sample_network(bytes, pid, tgid, protocol))
        return 0;

    /* Update statistics */
    update_network_stats(pid, tgid, NET_OP_SEND, protocol, bytes, latency_ns);

    /* Send event to user space */
    struct network_event event = {
        .pid = pid,
        .tgid = tgid,
        .timestamp = now,
        .bytes = bytes,
        .operation = NET_OP_SEND,
        .protocol = protocol, /* Use detected protocol */
        .local_port = 0,      /* Not available from syscall level - limitation */
        .remote_port = 0,     /* Not available from syscall level - limitation */
        .local_addr = 0,      /* Not available from syscall level - limitation */
        .remote_addr = 0,     /* Not available from syscall level - limitation */
        .latency_ns = latency_ns,
    };

    /* Get process name */
    bpf_get_current_comm(event.comm, COMM_LEN);

    /* Send event to ring buffer */
    struct network_event *ringbuf_event =
        bpf_ringbuf_reserve(&network_events, sizeof(struct network_event), 0);
    if (!ringbuf_event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }
    *ringbuf_event = event;
    bpf_ringbuf_submit(ringbuf_event, 0);
    return 0;
}

/* Enhanced tracepoint for socket receive operations - only track actual sockets */
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter *args)
{
    __u32 pid, tgid;
    __u64 now;
    __u64 pid_tgid;
    __u32 fd;
    unsigned long syscall_args[6];

    /* Get current process info */
    pid_tgid = bpf_get_current_pid_tgid();
    tgid = pid_tgid >> 32;
    pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Use BPF CORE to read syscall arguments safely */
    if (bpf_core_read(syscall_args, sizeof(syscall_args), &args->args) != 0)
        return 0;

    /* Extract fd from syscall arguments (first argument) */
    fd = (__u32)syscall_args[0];

    /* Only track if this is actually a socket */
    if (!is_socket_fd(pid, fd))
        return 0;

    now = get_timestamp_ns();
    struct network_request req = {
        .timestamp = now,
        .fd = fd,
    };
    /* Store request start time for latency calculation */
    int ret = bpf_map_update_elem(&network_request_times, &pid, &req, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }

    return 0;
}

/* Syscall tracepoint for socket receive operations completion */
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit *args)
{
    __u64 now;
    __u64 latency_ns = 0;
    __u64 bytes;
    __u32 protocol = NET_PROTO_TCP; /* Default to TCP */
    struct network_request *req;
    long ret_value;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Look up request start time */
    req = bpf_map_lookup_elem(&network_request_times, &pid);
    if (!req) {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }
    now = get_timestamp_ns();
    latency_ns = now - req->timestamp;
    __u64 sock_key = ((__u64)tgid << 32) | req->fd;
    bpf_map_delete_elem(&network_request_times, &pid);

    /* Use BPF CORE to read return value safely */
    ret_value = BPF_CORE_READ(args, ret);
    /* Check if syscall succeeded */
    if (ret_value < 0)
        return 0;
    bytes = ret_value; /* Return value is bytes received */

    /* Get actual protocol from socket info instead of assuming TCP */
    struct socket_info *info = bpf_map_lookup_elem(&socket_fd_map, &sock_key);
    if (info) {
        protocol = info->protocol;
    } else {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
    }

    /* Check if we should track this network operation */
    if (!should_sample_network(bytes, pid, tgid, protocol))
        return 0;

    /* Update statistics */
    update_network_stats(pid, tgid, NET_OP_RECEIVE, protocol, bytes, latency_ns);

    /* Send event to user space */
    struct network_event event = {
        .pid = pid,
        .tgid = tgid,
        .timestamp = now,
        .bytes = bytes,
        .operation = NET_OP_RECEIVE,
        .protocol = protocol, /* Use detected protocol */
        .local_port = 0,      /* Not available from syscall level - limitation */
        .remote_port = 0,     /* Not available from syscall level - limitation */
        .local_addr = 0,      /* Not available from syscall level - limitation */
        .remote_addr = 0,     /* Not available from syscall level - limitation */
        .latency_ns = latency_ns,
    };

    /* Get process name */
    bpf_get_current_comm(event.comm, COMM_LEN);

    /* Send event to ring buffer */
    struct network_event *ringbuf_event =
        bpf_ringbuf_reserve(&network_events, sizeof(struct network_event), 0);
    if (!ringbuf_event) {
        increment_error_counter(ERROR_RING_BUFFER_FULL);
        return 0;
    }
    *ringbuf_event = event;
    bpf_ringbuf_submit(ringbuf_event, 0);
    return 0;
}

/* Track socket creation with protocol detection */
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_create_enter(struct trace_event_raw_sys_enter *args)
{
    struct socket_info info = {0};
    unsigned long syscall_args[6];
    long type, protocol, domain;

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

    /* Extract socket arguments */
    domain = syscall_args[0];   /* domain */
    type = syscall_args[1];     /* type */
    protocol = syscall_args[2]; /* protocol */

    /* Determine protocol using both type and protocol arguments for robust detection */
    if (domain == AF_UNIX) {
        info.protocol = NET_PROTO_UNIX;
    } else if (type == SOCK_STREAM || protocol == IPPROTO_TCP) {
        info.protocol = NET_PROTO_TCP;
    } else if (type == SOCK_DGRAM || protocol == IPPROTO_UDP) {
        info.protocol = NET_PROTO_UDP;
    } else {
        /* Unknown socket type/protocol combination */
        info.protocol = NET_PROTO_TCP;
    }

    info.is_socket = 1;

    /* Store for matching with sys_exit_socket */
    int ret = bpf_map_update_elem(&socket_fd_map, &pid_tgid, &info, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }

    return 0;
}

/* Track socket creation completion */
SEC("tracepoint/syscalls/sys_exit_socket")
int trace_socket_create(struct trace_event_raw_sys_exit *args)
{
    struct socket_info *temp_info;
    struct socket_info info = {0};
    long ret, ret_value;

    /* Get current process info */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Look up the temporary socket info */
    temp_info = bpf_map_lookup_elem(&socket_fd_map, &pid_tgid);
    if (!temp_info) {
        increment_error_counter(ERROR_MAP_LOOKUP_FAILED);
        return 0;
    }
    /* Copy the protocol info */
    info = *temp_info;
    /* Remove temporary entry */
    bpf_map_delete_elem(&socket_fd_map, &pid_tgid);

    /* Check if socket creation succeeded */
    ret_value = BPF_CORE_READ(args, ret);
    if (ret_value < 0)
        return 0;
    /* Store with actual file descriptor */
    __u64 final_key = ((__u64)tgid << 32) | (__u32)ret_value;
    ret = bpf_map_update_elem(&socket_fd_map, &final_key, &info, BPF_ANY);
    if (ret != 0) {
        increment_error_counter(ERROR_MAP_UPDATE_FAILED);
    }
    return 0;
}

/* Track socket closing */
SEC("tracepoint/syscalls/sys_enter_close")
int trace_socket_close(struct trace_event_raw_sys_enter *args)
{
    __u64 key;
    __u32 fd;
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

    /* Extract fd from syscall arguments (first argument) */
    fd = (__u32)syscall_args[0];

    /* Remove fd from socket tracking */
    key = ((__u64)tgid << 32) | fd;
    bpf_map_delete_elem(&socket_fd_map, &key);

    return 0;
}

/* Enhanced process exit handler to clean up per-process network tracking */
SEC("tracepoint/sched/sched_process_exit")
int trace_network_process_exit(struct trace_event_raw_sched_process_template *args)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (__u32)pid_tgid;

    /* Filter out kernel threads */
    if (pid == 0 || tgid == 0)
        return 0;

    /* Mark network stats for cleanup by setting a special timestamp */
    /* This allows user space to identify and clean up stale entries */
    /* while preserving stats for post-mortem analysis temporarily */
    struct network_key key = {
        .pid = pid,
    };

    struct network_stats *stats = bpf_map_lookup_elem(&network_stats_map, &key);
    if (stats) {
        stats->exited = 1;
    }

    /* Note: User space should periodically clean up network entries for this PID */
    /* by checking process existence and removing stale entries marked with the special timestamp */

    return 0;
}

/* License required for eBPF programs */
char LICENSE[] SEC("license") = "Dual MIT/GPL";
