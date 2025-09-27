#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

/* BPF map definitions that are shared between kernel and user space */

/* Constants */
#define COMM_LEN 16

/* Map keys and values */
struct cpu_key {
    __u32 pid;
};

struct syscall_key {
    __u32 pid;
    __u32 syscall_nr;
};

struct io_key {
    __u32 pid;
};

struct network_key {
    __u32 pid;
};

struct memory_key {
    __u32 pid;
};

struct cpu_start_request {
    __u64 start_time_ns;
};

/* Event structures for ring buffers */
struct cpu_event {
    __u32 pid;
    __u32 tgid;
    __u32 cpu;
    __u64 timestamp;
    __u64 sched_latency_ns;
    __u64 delta_ns;
    char comm[COMM_LEN];
};

struct syscall_event {
    __u32 pid;
    __u32 tgid;
    __u32 syscall_nr;
    __u64 timestamp;
    __u64 latency_ns;
    char comm[COMM_LEN];
};

struct hpmon_io_event {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    __u64 bytes;
    __u32 operation; /* 0=read, 1=write */
    __u64 latency_ns;
    char comm[COMM_LEN];
};

struct network_request {
    __u64 timestamp;
    __u32 fd;
};

struct network_event {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    __u64 bytes;
    __u32 operation; /* 0=receive, 1=send */
    __u32 protocol;  /* 0=TCP, 1=UDP */
    __u32 local_port;
    __u32 remote_port;
    __u32 local_addr;  /* IPv4 address in network byte order */
    __u32 remote_addr; /* IPv4 address in network byte order */
    __u64 latency_ns;
    char comm[COMM_LEN];
};

/* Structure to track pending requests between enter and exit tracepoints */
struct memory_pending_request {
    __u64 size;
    __u64 timestamp;
    __u64 address;
    __u64 brk;
    __u32 request_id;
};

struct memory_event {
    __u32 pid;
    __u32 tgid;
    __u64 timestamp;
    __u64 size;
    __u64 address;
    __u32 operation; /* 0=alloc, 1=free, 2=mmap, 3=munmap, 4=brk, or page_fault types */
    __u64 latency_ns;
    char comm[COMM_LEN];
};

/* Socket information structure for protocol tracking */
struct socket_info {
    __u32 is_socket;
    __u32 protocol; /* 0=TCP, 1=UDP, 2=UNIX */
};

/* Statistics structures shared between eBPF and user space */

/* CPU statistics */
struct cpu_stats {
    __u64 cpu_time_ns;
    __u64 user_time_ns;
    __u64 sys_time_ns;
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u8 exited; /* Mark if process has exited for cleanup */
};

/* System call statistics */
struct syscall_stats {
    __u64 count;
    __u64 total_latency_ns;
    __u64 min_latency_ns;
    __u64 max_latency_ns;
    __u64 timestamp;
    __u32 pid;
    __u32 tgid;
    __u32 syscall_nr;
    __u8 category;
    __u8 exited; /* Mark if process has exited for cleanup */
};

/* I/O statistics */
struct io_stats {
    __u32 pid;
    __u32 tgid;
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_ops;
    __u64 write_ops;
    __u64 read_latency_ns;
    __u64 write_latency_ns;
    __u64 timestamp;
    __u8 exited; /* Mark if process has exited for cleanup */
};

/* Network statistics */
struct network_stats {
    __u32 pid;
    __u32 tgid;
    __u64 rx_bytes;      /* Received bytes */
    __u64 tx_bytes;      /* Transmitted bytes */
    __u64 rx_packets;    /* Received packets */
    __u64 tx_packets;    /* Transmitted packets */
    __u64 tcp_messages;  /* Number of TCP messages */
    __u64 udp_packets;   /* Number of UDP packets */
    __u64 rx_latency_ns; /* Average receive latency */
    __u64 tx_latency_ns; /* Average transmit latency */
    __u64 timestamp;
    __u8 exited; /* Mark if process has exited for cleanup */
};

/* Memory statistics */
struct memory_stats {
    __u32 pid;
    __u32 tgid;
    __u64 alloc_count;         /* Number of allocation calls */
    __u64 free_count;          /* Number of free calls */
    __u64 mmap_count;          /* Number of mmap calls */
    __u64 munmap_count;        /* Number of munmap calls */
    __u64 alloc_bytes;         /* Total bytes allocated */
    __u64 free_bytes;          /* Total bytes freed */
    __u64 mmap_bytes;          /* Total bytes mapped */
    __u64 munmap_bytes;        /* Total bytes unmapped */
    __u64 current_alloc_bytes; /* Currently allocated bytes */
    __u64 current_mmap_bytes;  /* Currently mapped bytes */
    __u64 peak_memory_bytes;   /* Peak memory usage */
    __u64 page_faults;         /* Number of page faults */
    __u64 alloc_latency_ns;    /* Total allocation latency */
    __u64 timestamp;
    __u8 exited; /* Mark if process has exited for cleanup */
};

/* I/O configuration structure */
struct io_config {
    __u64 min_bytes_threshold; /* Only track I/O larger than this */
    __u32 sample_rate;         /* Sample 1 in N requests */
    __u32 tgid;
};

/* Network configuration structure */
struct network_config {
    __u64 min_bytes_threshold; /* Only track network I/O larger than this */
    __u32 sample_rate;         /* Sample 1 in N packets */
    __u32 track_tcp_only;      /* Only track TCP connections (0=all, 1=TCP only) */
    __u32 tgid;
};

/* Memory configuration structure */
struct memory_config {
    __u32 tgid;
    __u32 sample_rate; /* Sample 1 in N processes */
};

struct cpu_config {
    __u32 sample_rate; /* Sample 1 in N processes */
    __u32 tgid;
};

struct syscall_config {
    __u64 syscall_bitmask; /* Bitmask to filter syscalls */
    __u32 tgid;
};

/* Error counter indices */
enum error_counter {
    ERROR_CONFIG_MISSING = 0,
    ERROR_MAP_UPDATE_FAILED = 1,
    ERROR_MAP_LOOKUP_FAILED = 2,
    ERROR_RING_BUFFER_FULL = 3,
    ERROR_MAX = 4
};

/* System call categories for filtering and analysis */
enum syscall_category {
    SYSCALL_CAT_FILE_IO = 0, /* read, write, open, close, etc. */
    SYSCALL_CAT_MEMORY = 1,  /* mmap, munmap, brk, etc. */
    SYSCALL_CAT_PROCESS = 2, /* fork, exec, wait, etc. */
    SYSCALL_CAT_NETWORK = 3, /* socket, connect, accept, etc. */
    SYSCALL_CAT_TIME = 4,    /* clock_gettime, nanosleep, etc. */
    SYSCALL_CAT_SIGNAL = 5,  /* kill, sigaction, etc. */
    SYSCALL_CAT_OTHER = 6,   /* everything else */
    SYSCALL_CAT_MAX = 7
};

#endif /* BPF_COMMON_H */
