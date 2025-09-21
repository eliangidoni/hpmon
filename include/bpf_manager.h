/* HPMon eBPF Program Manager Header
 *
 * This header defines the interface for loading, attaching, and managing
 * eBPF programs for CPU, syscall, and I/O monitoring.
 */

#ifndef BPF_MANAGER_H
#define BPF_MANAGER_H

#include "bpf_common.h"
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <stddef.h>

/* Forward declaration */
struct hpmon_config;

/* Maximum limits for BPF programs */
#define MAX_BPF_PROGRAMS 10
#define MAX_MAPS_PER_PROGRAM 10
#define MAX_ATTACHMENTS_PER_PROGRAM 10
#define MAX_PROGRAM_NAME_LEN 32
#define MAX_MAP_NAME_LEN 32

/* BPF program types for HPMon */
enum hpmon_bpf_program_type {
    HPMON_BPF_PROG_TYPE_CPU = 0,
    HPMON_BPF_PROG_TYPE_SYSCALL = 1,
    HPMON_BPF_PROG_TYPE_IO = 2,
    HPMON_BPF_PROG_TYPE_MEMORY = 3,
    HPMON_BPF_PROG_TYPE_NETWORK = 4,
    HPMON_BPF_PROG_MAX = 5
};

/* BPF map information for HPMon */
struct hpmon_bpf_map_info {
    char name[MAX_MAP_NAME_LEN];
    int fd;
};

/* BPF program information */
struct bpf_program_info {
    char name[MAX_PROGRAM_NAME_LEN];
    enum hpmon_bpf_program_type type;
    struct bpf_object *obj;
    struct bpf_link *links[MAX_ATTACHMENTS_PER_PROGRAM];
    int attachment_count;
    struct hpmon_bpf_map_info map_fds[MAX_MAPS_PER_PROGRAM];
    int map_count;
    bool loaded;
    bool attached;
    struct ring_buffer *ring_buffer; /* Ring buffer for events */
    const void *config;
};

/* BPF manager state */
struct bpf_manager {
    struct bpf_program_info programs[MAX_BPF_PROGRAMS];
    int programs_loaded;
    const struct hpmon_config *config;
};

/* BPF manager statistics */
struct bpf_manager_stats {
    int programs_loaded;
    int programs_attached;
    int total_maps;
    int total_attachments;
    uint64_t error_counters[HPMON_BPF_PROG_MAX][ERROR_MAX];
};

/* Function declarations */

/**
 * Initialize the BPF manager
 * @param config: HPMon configuration
 * @returns 0 on success, negative on error
 */
int bpf_manager_init(const struct hpmon_config *config);

/**
 * Load all enabled eBPF programs
 * @returns 0 on success, negative on error
 */
int bpf_manager_load_programs(void);

/**
 * Attach all loaded eBPF programs
 * @returns 0 on success, negative on error
 */
int bpf_manager_attach_programs(void);

/**
 * Detach all eBPF programs
 * @returns 0 on success, negative on error
 */
int bpf_manager_detach_programs(void);

/**
 * Cleanup BPF manager and all programs
 */
void bpf_manager_cleanup(void);

/**
 * Get BPF map file descriptor
 * @param prog_name: Program name
 * @param map_name: Map name
 * @returns Map file descriptor or negative on error
 */
int bpf_manager_get_map_fd(const char *prog_name, const char *map_name);

/**
 * Get program statistics
 * @param stats: Output statistics structure
 * @returns 0 on success, negative on error
 */
int bpf_manager_get_stats(struct bpf_manager_stats *stats);

/**
 * Check if all programs are healthy
 * @returns true if all programs are working, false otherwise
 */
bool bpf_manager_health_check(void);

/**
 * Poll ring buffers for events (non-blocking)
 * @param timeout_ms: Timeout in milliseconds (0 for non-blocking)
 * @returns 0 on success, negative on error
 */
int bpf_manager_poll_events(int timeout_ms);

/**
 * Cleanup old entries from BPF maps
 * @returns Number of entries cleaned up, negative on error
 */
int bpf_manager_cleanup_maps(void);

#endif /* BPF_MANAGER_H */
