// SPDX-License-Identifier: MIT
/* HPMon eBPF Program Manager
 *
 * This module handles loading, attaching, and managing eBPF programs
 * for CPU, syscall, and I/O monitoring. It provides a unified interface
 * for managing the lifecycle of all eBPF components.
 */

#include "bpf_manager.h"
#include "hpmon.h"
#include "safe_string.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

/* BPF manager constants */
#define RING_BUFFER_SIZE (256 * 1024) /* 256KB ring buffer */
#define DEFAULT_BPF_MAP_MAX_AGE_SECONDS 30
#define NANOSECONDS_PER_SECOND 1000000000ULL
#define PID_SHIFT_BITS 32
#define PROC_PATH_BUFFER_SIZE 64
#define MAX_CPUS 128 /* Maximum number of CPUs to handle */
#define MAX_TASKS 4096

/* Global BPF manager state */
static struct bpf_manager g_bpf_manager = {0};
static bool g_manager_initialized = false;
static FILE *g_event_log_fp = NULL;

/* Ring buffer event callback function prototypes */
static int handle_cpu_event(void *ctx, void *data, size_t size);
static int handle_syscall_event(void *ctx, void *data, size_t size);
static int handle_io_event(void *ctx, void *data, size_t size);
static int handle_memory_event(void *ctx, void *data, size_t size);
static int handle_network_event(void *ctx, void *data, size_t size);

/* Map cleanup helper function prototypes */
static int cleanup_network_stats_map(int network_stats_fd, int socket_fd_map_fd,
                                     int request_times_fd);
static int cleanup_memory_allocation_maps(int memory_stats_fd, int memory_request_times_fd);
static int cleanup_cpu_stats_maps(int cpu_stats_fd, int process_start_times_fd);
static int cleanup_syscall_stats_maps(int syscall_stats_fd, int syscall_entry_fd);
static int cleanup_io_stats_maps(int io_stats_fd, int io_request_times_fd);

/* Forward declarations */
static int load_prog_info(struct bpf_program_info *prog_info, const char *obj_path);
static int attach_tracepoints(struct bpf_program_info *prog_info);
static int detach_tracepoints(struct bpf_program_info *prog_info);
static void cleanup_program(struct bpf_program_info *prog_info);
static int setup_ring_buffers(struct bpf_program_info *prog_info);
static void cleanup_ring_buffers(struct bpf_program_info *prog_info);

/* eBPF program file paths (relative to binary location) */
#define CPU_MONITOR_OBJ_PATH "build/bpf/cpu_monitor.bpf.o"
#define SYSCALL_MONITOR_OBJ_PATH "build/bpf/syscall_monitor.bpf.o"
#define IO_MONITOR_OBJ_PATH "build/bpf/io_monitor.bpf.o"
#define MEMORY_MONITOR_OBJ_PATH "build/bpf/memory_monitor.bpf.o"
#define NETWORK_MONITOR_OBJ_PATH "build/bpf/network_monitor.bpf.o"

/* Error handling helper */
#define LOG_BPF_ERROR(operation, prog_name)                                                        \
    fprintf(stderr, "BPF Manager: Failed to %s for %s: %s\n", operation, prog_name, strerror(errno))

/* Initialize BPF manager */
int bpf_manager_init(const struct hpmon_config *config)
{
    if (!config) {
        return -EINVAL;
    }

    if (g_manager_initialized) {
        return -EALREADY;
    }

    /* Initialize manager state */
    memset(&g_bpf_manager, 0, sizeof(g_bpf_manager));
    g_bpf_manager.config = config;
    g_bpf_manager.programs_loaded = 0;

    /* Set libbpf error and debug info callback */
    libbpf_set_print(NULL); /* Disable verbose output for now */

    /* Open event log file if specified */
    if (config->event_log_file[0] != '\0') {
        g_event_log_fp = fopen(config->event_log_file, "a");
        if (!g_event_log_fp) {
            fprintf(stderr, "BPF Manager: Failed to open event log file '%s': %s\n",
                    config->event_log_file, strerror(errno));
        }
    }

    printf("BPF Manager: Initializing eBPF program management...\n");

    g_manager_initialized = true;
    return 0;
}

/* Load all enabled eBPF programs */
int bpf_manager_load_programs(void)
{
    int ret = 0;
    int loaded_count = 0;

    if (!g_manager_initialized) {
        return -EINVAL;
    }

    printf("BPF Manager: Loading eBPF programs...\n");

    /* Load CPU monitor if enabled */
    if (g_bpf_manager.config->monitor_cpu) {
        struct bpf_program_info *cpu_prog = &g_bpf_manager.programs[loaded_count];
        /* Initialize program metadata before loading */
        safe_strcpy(cpu_prog->name, sizeof(cpu_prog->name), "cpu_monitor");
        cpu_prog->type = HPMON_BPF_PROG_TYPE_CPU;
        cpu_prog->loaded = false; /* Explicitly set to false before loading */
        cpu_prog->config = &g_bpf_manager.config->bpf.cpu;

        ret = load_prog_info(cpu_prog, CPU_MONITOR_OBJ_PATH);
        if (ret == 0) {
            cpu_prog->loaded = true;
            loaded_count++;
            printf("  CPU monitor: loaded\n");
        } else {
            /* Reset program info on failure */
            memset(cpu_prog, 0, sizeof(*cpu_prog));
            LOG_BPF_ERROR("load", "CPU monitor");
            goto cleanup;
        }
    }

    /* Load syscall monitor if enabled */
    if (g_bpf_manager.config->monitor_syscalls) {
        struct bpf_program_info *syscall_prog = &g_bpf_manager.programs[loaded_count];
        /* Initialize program metadata before loading */
        safe_strcpy(syscall_prog->name, sizeof(syscall_prog->name), "syscall_monitor");
        syscall_prog->type = HPMON_BPF_PROG_TYPE_SYSCALL;
        syscall_prog->loaded = false; /* Explicitly set to false before loading */
        syscall_prog->config = &g_bpf_manager.config->bpf.sys;

        ret = load_prog_info(syscall_prog, SYSCALL_MONITOR_OBJ_PATH);
        if (ret == 0) {
            syscall_prog->loaded = true;
            loaded_count++;
            printf("  Syscall monitor: loaded\n");
        } else {
            /* Reset program info on failure */
            memset(syscall_prog, 0, sizeof(*syscall_prog));
            LOG_BPF_ERROR("load", "syscall monitor");
            goto cleanup;
        }
    }

    /* Load I/O monitor if enabled */
    if (g_bpf_manager.config->monitor_io) {
        struct bpf_program_info *io_prog = &g_bpf_manager.programs[loaded_count];
        /* Initialize program metadata before loading */
        safe_strcpy(io_prog->name, sizeof(io_prog->name), "io_monitor");
        io_prog->type = HPMON_BPF_PROG_TYPE_IO;
        io_prog->loaded = false; /* Explicitly set to false before loading */
        io_prog->config = &g_bpf_manager.config->bpf.io;

        ret = load_prog_info(io_prog, IO_MONITOR_OBJ_PATH);
        if (ret == 0) {
            io_prog->loaded = true;
            loaded_count++;
            printf("  I/O monitor: loaded\n");
        } else {
            /* Reset program info on failure */
            memset(io_prog, 0, sizeof(*io_prog));
            LOG_BPF_ERROR("load", "I/O monitor");
            goto cleanup;
        }
    }

    /* Load memory monitor if enabled */
    if (g_bpf_manager.config->monitor_memory) {
        struct bpf_program_info *memory_prog = &g_bpf_manager.programs[loaded_count];
        /* Initialize program metadata before loading */
        safe_strcpy(memory_prog->name, sizeof(memory_prog->name), "memory_monitor");
        memory_prog->type = HPMON_BPF_PROG_TYPE_MEMORY;
        memory_prog->loaded = false; /* Explicitly set to false before loading */
        memory_prog->config = &g_bpf_manager.config->bpf.mem;

        ret = load_prog_info(memory_prog, MEMORY_MONITOR_OBJ_PATH);
        if (ret == 0) {
            memory_prog->loaded = true;
            loaded_count++;
            printf("  Memory monitor: loaded\n");
        } else {
            /* Reset program info on failure */
            memset(memory_prog, 0, sizeof(*memory_prog));
            LOG_BPF_ERROR("load", "memory monitor");
            goto cleanup;
        }
    }

    /* Load network monitor if enabled */
    if (g_bpf_manager.config->monitor_network) {
        struct bpf_program_info *network_prog = &g_bpf_manager.programs[loaded_count];
        /* Initialize program metadata before loading */
        safe_strcpy(network_prog->name, sizeof(network_prog->name), "network_monitor");
        network_prog->type = HPMON_BPF_PROG_TYPE_NETWORK;
        network_prog->loaded = false; /* Explicitly set to false before loading */
        network_prog->config = &g_bpf_manager.config->bpf.net;

        ret = load_prog_info(network_prog, NETWORK_MONITOR_OBJ_PATH);
        if (ret == 0) {
            network_prog->loaded = true;
            loaded_count++;
            printf("  Network monitor: loaded\n");
        } else {
            /* Reset program info on failure */
            memset(network_prog, 0, sizeof(*network_prog));
            LOG_BPF_ERROR("load", "network monitor");
            goto cleanup;
        }
    }

    g_bpf_manager.programs_loaded = loaded_count;
    printf("BPF Manager: Successfully loaded %d eBPF programs\n", loaded_count);
    return 0;

cleanup:
    /* Clean up any successfully loaded programs */
    for (int i = 0; i < loaded_count; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];
        prog->loaded = false; /* Reset loaded flag before cleanup */
        cleanup_program(prog);
    }
    g_bpf_manager.programs_loaded = 0;
    return ret;
}

/* Attach all loaded eBPF programs */
int bpf_manager_attach_programs(void)
{
    int ret = 0;
    int attached_count = 0;

    if (!g_manager_initialized || g_bpf_manager.programs_loaded == 0) {
        return -EINVAL;
    }

    printf("BPF Manager: Attaching eBPF programs...\n");

    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded) {
            continue;
        }

        /* Attach tracepoints */
        ret = attach_tracepoints(prog);
        if (ret != 0) {
            LOG_BPF_ERROR("attach tracepoints", prog->name);
            goto cleanup;
        }

        /* Setup ring buffers for event collection */
        ret = setup_ring_buffers(prog);
        if (ret != 0) {
            LOG_BPF_ERROR("setup ring buffers", prog->name);
            detach_tracepoints(prog);
            goto cleanup;
        }

        prog->attached = true;
        attached_count++;
        printf("  %s: attached\n", prog->name);
    }

    printf("BPF Manager: Successfully attached %d eBPF programs\n", attached_count);
    return 0;

cleanup:
    /* Detach any successfully attached programs */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];
        if (prog->attached) {
            detach_tracepoints(prog);
            cleanup_ring_buffers(prog);
            prog->attached = false;
        }
    }
    return ret;
}

/* Detach all eBPF programs */
int bpf_manager_detach_programs(void)
{
    if (!g_manager_initialized) {
        return -EINVAL;
    }

    printf("BPF Manager: Detaching eBPF programs...\n");

    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (prog->attached) {
            detach_tracepoints(prog);
            cleanup_ring_buffers(prog);
            prog->attached = false;
            printf("  %s: detached\n", prog->name);
        }
    }

    return 0;
}

/* Cleanup BPF manager and all programs */
void bpf_manager_cleanup(void)
{
    /* Close event log file if open */
    if (g_event_log_fp) {
        fclose(g_event_log_fp);
        g_event_log_fp = NULL;
    }

    if (!g_manager_initialized) {
        return;
    }

    printf("BPF Manager: Cleaning up eBPF programs...\n");

    /* Detach programs first */
    bpf_manager_detach_programs();

    /* Clean up loaded programs */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        cleanup_program(&g_bpf_manager.programs[i]);
    }

    /* Reset state */
    memset(&g_bpf_manager, 0, sizeof(g_bpf_manager));
    g_manager_initialized = false;

    printf("BPF Manager: Cleanup complete\n");
}

/* Get BPF map file descriptor */
int bpf_manager_get_map_fd(const char *prog_name, const char *map_name)
{
    if (!g_manager_initialized || !prog_name || !map_name) {
        return -EINVAL;
    }

    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (strcmp(prog->name, prog_name) == 0 && prog->loaded) {
            /* Find the map by name */
            for (int j = 0; j < prog->map_count && j < MAX_MAPS_PER_PROGRAM; j++) {
                if (strcmp(prog->map_fds[j].name, map_name) == 0) {
                    int map_fd = prog->map_fds[j].fd;
                    /* Validate that the file descriptor is still valid */
                    if (map_fd < 0) {
                        return -EBADF;
                    }
                    /* Additional validation: check if map_fd is still accessible */
                    if (fcntl(map_fd, F_GETFD) == -1) {
                        return -EBADF;
                    }
                    return map_fd;
                }
            }
        }
    }

    return -ENOENT;
}

/* Get program statistics */
int bpf_manager_get_stats(struct bpf_manager_stats *stats)
{
    if (!g_manager_initialized || !stats) {
        return -EINVAL;
    }

    memset(stats, 0, sizeof(*stats));
    stats->programs_loaded = g_bpf_manager.programs_loaded;

    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];
        if (prog->attached) {
            stats->programs_attached++;
        }
        stats->total_maps += prog->map_count;
        stats->total_attachments += prog->attachment_count;

        if (!prog->loaded) {
            continue;
        }
        int error_counters_fd = -1;
        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "error_counters") == 0) {
                error_counters_fd = prog->map_fds[j].fd;
                break;
            }
        }
        if (error_counters_fd < 0) {
            fprintf(stderr, "Failed to find error map for %s\n", prog->name);
            continue;
        }
        /* Read error counters from the map */
        for (int err_type = 0; err_type < ERROR_MAX; err_type++) {
            uint32_t key = err_type;
            uint64_t value = 0;
            if (bpf_map_lookup_elem(error_counters_fd, &key, &value) == 0) {
                stats->error_counters[prog->type][err_type] = value;
            } else {
                fprintf(stderr, "Failed to lookup counter for %s\n", prog->name);
            }
        }
    }

    return 0;
}

/* Check if all programs are healthy */
bool bpf_manager_health_check(void)
{
    if (!g_manager_initialized) {
        return false;
    }

    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (prog->loaded && !prog->attached) {
            return false; /* Program loaded but not attached */
        }

        /* Check if BPF object is still valid */
        if (prog->obj == NULL) {
            return false;
        }
    }

    return true;
}

/* Load BPF monitor program */
static int load_prog_info(struct bpf_program_info *prog_info, const char *obj_path)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    int err;

    /* Load the BPF object file */
    obj = bpf_object__open(obj_path);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open %s BPF object: %s\n", obj_path,
                strerror((int)-libbpf_get_error(obj)));
        return -ENOENT;
    }

    /* Load the BPF object into the kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load %s BPF object: %s\n", obj_path, strerror(-err));
        bpf_object__close(obj);
        return -ENOEXEC;
    }

    prog_info->obj = obj;
    prog_info->map_count = 0;

    int config_map_fd = -1;
    /* Get map file descriptors */
    bpf_object__for_each_map(map, obj)
    {
        if (prog_info->map_count >= MAX_MAPS_PER_PROGRAM) {
            fprintf(stderr,
                    "Warning: %s exceeded maximum maps limit (%d), ignoring additional maps\n",
                    obj_path, MAX_MAPS_PER_PROGRAM);
            break;
        }

        const char *map_name = bpf_map__name(map);
        int map_fd = bpf_map__fd(map);

        if (map_fd >= 0) {
            if (strcmp(map_name, "config_map") == 0) {
                config_map_fd = map_fd;
            }
            safe_strcpy(prog_info->map_fds[prog_info->map_count].name,
                        sizeof(prog_info->map_fds[prog_info->map_count].name), map_name);
            prog_info->map_fds[prog_info->map_count].fd = map_fd;
            prog_info->map_count++;
        }
    }

    // Load config
    if (config_map_fd < 0) {
        fprintf(stderr, "Failed to find config map for %s\n", prog_info->name);
        bpf_object__close(obj);
        return -EINVAL;
    }
    __u32 key = 0;
    err = bpf_map_update_elem(config_map_fd, &key, prog_info->config, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update config map for %s: %s\n", prog_info->name,
                strerror(-err));
        bpf_object__close(obj);
        return err;
    }

    return 0;
}

/* Attach tracepoints for a program */
static int attach_tracepoints(struct bpf_program_info *prog_info)
{
    struct bpf_program *prog;
    struct bpf_link *link;
    int attached = 0;

    if (!prog_info->obj) {
        return -EINVAL;
    }

    /* Initialize attachment count */
    prog_info->attachment_count = 0;

    /* Attach all programs in the object */
    bpf_object__for_each_program(prog, prog_info->obj)
    {
        if (attached >= MAX_ATTACHMENTS_PER_PROGRAM) {
            fprintf(stderr,
                    "Warning: Program %s exceeded maximum attachments limit (%d), ignoring "
                    "additional programs\n",
                    prog_info->name, MAX_ATTACHMENTS_PER_PROGRAM);
            break;
        }

        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
            fprintf(stderr, "Failed to attach BPF program %s: %s\n", bpf_program__name(prog),
                    strerror((int)-libbpf_get_error(link)));
            goto cleanup;
        }

        prog_info->links[attached] = link;
        attached++;
    }

    prog_info->attachment_count = attached;
    return 0;

cleanup:
    /* Clean up any successful attachments */
    for (int i = 0; i < attached; i++) {
        if (prog_info->links[i]) {
            bpf_link__destroy(prog_info->links[i]);
            prog_info->links[i] = NULL;
        }
    }
    prog_info->attachment_count = 0;
    return -ENODEV;
}

/* Detach tracepoints for a program */
static int detach_tracepoints(struct bpf_program_info *prog_info)
{
    for (int i = 0; i < prog_info->attachment_count; i++) {
        if (prog_info->links[i]) {
            bpf_link__destroy(prog_info->links[i]);
            prog_info->links[i] = NULL;
        }
    }
    prog_info->attachment_count = 0;
    return 0;
}

/* Setup ring buffers for event collection */
static int setup_ring_buffers(struct bpf_program_info *prog_info)
{
    struct ring_buffer *ring_buffer = NULL;
    int map_fd = -1;

    /* Find the events map for this program type */
    const char *events_map_name = NULL;
    ring_buffer_sample_fn sample_cb = NULL;

    switch (prog_info->type) {
    case HPMON_BPF_PROG_TYPE_CPU:
        events_map_name = "cpu_events";
        sample_cb = handle_cpu_event;
        break;
    case HPMON_BPF_PROG_TYPE_SYSCALL:
        events_map_name = "syscall_events";
        sample_cb = handle_syscall_event;
        break;
    case HPMON_BPF_PROG_TYPE_IO:
        events_map_name = "io_events";
        sample_cb = handle_io_event;
        break;
    case HPMON_BPF_PROG_TYPE_MEMORY:
        events_map_name = "memory_events";
        sample_cb = handle_memory_event;
        break;
    case HPMON_BPF_PROG_TYPE_NETWORK:
        events_map_name = "network_events";
        sample_cb = handle_network_event;
        break;
    default:
        /* No events map for this program type */
        prog_info->ring_buffer = NULL;
        return 0;
    }

    /* Find the events map file descriptor */
    for (int i = 0; i < prog_info->map_count; i++) {
        if (strcmp(prog_info->map_fds[i].name, events_map_name) == 0) {
            map_fd = prog_info->map_fds[i].fd;
            break;
        }
    }

    if (map_fd < 0) {
        /* No events map found - this might be normal for some programs */
        prog_info->ring_buffer = NULL;
        return 0;
    }

    /* Create ring buffer */
    ring_buffer = ring_buffer__new(map_fd, sample_cb, prog_info, NULL);
    if (!ring_buffer) {
        fprintf(stderr, "Failed to create ring buffer for %s: %s\n", prog_info->name,
                strerror(errno));
        return -1;
    }

    prog_info->ring_buffer = ring_buffer;

    printf("Setup ring buffer for %s program (map: %s, fd: %d)\n", prog_info->name, events_map_name,
           map_fd);

    return 0;
}

/* Cleanup ring buffers */
static void cleanup_ring_buffers(struct bpf_program_info *prog_info)
{
    if (prog_info->ring_buffer) {
        ring_buffer__free(prog_info->ring_buffer);
        prog_info->ring_buffer = NULL;
        printf("Cleaned up ring buffer for %s program\n", prog_info->name);
    }
}

/* Cleanup a single program */
static void cleanup_program(struct bpf_program_info *prog_info)
{
    if (!prog_info) {
        return;
    }

    /* Mark program as being cleaned up to prevent concurrent access */
    prog_info->loaded = false;
    prog_info->attached = false;

    /* Detach if still attached */
    if (prog_info->attachment_count > 0) {
        detach_tracepoints(prog_info);
        cleanup_ring_buffers(prog_info);
    }

    /* Close BPF object */
    if (prog_info->obj) {
        bpf_object__close(prog_info->obj);
        prog_info->obj = NULL;
    }

    /* Reset program info - do this last to prevent race conditions */
    memset(prog_info, 0, sizeof(*prog_info));
}

/* Event handler callbacks for ring buffers */

/* Handle CPU monitoring events */
static int handle_cpu_event(void *ctx, void *data, size_t size)
{
    struct bpf_program_info *prog_info = (struct bpf_program_info *)ctx;
    if (!g_event_log_fp) {
        return 0; /* No logging if event log file is not set */
    }

    /* Parse the CPU event data based on cpu_event structure from bpf_common.h */
    if (size < sizeof(struct cpu_event)) {
        fprintf(stderr, "(%s) CPU event too small: %zu bytes\n", prog_info->name, size);
        return 0;
    }

    struct cpu_event *event = (struct cpu_event *)data;

    /* Log or process the event - in a real implementation, this would
     * forward to the appropriate data collection module */
    fprintf(g_event_log_fp,
            "CPU Event: PID=%u TID=%u CPU=%u DELTA_NS=%llu TIMESTAMP=%llu COMM=%s\n", event->tgid,
            event->pid, event->cpu, event->delta_ns, event->timestamp, event->comm);
    fflush(g_event_log_fp);

    return 0;
}

/* Handle syscall monitoring events */
static int handle_syscall_event(void *ctx, void *data, size_t size)
{
    struct bpf_program_info *prog_info = (struct bpf_program_info *)ctx;
    if (!g_event_log_fp) {
        return 0; /* No logging if event log file is not set */
    }

    if (size < sizeof(struct syscall_event)) {
        fprintf(stderr, "(%s) Syscall event too small: %zu bytes\n", prog_info->name, size);
        return 0;
    }

    struct syscall_event *event = (struct syscall_event *)data;
    fprintf(g_event_log_fp,
            "Syscall Event: PID=%u TID=%u SYSCALL_NR=%u LATENCY_NS=%llu TIMESTAMP=%llu COMM=%s\n",
            event->tgid, event->pid, event->syscall_nr, event->latency_ns, event->timestamp,
            event->comm);
    fflush(g_event_log_fp);
    return 0;
}

/* Handle I/O monitoring events */
static int handle_io_event(void *ctx, void *data, size_t size)
{
    struct bpf_program_info *prog_info = (struct bpf_program_info *)ctx;
    if (!g_event_log_fp) {
        return 0; /* No logging if event log file is not set */
    }

    if (size < sizeof(struct hpmon_io_event)) {
        fprintf(stderr, "(%s) I/O event too small: %zu bytes\n", prog_info->name, size);
        return 0;
    }

    struct hpmon_io_event *event = (struct hpmon_io_event *)data;

    fprintf(
        g_event_log_fp,
        "I/O Event: PID=%u TID=%u BYTES=%llu LATENCY_NS=%llu OPERATION=%u TIMESTAMP=%llu COMM=%s\n",
        event->tgid, event->pid, event->bytes, event->latency_ns, event->operation,
        event->timestamp, event->comm);
    fflush(g_event_log_fp);
    return 0;
}

/* Handle memory monitoring events */
static int handle_memory_event(void *ctx, void *data, size_t size)
{
    struct bpf_program_info *prog_info = (struct bpf_program_info *)ctx;
    if (!g_event_log_fp) {
        return 0; /* No logging if event log file is not set */
    }

    if (size < sizeof(struct memory_event)) {
        fprintf(stderr, "(%s) Memory event too small: %zu bytes\n", prog_info->name, size);
        return 0;
    }

    struct memory_event *event = (struct memory_event *)data;

    fprintf(g_event_log_fp,
            "Memory Event: PID=%u TID=%u SIZE=%llu OPERATION=%u TIMESTAMP=%llu COMM=%s\n",
            event->tgid, event->pid, event->size, event->operation, event->timestamp, event->comm);
    fflush(g_event_log_fp);
    return 0;
}

/* Handle network monitoring events */
static int handle_network_event(void *ctx, void *data, size_t size)
{
    struct bpf_program_info *prog_info = (struct bpf_program_info *)ctx;
    if (!g_event_log_fp) {
        return 0; /* No logging if event log file is not set */
    }
    if (size < sizeof(struct network_event)) {
        fprintf(stderr, "(%s) Network event too small: %zu bytes\n", prog_info->name, size);
        return 0;
    }

    struct network_event *event = (struct network_event *)data;

    fprintf(g_event_log_fp,
            "Network Event: PID=%u TID=%u BYTES=%llu LATENCY_NS=%llu OPERATION=%u PROTOCOL=%u "
            "TIMESTAMP=%llu COMM=%s\n",
            event->tgid, event->pid, event->bytes, event->latency_ns, event->operation,
            event->protocol, event->timestamp, event->comm);
    fflush(g_event_log_fp);
    return 0;
}

/* Poll ring buffers for events */
int bpf_manager_poll_events(int timeout_ms)
{
    if (!g_manager_initialized) {
        return -EINVAL;
    }

    int events_processed = 0;

    /* Poll all active ring buffers */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded || !prog->ring_buffer) {
            continue;
        }

        /* Poll this ring buffer */
        int ret = ring_buffer__poll(prog->ring_buffer, timeout_ms);
        if (ret < 0) {
            fprintf(stderr, "Error polling ring buffer for %s: %s\n", prog->name, strerror(-ret));
            return ret;
        }

        events_processed += ret;

        /* Only use timeout for the first buffer, then set to non-blocking mode */
        timeout_ms = 0;
    }

    return events_processed;
}
int bpf_manager_cleanup_maps(void)
{
    if (!g_manager_initialized) {
        return -1;
    }

    int total_cleaned = 0;

    /* Cleanup network monitor maps */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded || strstr(prog->name, "network") == NULL) {
            continue;
        }

        /* Find network request tracking maps */
        int request_times_fd = -1;
        int socket_fd_map_fd = -1;
        int network_stats_fd = -1;

        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "network_request_times") == 0) {
                request_times_fd = prog->map_fds[j].fd;
            } else if (strcmp(prog->map_fds[j].name, "socket_fd_map") == 0) {
                socket_fd_map_fd = prog->map_fds[j].fd;
            } else if (strcmp(prog->map_fds[j].name, "network_stats_map") == 0) {
                network_stats_fd = prog->map_fds[j].fd;
            }
        }

        /* Cleanup network stats map - remove entries marked as exited */
        if (network_stats_fd >= 0 || socket_fd_map_fd >= 0 || request_times_fd >= 0) {
            total_cleaned +=
                cleanup_network_stats_map(network_stats_fd, socket_fd_map_fd, request_times_fd);
        }
    }

    /* Cleanup memory monitor maps */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded || strstr(prog->name, "memory") == NULL) {
            continue;
        }

        /* Find memory allocation tracking maps */
        int memory_stats_fd = -1;
        int memory_request_times_fd = -1;

        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "memory_stats_map") == 0) {
                memory_stats_fd = prog->map_fds[j].fd;
            } else if (strcmp(prog->map_fds[j].name, "memory_request_times") == 0) {
                memory_request_times_fd = prog->map_fds[j].fd;
            }
        }

        /* Cleanup memory allocation tracking maps */
        if (memory_stats_fd >= 0 || memory_request_times_fd >= 0) {
            total_cleaned +=
                cleanup_memory_allocation_maps(memory_stats_fd, memory_request_times_fd);
        }
    }

    /* Cleanup CPU monitor maps */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded || strstr(prog->name, "cpu") == NULL) {
            continue;
        }

        /* Find CPU stats tracking maps */
        int cpu_stats_fd = -1;
        int process_start_times_fd = -1;

        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "cpu_stats_map") == 0) {
                cpu_stats_fd = prog->map_fds[j].fd;
            } else if (strcmp(prog->map_fds[j].name, "process_start_times") == 0) {
                process_start_times_fd = prog->map_fds[j].fd;
            }
        }

        /* Cleanup CPU stats tracking maps */
        if (cpu_stats_fd >= 0 || process_start_times_fd >= 0) {
            total_cleaned += cleanup_cpu_stats_maps(cpu_stats_fd, process_start_times_fd);
        }
    }

    /* Cleanup syscall monitor maps */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded || strstr(prog->name, "syscall") == NULL) {
            continue;
        }

        /* Find syscall stats tracking maps */
        int syscall_stats_fd = -1;
        int syscall_entry_fd = -1;
        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "syscall_stats_map") == 0) {
                syscall_stats_fd = prog->map_fds[j].fd;
            }
        }

        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "syscall_entry_times") == 0) {
                syscall_entry_fd = prog->map_fds[j].fd;
            }
        }

        /* Cleanup syscall stats tracking maps */
        if (syscall_stats_fd >= 0 || syscall_entry_fd >= 0) {
            total_cleaned += cleanup_syscall_stats_maps(syscall_stats_fd, syscall_entry_fd);
        }
    }

    /* Cleanup I/O monitor maps */
    for (int i = 0; i < g_bpf_manager.programs_loaded; i++) {
        struct bpf_program_info *prog = &g_bpf_manager.programs[i];

        if (!prog->loaded || strstr(prog->name, "io") == NULL) {
            continue;
        }

        /* Find I/O stats tracking maps */
        int io_stats_fd = -1;
        int io_request_times_fd = -1;

        for (int j = 0; j < prog->map_count; j++) {
            if (strcmp(prog->map_fds[j].name, "io_stats_map") == 0) {
                io_stats_fd = prog->map_fds[j].fd;
            } else if (strcmp(prog->map_fds[j].name, "io_request_times") == 0) {
                io_request_times_fd = prog->map_fds[j].fd;
            }
        }

        /* Cleanup I/O stats tracking maps */
        if (io_stats_fd >= 0 || io_request_times_fd >= 0) {
            total_cleaned += cleanup_io_stats_maps(io_stats_fd, io_request_times_fd);
        }
    }
    if (g_event_log_fp && total_cleaned > 0) {
        const struct hpmon_config *g_config = g_bpf_manager.config;
        fprintf(g_event_log_fp, "BPF cleanup: removed %d old map entries (interval: %us)\n",
                total_cleaned, g_config->bpf_cleanup_interval_seconds);
        fflush(g_event_log_fp);
    }
    return total_cleaned;
}

/* Helper function to cleanup network stats map */
static int cleanup_network_stats_map(int network_stats_fd, int socket_fd_map_fd,
                                     int request_times_fd)
{
    int cleaned_count = 0;
    int nr_cpus, ret;
    uint32_t exited_pids[MAX_TASKS];
    int exited_pids_count = 0;

    /* Get number of possible CPUs for PERCPU map handling */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs for network cleanup: %s\n",
                strerror(-nr_cpus));
        return 0;
    }
    if (nr_cpus > MAX_CPUS) {
        nr_cpus = MAX_CPUS;
    }

    if (network_stats_fd >= 0 && request_times_fd >= 0) {
        struct network_key key, next_key;
        struct network_stats stats[MAX_CPUS]; /* Array for per-CPU values */
        uint32_t next_req_key;

        key.pid = 0;
        while (bpf_map_get_next_key(network_stats_fd, &key, &next_key) == 0 &&
               exited_pids_count < MAX_TASKS) {
            ret = bpf_map_lookup_elem(network_stats_fd, &next_key, stats);
            if (ret == 0) {
                /* Check if any CPU entry is marked as exited */
                bool process_exited = false;
                for (int cpu = 0; cpu < nr_cpus; cpu++) {
                    if (stats[cpu].exited) {
                        process_exited = true;
                        break;
                    }
                }
                if (process_exited) {
                    next_req_key = next_key.pid;
                    /* Process is marked as exited, remove from map */
                    bpf_map_delete_elem(network_stats_fd, &next_key);
                    bpf_map_delete_elem(request_times_fd, &next_req_key);
                    cleaned_count += 2;
                    exited_pids[exited_pids_count] = next_key.pid;
                    exited_pids_count++;
                }
            }
            key = next_key;
        }
    }

    if (socket_fd_map_fd >= 0) {
        uint64_t key, next_key;
        struct socket_info sock_info;

        key = 0;
        while (bpf_map_get_next_key(socket_fd_map_fd, &key, &next_key) == 0) {
            ret = bpf_map_lookup_elem(socket_fd_map_fd, &next_key, &sock_info);
            if (ret == 0) {
                /* Extract PID from key (upper 32 bits) */
                uint32_t tgid = (uint32_t)(next_key >> PID_SHIFT_BITS);
                for (int i = 0; i < exited_pids_count; i++) {
                    if (tgid == exited_pids[i]) {
                        /* Process is marked as exited, remove from map */
                        bpf_map_delete_elem(socket_fd_map_fd, &next_key);
                        cleaned_count++;
                        break;
                    }
                }
            }
            key = next_key;
        }
    }

    return cleaned_count;
}

/* Helper function to cleanup memory allocation tracking maps */
static int cleanup_memory_allocation_maps(int memory_stats_fd, int memory_request_times_fd)
{
    int cleaned_count = 0;
    int nr_cpus;

    /* Get number of possible CPUs for PERCPU map handling */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs for memory cleanup: %s\n",
                strerror(-nr_cpus));
        return 0;
    }
    if (nr_cpus > MAX_CPUS) {
        nr_cpus = MAX_CPUS;
    }

    /* Cleanup memory stats map - remove entries for processes marked as exited */
    if (memory_stats_fd >= 0 && memory_request_times_fd >= 0) {
        struct memory_key key, next_key;
        struct memory_stats stats[MAX_CPUS];
        int ret;
        uint32_t next_req_key;

        key.pid = 0;
        while (bpf_map_get_next_key(memory_stats_fd, &key, &next_key) == 0) {
            ret = bpf_map_lookup_elem(memory_stats_fd, &next_key, stats);
            if (ret == 0) {
                /* Check if this process is marked as exited */
                bool process_exited = false;
                for (int cpu = 0; cpu < nr_cpus; cpu++) {
                    if (stats[cpu].exited) {
                        process_exited = true;
                        break;
                    }
                }
                if (process_exited) {
                    next_req_key = next_key.pid;
                    /* Process is marked as exited, remove from map */
                    bpf_map_delete_elem(memory_stats_fd, &next_key);
                    bpf_map_delete_elem(memory_request_times_fd, &next_req_key);
                    cleaned_count += 2;
                }
            }
            key = next_key;
        }
    }

    return cleaned_count;
}

/* Helper function to cleanup CPU stats tracking maps */
static int cleanup_cpu_stats_maps(int cpu_stats_fd, int process_start_times_fd)
{
    int cleaned_count = 0;
    int nr_cpus;

    /* Get number of possible CPUs */
    nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus < 0) {
        fprintf(stderr, "Failed to get number of CPUs: %s\n", strerror(-nr_cpus));
        return 0;
    }
    if (nr_cpus > MAX_CPUS) {
        nr_cpus = MAX_CPUS;
    }

    /* Cleanup CPU stats map - remove entries for processes marked as exited */
    if (cpu_stats_fd >= 0 && process_start_times_fd >= 0) {
        struct cpu_key key, next_key;
        struct cpu_stats stats[MAX_CPUS]; /* Array for per-CPU values */
        int ret;
        uint32_t next_pid_key;

        key.pid = 0;
        while (bpf_map_get_next_key(cpu_stats_fd, &key, &next_key) == 0) {
            ret = bpf_map_lookup_elem(cpu_stats_fd, &next_key, stats);
            if (ret == 0) {
                /* Check if this process is marked as exited */
                bool process_exited = false;
                for (int cpu = 0; cpu < nr_cpus; cpu++) {
                    if (stats[cpu].exited) {
                        process_exited = true;
                        break;
                    }
                }
                if (process_exited) {
                    next_pid_key = next_key.pid;
                    /* Process is marked as exited, remove from map */
                    bpf_map_delete_elem(cpu_stats_fd, &next_key);
                    bpf_map_delete_elem(process_start_times_fd, &next_pid_key);
                    cleaned_count += 2;
                }
            }
            key = next_key;
        }
    }

    return cleaned_count;
}

/* Helper function to cleanup syscall stats tracking maps */
static int cleanup_syscall_stats_maps(int syscall_stats_fd, int syscall_entry_fd)
{
    int cleaned_count = 0;

    /* Cleanup syscall stats map - remove entries for processes marked as exited */
    if (syscall_stats_fd >= 0 && syscall_entry_fd >= 0) {
        struct syscall_key key, next_key;
        struct syscall_stats stats[MAX_CPUS]; /* Array for per-CPU values */
        int ret;
        int nr_cpus;
        uint32_t exited_pids[MAX_TASKS];
        int exited_pids_count = 0;

        /* Get number of possible CPUs */
        nr_cpus = libbpf_num_possible_cpus();
        if (nr_cpus < 0) {
            fprintf(stderr, "Failed to get number of CPUs for syscall cleanup: %s\n",
                    strerror(-nr_cpus));
            return 0;
        }
        if (nr_cpus > MAX_CPUS) {
            nr_cpus = MAX_CPUS;
        }

        // First pass: collect all pids with syscall_nr==0 and exited
        key.pid = 0;
        key.syscall_nr = 0;
        while (bpf_map_get_next_key(syscall_stats_fd, &key, &next_key) == 0 &&
               exited_pids_count < MAX_TASKS) {
            if (next_key.syscall_nr == 0) {
                ret = bpf_map_lookup_elem(syscall_stats_fd, &next_key, stats);
                if (ret == 0) {
                    bool process_exited = false;
                    for (int cpu = 0; cpu < nr_cpus; cpu++) {
                        if (stats[cpu].exited) {
                            process_exited = true;
                            break;
                        }
                    }
                    if (process_exited) {
                        exited_pids[exited_pids_count] = next_key.pid;
                        exited_pids_count++;
                    }
                }
            }
            key = next_key;
        }

        // Second pass: delete all entries for exited pids
        key.pid = 0;
        key.syscall_nr = 0;
        while (bpf_map_get_next_key(syscall_stats_fd, &key, &next_key) == 0) {
            for (int i = 0; i < exited_pids_count; i++) {
                if (next_key.pid == exited_pids[i]) {
                    bpf_map_delete_elem(syscall_stats_fd, &next_key);
                    bpf_map_delete_elem(syscall_entry_fd, &next_key);
                    cleaned_count += 2;
                    break;
                }
            }
            key = next_key;
        }
    }

    return cleaned_count;
}

/* Helper function to cleanup I/O stats tracking maps */
static int cleanup_io_stats_maps(int io_stats_fd, int io_request_times_fd)
{
    int cleaned_count = 0;

    /* Cleanup I/O stats map - remove entries for processes marked as exited */
    if (io_stats_fd >= 0 && io_request_times_fd >= 0) {
        struct io_key key, next_key;
        struct io_stats stats[MAX_CPUS]; /* Array for per-CPU values */
        int ret;
        int nr_cpus;
        uint32_t next_req_key;
        /* Get number of possible CPUs */
        nr_cpus = libbpf_num_possible_cpus();
        if (nr_cpus < 0) {
            fprintf(stderr, "Failed to get number of CPUs for io cleanup: %s\n",
                    strerror(-nr_cpus));
            return 0;
        }
        if (nr_cpus > MAX_CPUS) {
            nr_cpus = MAX_CPUS;
        }

        key.pid = 0;
        while (bpf_map_get_next_key(io_stats_fd, &key, &next_key) == 0) {
            ret = bpf_map_lookup_elem(io_stats_fd, &next_key, stats);
            if (ret == 0) {
                /* Check if any CPU has the process marked as exited */
                bool process_exited = false;
                for (int cpu = 0; cpu < nr_cpus; cpu++) {
                    if (stats[cpu].exited) {
                        process_exited = true;
                        break;
                    }
                }
                if (process_exited) {
                    next_req_key = next_key.pid;
                    /* Process is marked as exited, remove from map */
                    bpf_map_delete_elem(io_stats_fd, &next_key);
                    bpf_map_delete_elem(io_request_times_fd, &next_req_key);
                    cleaned_count += 2;
                }
            }
            key = next_key;
        }
    }

    return cleaned_count;
}
