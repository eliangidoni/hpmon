#define _GNU_SOURCE // for gettid()

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_manager.h"
#include "container_tracker.h"
#include "data_collector.h"
#include "export.h"
#include "hpmon.h"
#include "realtime.h"
#include "safe_string.h"

/* Constants */
#define MILLISECONDS_PER_SECOND 1000
#define EVENT_POLL_INTERVAL_MS 20
#define BPF_ERROR_BREAKDOWN_SIZE 512

/* Program type short names - synchronized with enum hpmon_bpf_program_type */
static const char *prog_type_short[HPMON_BPF_PROG_MAX] = {[HPMON_BPF_PROG_TYPE_CPU] = "CPU",
                                                          [HPMON_BPF_PROG_TYPE_SYSCALL] = "SC",
                                                          [HPMON_BPF_PROG_TYPE_IO] = "IO",
                                                          [HPMON_BPF_PROG_TYPE_MEMORY] = "MEM",
                                                          [HPMON_BPF_PROG_TYPE_NETWORK] = "NET"};

/* Compile-time assertion to ensure array completeness */
_Static_assert(sizeof(prog_type_short) / sizeof(prog_type_short[0]) == HPMON_BPF_PROG_MAX,
               "prog_type_short array size must match HPMON_BPF_PROG_MAX");

/* Global state */
static struct hpmon_config *g_config = NULL;
static bool initialized = false;
static bool monitoring = false;
static pthread_mutex_t hpmon_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Subsystem initialization state tracking */
static bool container_tracker_initialized = false;
static bool bpf_manager_initialized = false;
static bool data_collector_initialized = false;
static bool export_engine_initialized = false;
static bool bpf_programs_loaded = false;
static bool realtime_processor_initialized = false;

/* BPF polling thread */
static pthread_t bpf_poll_thread;
static bool bpf_poll_thread_running = false;

/* BPF cleanup thread */
static pthread_t bpf_cleanup_thread;
static bool bpf_cleanup_thread_running = false;

static void *bpf_poll_thread_func(void *arg)
{
    (void)arg;
    printf("  BPF event thread started, TID: %u\n", gettid());
    for (;;) {
        pthread_mutex_lock(&hpmon_mutex);
        bool active = monitoring;
        pthread_mutex_unlock(&hpmon_mutex);
        if (!active) {
            break;
        }
        bpf_manager_poll_events(EVENT_POLL_INTERVAL_MS);
    }
    return NULL;
}

static void *bpf_cleanup_thread_func(void *arg)
{
    (void)arg;
    printf("  BPF cleanup thread started, TID: %u\n", gettid());
    for (;;) {
        pthread_mutex_lock(&hpmon_mutex);
        bool active = monitoring;
        pthread_mutex_unlock(&hpmon_mutex);
        if (!active) {
            break;
        }
        bpf_manager_cleanup_maps();
        sleep(g_config->bpf_cleanup_interval_seconds);
    }
    return NULL;
}

/* Compile-time version string construction to avoid runtime formatting & races */
#ifndef HPMON_VERSION_STRINGIFY
#define HPMON_VERSION_STRINGIFY2(x) #x
#define HPMON_VERSION_STRINGIFY(x) HPMON_VERSION_STRINGIFY2(x)
#endif
#define HPMON_VERSION_COMPILETIME                                                                  \
    HPMON_VERSION_STRINGIFY(HPMON_VERSION_MAJOR)                                                   \
    "." HPMON_VERSION_STRINGIFY(HPMON_VERSION_MINOR) "." HPMON_VERSION_STRINGIFY(                  \
        HPMON_VERSION_PATCH)

const char *hpmon_version_string(void)
{
    return HPMON_VERSION_COMPILETIME;
}

int hpmon_init(struct hpmon_config *config)
{
    pthread_mutex_lock(&hpmon_mutex);

    if (!config) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    if (initialized) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -EALREADY;
    }

    /* Validate configuration parameters */
    if (config->poll_interval_ms == 0 || config->poll_interval_ms < MIN_POLL_INTERVAL ||
        config->poll_interval_ms > MAX_POLL_INTERVAL) {
        printf("Error: Invalid poll interval (%u ms). Must be between %d and %d ms.\n",
               config->poll_interval_ms, MIN_POLL_INTERVAL, MAX_POLL_INTERVAL);
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    if (config->max_processes == 0 || config->max_processes < MIN_MAX_PROCESSES ||
        config->max_processes > MAX_MAX_PROCESSES) {
        printf("Error: Invalid max processes (%u). Must be between %d and %d.\n",
               config->max_processes, MIN_MAX_PROCESSES, MAX_MAX_PROCESSES);
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    /* Validate aggregation window if set */
    if (config->aggregation_window_ms != 0 &&
        (config->aggregation_window_ms < MIN_AGGREGATION_WINDOW ||
         config->aggregation_window_ms > MAX_AGGREGATION_WINDOW)) {
        printf("Error: Invalid aggregation window (%u ms). Must be between %d and %d ms.\n",
               config->aggregation_window_ms, MIN_AGGREGATION_WINDOW, MAX_AGGREGATION_WINDOW);
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    g_config = config;

    printf("Initializing HPMon with configuration:\n");
    printf("  Monitoring modules:\n");
    printf("    CPU: %s\n", config->monitor_cpu ? "enabled" : "disabled");
    printf("    System calls: %s\n", config->monitor_syscalls ? "enabled" : "disabled");
    printf("    I/O operations: %s\n", config->monitor_io ? "enabled" : "disabled");
    printf("    Network: %s\n", config->monitor_network ? "enabled" : "disabled");
    printf("    Containers: %s\n", config->monitor_containers ? "enabled" : "disabled");

    /* Initialize container tracker if container monitoring is enabled */
    if (config->monitor_containers) {
        if (container_tracker_init() != 0) {
            printf("Error: Failed to initialize container tracker\n");
            goto cleanup_failure;
        } else {
            container_tracker_initialized = true;
            printf("  Container tracker initialized\n");
        }
    }

    /* Initialize BPF manager */
    if (bpf_manager_init(config) != 0) {
        printf("Error: Failed to initialize BPF manager\n");
        goto cleanup_failure;
    }
    bpf_manager_initialized = true;
    printf("  BPF manager initialized\n");

    /* Initialize data collector */
    if (data_collector_init(config) != 0) {
        printf("Error: Failed to initialize data collector\n");
        goto cleanup_failure;
    }
    data_collector_initialized = true;
    printf("  Data collector initialized\n");

    /* Initialize real-time processor */
    if (realtime_processor_init(config, DEFAULT_WINDOW_SIZE, DEFAULT_RATE_LIMIT_MB) != 0) {
        printf("Error: Failed to initialize real-time processor\n");
        goto cleanup_failure;
    }
    realtime_processor_initialized = true;
    printf("  Real-time processor initialized\n");

    /* Initialize export engine */
    if (export_engine_init(config) != 0) {
        printf("Error: Failed to initialize export engine\n");
        goto cleanup_failure;
    }
    export_engine_initialized = true;
    printf("  Export engine initialized\n");

    /* Load eBPF programs */
    if (bpf_manager_load_programs() != 0) {
        printf("Error: Failed to load eBPF programs\n");
        goto cleanup_failure;
    }
    bpf_programs_loaded = true;
    printf("  eBPF programs loaded\n");

    initialized = true;
    pthread_mutex_unlock(&hpmon_mutex);
    return 0;

cleanup_failure:
    /* Cleanup in reverse order of initialization */
    if (export_engine_initialized) {
        export_engine_cleanup();
        export_engine_initialized = false;
    }
    if (data_collector_initialized) {
        data_collector_cleanup();
        data_collector_initialized = false;
    }
    if (realtime_processor_initialized) {
        realtime_processor_cleanup();
        realtime_processor_initialized = false;
    }
    if (bpf_manager_initialized) {
        bpf_manager_cleanup();
        bpf_manager_initialized = false;
    }
    if (container_tracker_initialized) {
        container_tracker_cleanup();
        container_tracker_initialized = false;
    }

    g_config = NULL;
    pthread_mutex_unlock(&hpmon_mutex);
    return -1;
}

int hpmon_start(void)
{
    pthread_mutex_lock(&hpmon_mutex);

    if (!initialized) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    if (monitoring) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -EALREADY;
    }

    printf("Starting monitoring subsystems...\n");

    /* Attach eBPF programs and start data collection */
    if (bpf_manager_attach_programs() != 0) {
        printf("Error: Failed to attach eBPF programs\n");
        pthread_mutex_unlock(&hpmon_mutex);
        return -1;
    }
    printf("  eBPF programs attached\n");

    /* Start data collection */
    if (data_collector_start() != 0) {
        printf("Error: Failed to start data collector\n");
        bpf_manager_detach_programs();
        pthread_mutex_unlock(&hpmon_mutex);
        return -1;
    }
    printf("  Data collection started\n");

    /* Start real-time processing */
    if (realtime_processor_start() != 0) {
        printf("Error: Failed to start real-time processor\n");
        data_collector_stop();
        bpf_manager_detach_programs();
        pthread_mutex_unlock(&hpmon_mutex);
        return -1;
    }
    printf("  Real-time processing started\n");

    monitoring = true;

    /* Start BPF polling thread */
    if (pthread_create(&bpf_poll_thread, NULL, bpf_poll_thread_func, NULL) != 0) {
        printf("Error: Failed to start BPF polling thread\n");
        monitoring = false;
        /* Roll back started subsystems */
        realtime_processor_stop();
        data_collector_stop();
        bpf_manager_detach_programs();
        pthread_mutex_unlock(&hpmon_mutex);
        return -1;
    }
    bpf_poll_thread_running = true;

    /* Start BPF cleanup thread */
    if (pthread_create(&bpf_cleanup_thread, NULL, bpf_cleanup_thread_func, NULL) != 0) {
        printf("Error: Failed to start BPF cleanup thread\n");
        monitoring = false;
        /* Stop the poll thread and roll back started subsystems */
        pthread_join(bpf_poll_thread, NULL);
        bpf_poll_thread_running = false;
        realtime_processor_stop();
        data_collector_stop();
        bpf_manager_detach_programs();
        pthread_mutex_unlock(&hpmon_mutex);
        return -1;
    }
    bpf_cleanup_thread_running = true;
    pthread_mutex_unlock(&hpmon_mutex);
    return 0;
}

int hpmon_stop(void)
{
    pthread_mutex_lock(&hpmon_mutex);

    if (!monitoring) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    printf("Stopping monitoring subsystems...\n");

    /* Stop real-time processing */
    if (realtime_processor_stop() != 0) {
        printf("Warning: Failed to stop real-time processor gracefully\n");
    } else {
        printf("  Real-time processing stopped\n");
    }

    /* Stop data collection */
    if (data_collector_stop() != 0) {
        printf("Warning: Failed to stop data collector gracefully\n");
    } else {
        printf("  Data collection stopped\n");
    }

    /* Detach eBPF programs and stop data collection */
    if (bpf_manager_detach_programs() != 0) {
        printf("Warning: Failed to detach eBPF programs gracefully\n");
    } else {
        printf("  eBPF programs detached\n");
    }
    monitoring = false;
    pthread_mutex_unlock(&hpmon_mutex);

    /* Join polling thread */
    if (bpf_poll_thread_running) {
        pthread_join(bpf_poll_thread, NULL);
        bpf_poll_thread_running = false;
    }

    /* Join cleanup thread */
    if (bpf_cleanup_thread_running) {
        pthread_join(bpf_cleanup_thread, NULL);
        bpf_cleanup_thread_running = false;
    }

    return 0;
}

void hpmon_cleanup(void)
{
    pthread_mutex_lock(&hpmon_mutex);

    if (monitoring) {
        printf("Stopping monitoring before cleanup...\n");
        /* Use internal stop logic to avoid recursive mutex lock */
        monitoring = false;

        /* Stop real-time processing */
        if (realtime_processor_stop() != 0) {
            printf("Warning: Failed to stop real-time processor gracefully\n");
        }

        /* Stop data collection */
        if (data_collector_stop() != 0) {
            printf("Warning: Failed to stop data collector gracefully\n");
        }

        /* Detach eBPF programs */
        if (bpf_manager_detach_programs() != 0) {
            printf("Warning: Failed to detach eBPF programs gracefully\n");
        }
    }

    pthread_mutex_unlock(&hpmon_mutex);

    /* Ensure polling thread is joined if it was running */
    if (bpf_poll_thread_running) {
        pthread_join(bpf_poll_thread, NULL);
        bpf_poll_thread_running = false;
    }

    /* Ensure cleanup thread is joined if it was running */
    if (bpf_cleanup_thread_running) {
        pthread_join(bpf_cleanup_thread, NULL);
        bpf_cleanup_thread_running = false;
    }

    pthread_mutex_lock(&hpmon_mutex);

    /* Clean up subsystems in reverse order of initialization */
    if (export_engine_initialized) {
        export_engine_cleanup();
        export_engine_initialized = false;
        printf("  Export engine cleaned up\n");
    }

    if (realtime_processor_initialized) {
        realtime_processor_cleanup();
        realtime_processor_initialized = false;
        printf("  Real-time processor cleaned up\n");
    }

    if (data_collector_initialized) {
        data_collector_cleanup();
        data_collector_initialized = false;
        printf("  Data collector cleaned up\n");
    }

    if (bpf_manager_initialized) {
        bpf_manager_cleanup();
        bpf_manager_initialized = false;
        printf("  BPF manager cleaned up\n");
    }

    if (container_tracker_initialized) {
        container_tracker_cleanup();
        container_tracker_initialized = false;
        printf("  Container tracker cleaned up\n");
    }

    /* Reset global state */
    g_config = NULL;
    initialized = false;
    bpf_programs_loaded = false;

    printf("Cleanup complete.\n");
    pthread_mutex_unlock(&hpmon_mutex);
}

void hpmon_print_stats(void)
{
    struct collection_stats stats;
    struct container_summary containers[MAX_CONTAINERS];
    size_t container_count = 0;
    struct bpf_manager_stats bpf_stats;
    bool have_bpf_stats = false;
    char bpf_error_breakdown[BPF_ERROR_BREAKDOWN_SIZE];
    bpf_error_breakdown[0] = '\0';

    pthread_mutex_lock(&hpmon_mutex);

    if (!initialized || !monitoring) {
        pthread_mutex_unlock(&hpmon_mutex);
        return;
    }

    /* For statistics display, we only need basic collection stats, not full processing.
     * The full processing pipeline should be handled by the main monitoring loop,
     * not by the statistics display function. This improves efficiency significantly. */

    /* Get current statistics from data collector */
    if (data_collector_get_stats(&stats) != 0) {
        printf("\rError: Failed to get data collection statistics");
        fflush(stdout);
        pthread_mutex_unlock(&hpmon_mutex);
        return;
    }

    /* Update container statistics if container monitoring is enabled */
    if (g_config->monitor_containers && container_tracker_initialized) {
        container_tracker_get_containers(containers, MAX_CONTAINERS, &container_count);
    }

    /* Store historical snapshot periodically (every 10 collections) */
    static uint64_t collection_counter = 0;
    if (++collection_counter % HISTORICAL_SNAPSHOT_INTERVAL == 0) {
        store_historical_snapshot();
    }

    /* Collect BPF manager statistics (non-fatal if unavailable) */
    if (g_config->bpf_stats && bpf_manager_initialized && bpf_manager_get_stats(&bpf_stats) == 0) {
        /* Error counter indices correspond to enum error_counter: CONFIG(c), MAP_UPDATE(upd),
         * MAP_LOOKUP(lk), RING_BUFFER_FULL(b) */
        size_t off = 0;
        for (int pt = 0; pt < HPMON_BPF_PROG_MAX; pt++) {
            uint64_t config_errors = bpf_stats.error_counters[pt][ERROR_CONFIG_MISSING];
            uint64_t update_errors = bpf_stats.error_counters[pt][ERROR_MAP_UPDATE_FAILED];
            uint64_t lookup_errors = bpf_stats.error_counters[pt][ERROR_MAP_LOOKUP_FAILED];
            uint64_t buffer_errors = bpf_stats.error_counters[pt][ERROR_RING_BUFFER_FULL];
            if (config_errors || update_errors || lookup_errors || buffer_errors) {
                int chars_written =
                    snprintf(bpf_error_breakdown + off, sizeof(bpf_error_breakdown) - off,
                             "%s(c:%" PRIu64 ",u:%" PRIu64 ",l:%" PRIu64 ",b:%" PRIu64 ") ",
                             prog_type_short[pt], config_errors, update_errors, lookup_errors,
                             buffer_errors);
                if (chars_written > 0) {
                    off += (size_t)chars_written;
                    if (off >= sizeof(bpf_error_breakdown)) {
                        break;
                    }
                }
            }
        }
        if (bpf_error_breakdown[0] != '\0') {
            /* Trim trailing space */
            size_t len = strlen(bpf_error_breakdown);
            if (len > 0 && bpf_error_breakdown[len - 1] == ' ') {
                bpf_error_breakdown[len - 1] = '\0';
            }
            have_bpf_stats = true;
        }
    }

    /* Print statistics based on configuration */
    if (g_config->monitor_containers) {
        printf("\r[%s] Procs: %lu active (%lu containers), %lu total | Containers: %zu | "
               "Syscalls: %lu | I/O: %lub | High CPU: %lu | Collections: %lu",
               hpmon_version_string(), stats.active_processes, stats.container_processes,
               stats.total_processes, container_count, stats.total_syscalls, stats.total_io_bytes,
               stats.high_cpu_processes, stats.collections_performed);
    } else {
        printf("\r[%s] Procs: %lu active, %lu total | Syscalls: %lu | I/O: %lub | "
               "High CPU: %lu | Collections: %lu",
               hpmon_version_string(), stats.active_processes, stats.total_processes,
               stats.total_syscalls, stats.total_io_bytes, stats.high_cpu_processes,
               stats.collections_performed);
    }
    if (have_bpf_stats) {
        printf(" | BPF %s", bpf_error_breakdown);
    }
    fflush(stdout);

    pthread_mutex_unlock(&hpmon_mutex);
}

int hpmon_export_json(const char *filename)
{
    struct collection_stats stats;
    FILE *output_file;

    pthread_mutex_lock(&hpmon_mutex);

    if (!initialized) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -EINVAL;
    }

    /* Get current statistics */
    if (data_collector_get_stats(&stats) != 0) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -ENODATA;
    }

    output_file = filename ? fopen(filename, "w") : stdout;
    if (!output_file) {
        pthread_mutex_unlock(&hpmon_mutex);
        return -errno;
    }

    /* Export basic JSON structure */
    fprintf(output_file, "{\n");
    fprintf(output_file, "  \"hpmon_version\": \"%s\",\n", hpmon_version_string());
    fprintf(output_file, "  \"timestamp\": %lu,\n", time(NULL));
    fprintf(output_file, "  \"statistics\": {\n");
    fprintf(output_file, "    \"total_processes\": %lu,\n", stats.total_processes);
    fprintf(output_file, "    \"active_processes\": %lu,\n", stats.active_processes);
    fprintf(output_file, "    \"total_syscalls\": %lu,\n", stats.total_syscalls);
    fprintf(output_file, "    \"total_io_bytes\": %lu,\n", stats.total_io_bytes);
    fprintf(output_file, "    \"high_cpu_processes\": %lu,\n", stats.high_cpu_processes);
    fprintf(output_file, "    \"high_io_processes\": %lu,\n", stats.high_io_processes);
    fprintf(output_file, "    \"container_processes\": %lu,\n", stats.container_processes);
    fprintf(output_file, "    \"collections_performed\": %lu\n", stats.collections_performed);
    fprintf(output_file, "  },\n");

    /* Export container information if enabled */
    if (g_config->monitor_containers) {
        struct container_summary containers[MAX_CONTAINERS];
        size_t container_count;

        fprintf(output_file, "  \"containers\": [\n");

        if (container_tracker_get_containers(containers, MAX_CONTAINERS, &container_count) == 0) {
            for (int i = 0; i < (int)container_count; i++) {
                fprintf(output_file, "    {\n");
                fprintf(output_file, "      \"container_id\": \"%.12s\",\n",
                        containers[i].container_id);
                fprintf(output_file, "      \"runtime\": \"%s\",\n", containers[i].runtime);
                fprintf(output_file, "      \"process_count\": %d\n", containers[i].process_count);
                fprintf(output_file, "    }%s\n", (i < (int)container_count - 1) ? "," : "");
            }
        }

        fprintf(output_file, "  ],\n");
    }

    fprintf(output_file, "  \"configuration\": {\n");
    fprintf(output_file, "    \"monitor_cpu\": %s,\n", g_config->monitor_cpu ? "true" : "false");
    fprintf(output_file, "    \"monitor_syscalls\": %s,\n",
            g_config->monitor_syscalls ? "true" : "false");
    fprintf(output_file, "    \"monitor_io\": %s,\n", g_config->monitor_io ? "true" : "false");
    fprintf(output_file, "    \"monitor_containers\": %s,\n",
            g_config->monitor_containers ? "true" : "false");
    fprintf(output_file, "    \"poll_interval_ms\": %u,\n", g_config->poll_interval_ms);
    fprintf(output_file, "    \"max_processes\": %u\n", g_config->max_processes);
    fprintf(output_file, "  }\n");
    fprintf(output_file, "}\n");

    if (filename) {
        fclose(output_file);
    }

    pthread_mutex_unlock(&hpmon_mutex);
    return 0;
}

/* Print detailed container information */
void hpmon_print_container_stats(void)
{
    pthread_mutex_lock(&hpmon_mutex);

    if (!initialized || !g_config->monitor_containers || !container_tracker_initialized) {
        printf("Container monitoring not enabled or initialized\n");
        pthread_mutex_unlock(&hpmon_mutex);
        return;
    }

    printf("\nContainer Statistics:\n");
    container_tracker_print_stats();

    pthread_mutex_unlock(&hpmon_mutex);
}
