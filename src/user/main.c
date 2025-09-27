#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bpf_manager.h"
#include "cli.h"
#include "data_collector.h"
#include "hpmon.h"
#include "tui.h"

/* Signal handling */
static volatile bool running = true;

#define MS_TO_SEC 1000
#define MS_TO_NS 1000000L
#define IDLE_MS 10

static void signal_handler(int sig)
{
    (void)sig; /* Unused parameter */
    running = false;
}

static inline void sleep_ms(__u32 interval_ms)
{
    struct timespec timespec_val;
    timespec_val.tv_sec = interval_ms / MS_TO_SEC;
    timespec_val.tv_nsec =
        (long)(interval_ms % MS_TO_SEC) * MS_TO_NS; /* convert remaining ms to ns */
    nanosleep(&timespec_val, NULL);
}

int main(int argc, char *argv[])
{
    int ret = 0;
    struct cli_options options;

    /* Initialize CLI options with defaults */
    cli_init_options(&options);

    /* Try to auto-load configuration file first */
    cli_auto_load_config(&options.config);

    /* Parse command line arguments (which can override config file) */
    ret = cli_parse_arguments(argc, argv, &options);
    if (ret == CLI_EXIT_SUCCESS) {
        cli_cleanup_options(&options);
        return 0;
    }
    if (ret == CLI_EXIT_ERROR || ret == CLI_ERROR) {
        cli_cleanup_options(&options);
        return 1;
    }

    /* Check privileges */
    if (cli_check_privileges() < 0) {
        cli_cleanup_options(&options);
        return 1;
    }

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("HPMon v%s - Starting system monitoring...\n", hpmon_version_string());
    cli_print_config(&options.config);
    printf("\n");

    /* Initialize HPMon */
    ret = hpmon_init(&options.config);
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to initialize HPMon: %s\n", strerror(-ret));
        goto cleanup;
    }

    /* Start monitoring */
    ret = hpmon_start();
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to start monitoring: %s\n", strerror(-ret));
        goto cleanup;
    }

    /* Main monitoring loop */
    if (options.config.enable_tui) {
        /* Initialize TUI */
        ret = tui_init(&options.config);
        if (ret < 0) {
            fprintf(stderr, "Error: Failed to initialize TUI: %s\n", strerror(-ret));
            goto cleanup;
        }

        printf("Starting TUI mode...\n");
        sleep(1); /* Give user a moment to see the message */
        uint64_t last_collection_time = get_current_time_ns() / MS_TO_NS;
        /* TUI main loop handles everything, but we still collect data here */
        while (running) {
            uint64_t current_time = get_current_time_ns() / MS_TO_NS;
            bool need_collection = false;
            if (current_time - last_collection_time >= options.config.poll_interval_ms) {
                last_collection_time = current_time;
                need_collection = true;
            }
            if (need_collection) {
                /* Perform data collection cycle */
                data_collector_collect();
                /* Process real-time metrics */
                struct process_data processes[MAX_TRACKED_PROCESSES];
                size_t process_count = 0;
                if (data_collector_get_processes(processes, MAX_TRACKED_PROCESSES,
                                                 &process_count) == 0) {
                    /* Process through real-time processor */
                    realtime_processor_process_sample(processes, process_count);

                    /* Get real-time metrics for analytics and detection */
                    struct rt_process_metrics rt_metrics[MAX_TRACKED_PROCESSES];
                    size_t rt_count = 0;
                    if (realtime_processor_get_all_metrics(rt_metrics, MAX_TRACKED_PROCESSES,
                                                           &rt_count) == 0) {
                        /* Update TUI with new data */
                        struct collection_stats collection_stats;
                        struct realtime_stats realtime_stats;
                        struct bpf_manager_stats bpf_stats;
                        bool have_bpf_stats = false;

                        data_collector_get_stats(&collection_stats);
                        realtime_processor_get_stats(&realtime_stats);
                        /* Get BPF stats if enabled */
                        if (options.config.bpf_stats && bpf_manager_get_stats(&bpf_stats) == 0) {
                            have_bpf_stats = true;
                        }

                        tui_update_data(rt_metrics, rt_count, &collection_stats, &realtime_stats,
                                        have_bpf_stats ? &bpf_stats : NULL);
                    }
                }
            }

            /* Let TUI handle input and refresh - this returns false if user wants to quit */
            if (!tui_handle_input_and_refresh(options.config.poll_interval_ms)) {
                running = false;
            }

            /* Sleep  */
            sleep_ms(IDLE_MS);
        }

        /* Cleanup TUI */
        tui_cleanup();
    } else {
        printf("Monitoring started. Press Ctrl+C to stop.\n");
        while (running) {
            /* Perform data collection cycle */
            data_collector_collect();

            /* Process real-time metrics */
            struct process_data processes[MAX_TRACKED_PROCESSES];
            size_t process_count = 0;
            data_collector_get_processes(processes, MAX_TRACKED_PROCESSES, &process_count);

            /* Print periodic statistics */
            if (!options.config.enable_json_output) {
                hpmon_print_stats();
            }

            /* Sleep for configured poll interval */
            sleep_ms(options.config.poll_interval_ms);
        }
    }

    /* Stop monitoring */
    printf("\nStopping monitoring...\n");
    ret = hpmon_stop();
    if (ret < 0) {
        fprintf(stderr, "Warning: Failed to stop monitoring gracefully: %s\n", strerror(-ret));
    }

cleanup:
    hpmon_cleanup();
    cli_cleanup_options(&options);
    printf("HPMon shutdown complete.\n");
    return ret < 0 ? 1 : 0;
}
