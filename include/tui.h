/* HPMon Terminal User Interface Header
 *
 * This header defines the interface for the ncurses-based terminal
 * user interface with real-time data visualization and interactive features.
 */

#ifndef TUI_H
#define TUI_H

#include "bpf_manager.h"
#include "data_collector.h"
#include "hpmon.h"
#include "realtime.h"
#include <ncurses.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* TUI configuration constants */
#define TUI_REFRESH_RATE_MS 500      /* TUI refresh rate */
#define TUI_MAX_VISIBLE_PROCESSES 50 /* Maximum processes shown at once */
#define TUI_MIN_WIDTH 80             /* Minimum terminal width */
#define TUI_MIN_HEIGHT 24            /* Minimum terminal height */
#define TUI_HEADER_HEIGHT 6          /* Header area height */
#define TUI_STATUS_HEIGHT 1          /* Status bar height */
#define TUI_FOOTER_HEIGHT 2          /* Footer help area height */

/* TUI buffer sizes */
#define TUI_HELP_BUFFER_SIZE 256      /* Buffer size for help text */
#define TUI_SORT_BUFFER_SIZE 256      /* Buffer size for sort information */
#define TUI_BPF_BUFFER_SIZE 512       /* Buffer size for BPF status */
#define TUI_BPF_ERROR_BUFFER_SIZE 256 /* Buffer size for BPF errors */

/* Function declarations */

/**
 * Initialize the TUI system
 * @param config: HPMon configuration
 * @returns 0 on success, negative on error
 */
int tui_init(const struct hpmon_config *config);

/**
 * Update TUI with new data
 * @param process_metrics: Array of real-time process metrics
 * @param count: Number of process metrics
 * @param collection_stats: Collection statistics
 * @param realtime_stats: Real-time processing statistics
 * @param bpf_stats: BPF internal statistics
 * @returns 0 on success, negative on error
 */
int tui_update_data(const struct rt_process_metrics *process_metrics, size_t count,
                    const struct collection_stats *collection_stats,
                    const struct realtime_stats *realtime_stats,
                    const struct bpf_manager_stats *bpf_stats);

/**
 * Handle keyboard input and refresh display
 * @returns true to continue, false to exit
 */
bool tui_handle_input_and_refresh();

/**
 * Cleanup and shutdown TUI
 */
void tui_cleanup(void);

#endif /* TUI_H */
