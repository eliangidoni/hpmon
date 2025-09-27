/* HPMon Terminal User Interface Implementation
 *
 * This file implements a ncurses-based terminal user interface for HPMon
 * with real-time data visualization, multiple view modes, and interactive features.
 */

/* For CLOCK_MONOTONIC and usleep on some systems */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

/* TUI Constants */
#define TUI_COLOR_NEUTRAL_TREND 5
#define TUI_COLOR_STATUS_INFO 6
#define TUI_KEY_ESC 27
#define TUI_KEY_LF 10
#define TUI_KEY_CR 13
#define TUI_TIME_STR_SIZE 64
#define TUI_PROCESS_NAME_SIZE 17
#define TUI_TREND_COL_START 27
#define TUI_TREND_COL_WIDTH 9
#define TUI_HEADER_PROCESS_COUNT_OFFSET 20
#define TUI_STATUS_BPF_OFFSET 30
#define TUI_TREND_THRESHOLD_HIGH 0.1
#define TUI_TREND_THRESHOLD_MEDIUM 0.05
#define TUI_TREND_THRESHOLD_LARGE 0.5
#define TUI_NANOSECONDS_TO_MICROSECONDS 1000.0
#define TUI_BYTES_TO_MEGABYTES 1000.0
#define TUI_SECONDS_TO_MICROSECONDS 1000000.0

#include "tui.h"
#include "bpf_common.h"
#include "safe_string.h"
#include <ctype.h>
#include <inttypes.h>
#include <locale.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* TUI state and sorting */
typedef enum {
    SORT_PID,
    SORT_NAME,
    SORT_CPU,
    SORT_MEMORY,
    SORT_IO,
    SORT_NETWORK,
    SORT_SYSCALL,
    SORT_MAX
} sort_column_t;

typedef enum { VIEW_MAIN, VIEW_DETAILS } view_mode_t;

static struct tui_state {
    /* ncurses windows */
    WINDOW *header_win;
    WINDOW *main_win;
    WINDOW *status_win;

    /* Data */
    struct rt_process_metrics *processes;
    size_t process_count;
    struct collection_stats collection_stats;
    struct realtime_stats realtime_stats;
    struct bpf_manager_stats bpf_stats;
    bool has_bpf_stats;

    /* Navigation and display */
    int selected_row;
    int scroll_offset;
    int max_rows; /* Maximum rows that can be displayed */

    /* Sorting */
    sort_column_t sort_column;
    bool sort_descending;

    /* View mode */
    view_mode_t view_mode;
    int detailed_pid; /* PID of process in detailed view */

    /* Screen dimensions */
    int screen_height;
    int screen_width;

    /* Refresh timing */
    uint64_t last_refresh_time; /* Last time the display was refreshed */

    bool initialized;
} tui;

/* Program type short names for error display - synchronized with enum hpmon_bpf_program_type */
static const char *prog_type_short[HPMON_BPF_PROG_MAX] = {[HPMON_BPF_PROG_TYPE_CPU] = "CPU",
                                                          [HPMON_BPF_PROG_TYPE_SYSCALL] = "SC",
                                                          [HPMON_BPF_PROG_TYPE_IO] = "IO",
                                                          [HPMON_BPF_PROG_TYPE_MEMORY] = "MEM",
                                                          [HPMON_BPF_PROG_TYPE_NETWORK] = "NET"};

/* Forward declarations */
static int tui_setup_windows(void);
static void tui_cleanup_windows(void);
static void tui_draw_header(void);
static void tui_draw_main_view(void);
static void tui_draw_detailed_view(void);
static void tui_draw_status(void);
static void tui_sort_processes(void);
static int tui_compare_processes(const void *first_proc, const void *second_proc);
static const char *tui_format_trend(double trend);
static void tui_handle_resize(void);
static uint64_t tui_get_current_time_ms(void);
static bool tui_should_refresh(unsigned int poll_interval_ms);
static double tui_convert_bytes_to_mb(double bytes_per_sec);
static double tui_convert_calls_to_microsec(double calls_per_sec);
static double tui_get_current_cpu_percent(const struct rt_process_metrics *proc);
static double tui_get_current_memory_mb(const struct rt_process_metrics *proc);
static double tui_get_current_io_rate_mb(const struct rt_process_metrics *proc);
static double tui_get_current_network_rate_mb(const struct rt_process_metrics *proc);
static double tui_get_current_syscall_rate(const struct rt_process_metrics *proc);

int tui_init(const struct hpmon_config *config)
{
    if (!config) {
        return -1;
    }

    /* Initialize locale for proper character support */
    setlocale(LC_ALL, "");

    /* Initialize ncurses */
    initscr();

    /* Check terminal size */
    getmaxyx(stdscr, tui.screen_height, tui.screen_width);
    if (tui.screen_height < TUI_MIN_HEIGHT || tui.screen_width < TUI_MIN_WIDTH) {
        endwin();
        fprintf(stderr, "Error: Terminal too small. Minimum size: %dx%d\n", TUI_MIN_WIDTH,
                TUI_MIN_HEIGHT);
        return -1;
    }

    /* Configure ncurses */
    cbreak();             /* Disable line buffering */
    noecho();             /* Don't echo key presses */
    keypad(stdscr, TRUE); /* Enable arrow keys */
    timeout(0);           /* Non-blocking input */
    curs_set(0);          /* Hide cursor */

    /* Initialize colors if supported */
    if (has_colors()) {
        start_color();
        use_default_colors();

        /* Define color pairs */
        init_pair(1, COLOR_WHITE, -1);                        /* Header */
        init_pair(2, COLOR_BLACK, COLOR_WHITE);               /* Selected row */
        init_pair(3, COLOR_GREEN, -1);                        /* Positive trend */
        init_pair(4, COLOR_RED, -1);                          /* Negative trend */
        init_pair(TUI_COLOR_NEUTRAL_TREND, COLOR_YELLOW, -1); /* Neutral trend */
        init_pair(TUI_COLOR_STATUS_INFO, COLOR_CYAN, -1);     /* Status info */
    }

    /* Initialize TUI state */
    memset(&tui, 0, sizeof(tui));
    tui.sort_column = SORT_CPU;
    tui.sort_descending = true;
    tui.view_mode = VIEW_MAIN;
    tui.selected_row = 0;
    tui.scroll_offset = 0;
    tui.screen_height = getmaxy(stdscr);
    tui.screen_width = getmaxx(stdscr);
    tui.last_refresh_time = tui_get_current_time_ms();

    /* Set up windows */
    if (tui_setup_windows() < 0) {
        endwin();
        return -1;
    }

    /* Allocate process array */
    tui.processes = calloc(TUI_MAX_VISIBLE_PROCESSES, sizeof(struct rt_process_metrics));
    if (!tui.processes) {
        tui_cleanup_windows();
        endwin();
        return -1;
    }

    tui.initialized = true;
    return 0;
}

int tui_update_data(const struct rt_process_metrics *process_metrics, size_t count,
                    const struct collection_stats *collection_stats,
                    const struct realtime_stats *realtime_stats,
                    const struct bpf_manager_stats *bpf_stats)
{
    if (!tui.initialized || !process_metrics || !collection_stats || !realtime_stats) {
        return -1;
    }

    /* Copy process metrics (limit to visible processes) */
    size_t copy_count = count > TUI_MAX_VISIBLE_PROCESSES ? TUI_MAX_VISIBLE_PROCESSES : count;
    memcpy(tui.processes, process_metrics, copy_count * sizeof(struct rt_process_metrics));
    tui.process_count = copy_count;

    /* Copy statistics */
    tui.collection_stats = *collection_stats;
    tui.realtime_stats = *realtime_stats;
    if (bpf_stats) {
        tui.bpf_stats = *bpf_stats;
        tui.has_bpf_stats = true;
    } else {
        tui.has_bpf_stats = false;
    }

    /* Sort processes based on current sort criteria */
    tui_sort_processes();

    /* Adjust selection if it's out of bounds */
    if (tui.selected_row >= (int)tui.process_count) {
        tui.selected_row = (int)tui.process_count - 1;
        if (tui.selected_row < 0) {
            tui.selected_row = 0;
        }
    }

    return 0;
}

bool tui_handle_input_and_refresh(unsigned int poll_interval_ms)
{
    if (!tui.initialized) {
        return false;
    }

    /* Handle window resize */
    tui_handle_resize();

    /* Handle keyboard input */
    bool need_refresh = false;
    int key_code = getch();

    if (key_code != ERR) {
        /* Key was pressed, handle it and force refresh */
        need_refresh = true;

        switch (key_code) {
        case 'q':
        case 'Q':
        case TUI_KEY_ESC: /* ESC */
            if (tui.view_mode == VIEW_DETAILS) {
                tui.view_mode = VIEW_MAIN;
            } else {
                return false; /* Exit TUI */
            }
            break;

        case KEY_UP:
            if (tui.view_mode == VIEW_MAIN) {
                if (tui.selected_row > 0) {
                    tui.selected_row--;
                    if (tui.selected_row < tui.scroll_offset) {
                        tui.scroll_offset--;
                    }
                }
            }
            break;

        case KEY_DOWN:
            if (tui.view_mode == VIEW_MAIN) {
                if (tui.selected_row < (int)tui.process_count - 1) {
                    tui.selected_row++;
                    if (tui.selected_row >= tui.scroll_offset + tui.max_rows) {
                        tui.scroll_offset++;
                    }
                }
            }
            break;

        case KEY_ENTER:
        case TUI_KEY_LF:
        case TUI_KEY_CR:
            if (tui.view_mode == VIEW_MAIN && tui.selected_row < (int)tui.process_count) {
                tui.detailed_pid = (int)tui.processes[tui.selected_row].pid;
                tui.view_mode = VIEW_DETAILS;
            }
            break;

        case 'p':
        case 'P':
            tui.sort_column = SORT_PID;
            tui.sort_descending = !tui.sort_descending;
            break;

        case 'n':
        case 'N':
            tui.sort_column = SORT_NAME;
            tui.sort_descending = !tui.sort_descending;
            break;

        case 'c':
        case 'C':
            tui.sort_column = SORT_CPU;
            tui.sort_descending = !tui.sort_descending;
            break;

        case 'm':
        case 'M':
            tui.sort_column = SORT_MEMORY;
            tui.sort_descending = !tui.sort_descending;
            break;

        case 'i':
        case 'I':
            tui.sort_column = SORT_IO;
            tui.sort_descending = !tui.sort_descending;
            break;

        case 't':
        case 'T':
            tui.sort_column = SORT_NETWORK;
            tui.sort_descending = !tui.sort_descending;
            break;

        case 's':
        case 'S':
            tui.sort_column = SORT_SYSCALL;
            tui.sort_descending = !tui.sort_descending;
            break;
        default:
            /* Unrecognized key, still refresh */
            break;
        }
    }

    /* Check if we should refresh based on time interval */
    if (!need_refresh) {
        need_refresh = tui_should_refresh(poll_interval_ms);
    }

    /* Only refresh display if needed */
    if (need_refresh) {
        tui_draw_header();

        if (tui.view_mode == VIEW_MAIN) {
            tui_draw_main_view();
        } else {
            tui_draw_detailed_view();
        }

        tui_draw_status();

        /* Refresh all windows */
        wrefresh(tui.header_win);
        wrefresh(tui.main_win);
        wrefresh(tui.status_win);
    }

    return true;
}

void tui_cleanup(void)
{
    if (tui.initialized) {
        tui_cleanup_windows();

        if (tui.processes) {
            free(tui.processes);
            tui.processes = NULL;
        }

        endwin();
        tui.initialized = false;
    }
}

/* Helper function implementations */
static int tui_setup_windows(void)
{
    /* Header window */
    tui.header_win = newwin(TUI_HEADER_HEIGHT, tui.screen_width, 0, 0);
    if (!tui.header_win) {
        return -1;
    }

    /* Main content window */
    int main_height = tui.screen_height - TUI_HEADER_HEIGHT - TUI_STATUS_HEIGHT;
    tui.main_win = newwin(main_height, tui.screen_width, TUI_HEADER_HEIGHT, 0);
    if (!tui.main_win) {
        return -1;
    }
    tui.max_rows = main_height - 2; /* Reserve space for column headers and subheaders */

    /* Status window */
    tui.status_win =
        newwin(TUI_STATUS_HEIGHT, tui.screen_width, tui.screen_height - TUI_STATUS_HEIGHT, 0);
    if (!tui.status_win) {
        return -1;
    }

    return 0;
}

static void tui_cleanup_windows(void)
{
    if (tui.header_win) {
        delwin(tui.header_win);
        tui.header_win = NULL;
    }
    if (tui.main_win) {
        delwin(tui.main_win);
        tui.main_win = NULL;
    }
    if (tui.status_win) {
        delwin(tui.status_win);
        tui.status_win = NULL;
    }
}

static void tui_draw_header(void)
{
    if (!tui.header_win) {
        return;
    }

    werase(tui.header_win);

    /* Header background */
    if (has_colors()) {
        wbkgd(tui.header_win, COLOR_PAIR(1));
    }

    /* Calculate usable width (accounting for box borders) */
    int usable_width = tui.screen_width - 2;

    /* Title and version */
    mvwprintw(tui.header_win, 1, 1, "HPMon v%s - Hot Spot Performance Monitor",
              hpmon_version_string());

    /* Current time - ensure it fits within the usable width */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[TUI_TIME_STR_SIZE];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    int time_pos = usable_width - (int)strlen(time_str) + 1;
    if (time_pos > 1) {
        mvwprintw(tui.header_win, 1, time_pos, "%s", time_str);
    }

    /* Help and key bindings - truncate if necessary */
    const char *help_text;
    if (tui.view_mode == VIEW_MAIN) {
        help_text = "Keys: ^v=Navigate Enter=Details pP/nN/cC/mM/iI/tT/sS=Sort Q/ESC=Quit";
    } else {
        help_text = "Keys: Q/ESC=Back to main view";
    }

    char truncated_help[TUI_HELP_BUFFER_SIZE];
    int help_len = (int)strlen(help_text);
    if (help_len > usable_width - 1) {
        snprintf(truncated_help, usable_width - 2, "%s", help_text);
    } else {
        snprintf(truncated_help, sizeof(truncated_help), "%s", help_text);
    }
    mvwprintw(tui.header_win, 2, 1, "%s", truncated_help);

    /* Sort indicator and process count - truncate if necessary */
    const char *sort_names[] = {"TID", "NAME", "CPU", "MEM", "I/O", "NET", "SYS"};
    char sort_info[TUI_SORT_BUFFER_SIZE];
    snprintf(sort_info, sizeof(sort_info), "Sort: %s (%s) | View: %s | Processes: %zu",
             sort_names[tui.sort_column], tui.sort_descending ? "DESC" : "ASC",
             tui.view_mode == VIEW_MAIN ? "Main" : "Details", tui.process_count);

    /* Truncate sort info if it's too long */
    char truncated_sort[TUI_SORT_BUFFER_SIZE];
    int sort_len = (int)strlen(sort_info);
    if (sort_len > usable_width - 1) {
        snprintf(truncated_sort, usable_width - 2, "%s", sort_info);
    } else {
        snprintf(truncated_sort, sizeof(truncated_sort), "%s", sort_info);
    }
    mvwprintw(tui.header_win, 3, 1, "%s", truncated_sort);

    /* BPF status and error information - truncate if necessary */
    char bpf_status[TUI_BPF_BUFFER_SIZE];
    if (tui.has_bpf_stats) {
        char bpf_errors[TUI_BPF_ERROR_BUFFER_SIZE] = {0};
        size_t off = 0;
        bool has_errors = false;

        for (int pt = 0; pt < HPMON_BPF_PROG_MAX; pt++) {
            uint64_t config_errors = tui.bpf_stats.error_counters[pt][ERROR_CONFIG_MISSING];
            uint64_t update_errors = tui.bpf_stats.error_counters[pt][ERROR_MAP_UPDATE_FAILED];
            uint64_t lookup_errors = tui.bpf_stats.error_counters[pt][ERROR_MAP_LOOKUP_FAILED];
            uint64_t buffer_errors = tui.bpf_stats.error_counters[pt][ERROR_RING_BUFFER_FULL];

            if (config_errors || update_errors || lookup_errors || buffer_errors) {
                int chars_written = snprintf(bpf_errors + off, sizeof(bpf_errors) - off,
                                             "%s%s(c:%lu,u:%lu,l:%lu,b:%lu)", has_errors ? " " : "",
                                             prog_type_short[pt], config_errors, update_errors,
                                             lookup_errors, buffer_errors);
                if (chars_written > 0) {
                    off += (size_t)chars_written;
                    has_errors = true;
                    if (off >= sizeof(bpf_errors) - 1) {
                        break;
                    }
                }
            }
        }

        if (!has_errors) {
            snprintf(bpf_errors, sizeof(bpf_errors), "N/A");
        }

        snprintf(bpf_status, sizeof(bpf_status), "BPF: %d/%d programs loaded | Counters: %s",
                 tui.bpf_stats.programs_attached, tui.bpf_stats.programs_loaded, bpf_errors);
    } else {
        snprintf(bpf_status, sizeof(bpf_status), "BPF: stats disabled");
    }

    /* Truncate BPF status if it's too long */
    char truncated_bpf[TUI_BPF_BUFFER_SIZE];
    int bpf_len = (int)strlen(bpf_status);
    if (bpf_len > usable_width - 1) {
        snprintf(truncated_bpf, usable_width - 2, "%s", bpf_status);
    } else {
        snprintf(truncated_bpf, sizeof(truncated_bpf), "%s", bpf_status);
    }
    mvwprintw(tui.header_win, 4, 1, "%s", truncated_bpf);

    box(tui.header_win, 0, 0);
}

static void tui_draw_main_view(void)
{
    if (!tui.main_win) {
        return;
    }

    werase(tui.main_win);

    /* Column headers - Main headers */
    mvwprintw(tui.main_win, 0, 1, "%-8s %-16s %8s %8s %8s %8s %8s", "TID", "PROCESS", "CPU%",
              "MEMORY", "I/O RATE", "NETWORK", "SYSCALLS");

    /* Column headers - Sub-headers with units and descriptions */
    if (has_colors()) {
        wattron(tui.main_win, COLOR_PAIR(TUI_COLOR_STATUS_INFO));
    }
    mvwprintw(tui.main_win, 1, 1, "%-8s %-16s %8s %8s %8s %8s %8s", "TID", "COMMAND", "CPU %",
              "MEM MB", "IO MB/s", "NET MB/s", "SYSCALL call/s");
    if (has_colors()) {
        wattroff(tui.main_win, COLOR_PAIR(TUI_COLOR_STATUS_INFO));
    }

    /* Draw horizontal line */
    mvwhline(tui.main_win, 2, 1, ACS_HLINE, tui.screen_width - 2);

    /* Draw process list */
    for (int i = 0; i < tui.max_rows - 2 && i + tui.scroll_offset < (int)tui.process_count; i++) {
        int process_idx = i + tui.scroll_offset;
        struct rt_process_metrics *proc = &tui.processes[process_idx];

        int row = i + 3; /* Start after headers and line */

        /* Highlight selected row */
        if (process_idx == tui.selected_row && has_colors()) {
            wattron(tui.main_win, COLOR_PAIR(2));
        }

        /* Format process name */
        char name[TUI_PROCESS_NAME_SIZE];
        snprintf(name, sizeof(name), "%.16s", proc->comm);

        /* Draw basic process info */
        mvwprintw(tui.main_win, row, 1, "%-8u %-16s", proc->pid, name);

        /* Draw trends with colors */
        int col = TUI_TREND_COL_START; /* Starting column for trends */

        /* CPU trend */
        const char *cpu_trend = tui_format_trend(proc->cpu_trend);
        if (has_colors()) {
            if (proc->cpu_trend > TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(4));
            } else if (proc->cpu_trend < -TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(3));
            } else {
                wattron(tui.main_win, COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
            }
        }
        mvwprintw(tui.main_win, row, col, "%8s", cpu_trend);
        if (has_colors()) {
            wattroff(tui.main_win,
                     COLOR_PAIR(4) | COLOR_PAIR(3) | COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
        }
        col += TUI_TREND_COL_WIDTH;

        /* Memory trend */
        const char *mem_trend = tui_format_trend(proc->memory_trend);
        if (has_colors()) {
            if (proc->memory_trend > TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(4));
            } else if (proc->memory_trend < -TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(3));
            } else {
                wattron(tui.main_win, COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
            }
        }
        mvwprintw(tui.main_win, row, col, "%8s", mem_trend);
        if (has_colors()) {
            wattroff(tui.main_win,
                     COLOR_PAIR(4) | COLOR_PAIR(3) | COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
        }
        col += TUI_TREND_COL_WIDTH;

        /* I/O trend */
        const char *io_trend = tui_format_trend(proc->io_trend);
        if (has_colors()) {
            if (proc->io_trend > TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(4));
            } else if (proc->io_trend < -TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(3));
            } else {
                wattron(tui.main_win, COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
            }
        }
        mvwprintw(tui.main_win, row, col, "%8s", io_trend);
        if (has_colors()) {
            wattroff(tui.main_win,
                     COLOR_PAIR(4) | COLOR_PAIR(3) | COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
        }
        col += TUI_TREND_COL_WIDTH;

        /* Network trend */
        const char *net_trend = tui_format_trend(proc->network_trend);
        if (has_colors()) {
            if (proc->network_trend > TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(4));
            } else if (proc->network_trend < -TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(3));
            } else {
                wattron(tui.main_win, COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
            }
        }
        mvwprintw(tui.main_win, row, col, "%8s", net_trend);
        if (has_colors()) {
            wattroff(tui.main_win,
                     COLOR_PAIR(4) | COLOR_PAIR(3) | COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
        }
        col += TUI_TREND_COL_WIDTH;

        /* Syscall trend */
        const char *sys_trend = tui_format_trend(proc->syscall_trend);
        if (has_colors()) {
            if (proc->syscall_trend > TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(4));
            } else if (proc->syscall_trend < -TUI_TREND_THRESHOLD_HIGH) {
                wattron(tui.main_win, COLOR_PAIR(3));
            } else {
                wattron(tui.main_win, COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
            }
        }
        mvwprintw(tui.main_win, row, col, "%8s", sys_trend);
        if (has_colors()) {
            wattroff(tui.main_win,
                     COLOR_PAIR(4) | COLOR_PAIR(3) | COLOR_PAIR(TUI_COLOR_NEUTRAL_TREND));
        }

        /* Turn off selection highlighting */
        if (process_idx == tui.selected_row && has_colors()) {
            wattroff(tui.main_win, COLOR_PAIR(2));
        }
    }

    box(tui.main_win, 0, 0);
}

static void tui_draw_detailed_view(void)
{
    if (!tui.main_win) {
        return;
    }

    werase(tui.main_win);

    /* Find the process */
    struct rt_process_metrics *proc = NULL;
    for (size_t i = 0; i < tui.process_count; i++) {
        if ((int)tui.processes[i].pid == tui.detailed_pid) {
            proc = &tui.processes[i];
            break;
        }
    }

    if (!proc) {
        mvwprintw(tui.main_win, 1, 1, "Process TID %d not found", tui.detailed_pid);
        box(tui.main_win, 0, 0);
        return;
    }

    int row = 1;

    /* Process header */
    mvwprintw(tui.main_win, row++, 1, "Process Details - TID: %u (%s)", proc->pid, proc->comm);
    row++;

    /* Container info if available */
    if (proc->is_container && strlen(proc->container_id) > 0) {
        mvwprintw(tui.main_win, row++, 1, "Container: %.32s", proc->container_id);
        row++;
    }

    /* Trends section with current values */
    mvwprintw(tui.main_win, row++, 1, "=== TRENDS & CURRENT VALUES ===");
    mvwprintw(tui.main_win, row++, 1, "CPU Usage:     %-4s (%.2f%%)",
              tui_format_trend(proc->cpu_trend), tui_get_current_cpu_percent(proc));
    mvwprintw(tui.main_win, row++, 1, "Memory Usage:  %-4s (%.2f MB)",
              tui_format_trend(proc->memory_trend), tui_get_current_memory_mb(proc));
    mvwprintw(tui.main_win, row++, 1, "I/O Activity:  %-4s (%.2f MB/s)",
              tui_format_trend(proc->io_trend), tui_get_current_io_rate_mb(proc));
    mvwprintw(tui.main_win, row++, 1, "Network:       %-4s (%.2f MB/s)",
              tui_format_trend(proc->network_trend), tui_get_current_network_rate_mb(proc));
    mvwprintw(tui.main_win, row++, 1, "Syscalls:      %-4s (%.0f calls/s)",
              tui_format_trend(proc->syscall_trend), tui_get_current_syscall_rate(proc));
    row++;

    /* Moving averages section */
    mvwprintw(tui.main_win, row++, 1, "=== MOVING AVERAGES (1m/5m/15m) ===");
    mvwprintw(tui.main_win, row++, 1, "CPU (%%):              %.2f / %.2f / %.2f",
              proc->cpu_averages.short_term, proc->cpu_averages.medium_term,
              proc->cpu_averages.long_term);
    mvwprintw(tui.main_win, row++, 1, "Memory (MB/sec):      %.2f / %.2f / %.2f",
              tui_convert_bytes_to_mb(proc->memory_averages.short_term),
              tui_convert_bytes_to_mb(proc->memory_averages.medium_term),
              tui_convert_bytes_to_mb(proc->memory_averages.long_term));
    mvwprintw(tui.main_win, row++, 1, "I/O (MB/sec):         %.2f / %.2f / %.2f",
              tui_convert_bytes_to_mb(proc->io_averages.short_term),
              tui_convert_bytes_to_mb(proc->io_averages.medium_term),
              tui_convert_bytes_to_mb(proc->io_averages.long_term));
    mvwprintw(tui.main_win, row++, 1, "Network (MB/sec):     %.2f / %.2f / %.2f",
              tui_convert_bytes_to_mb(proc->network_averages.short_term),
              tui_convert_bytes_to_mb(proc->network_averages.medium_term),
              tui_convert_bytes_to_mb(proc->network_averages.long_term));
    mvwprintw(tui.main_win, row++, 1, "Syscalls (calls/µs):  %.2f / %.2f / %.2f",
              tui_convert_calls_to_microsec(proc->syscall_averages.short_term),
              tui_convert_calls_to_microsec(proc->syscall_averages.medium_term),
              tui_convert_calls_to_microsec(proc->syscall_averages.long_term));
    row++;

    /* Totals section */
    mvwprintw(tui.main_win, row++, 1, "=== TOTALS ===");
    mvwprintw(tui.main_win, row++, 1, "CPU Time (us):    %.2f",
              (double)proc->prev_cpu_time_ns / TUI_NANOSECONDS_TO_MICROSECONDS);
    mvwprintw(tui.main_win, row++, 1, "Syscall Count:    %lu", proc->prev_syscall_count);
    mvwprintw(tui.main_win, row++, 1, "I/O Bytes:        %lu", proc->prev_io_bytes);
    mvwprintw(tui.main_win, row++, 1, "Network Bytes:    %lu", proc->prev_network_bytes);
    mvwprintw(tui.main_win, row++, 1, "Memory Usage:     %lu", proc->prev_memory_bytes);
    row++;

    /* Syscall categories section */
    mvwprintw(tui.main_win, row++, 1, "=== SYSCALL CATEGORIES ===");

    const char *category_names[SYSCALL_CAT_MAX] = {
        "File I/O", /* SYSCALL_CAT_FILE_IO */
        "Memory",   /* SYSCALL_CAT_MEMORY */
        "Process",  /* SYSCALL_CAT_PROCESS */
        "Network",  /* SYSCALL_CAT_NETWORK */
        "Time",     /* SYSCALL_CAT_TIME */
        "Signal",   /* SYSCALL_CAT_SIGNAL */
        "Other"     /* SYSCALL_CAT_OTHER */
    };

    for (int i = 0; i < SYSCALL_CAT_MAX; i++) {
        uint64_t count = proc->syscall_category_counts[i].count;
        uint64_t total_latency = proc->syscall_category_counts[i].total_latency_ns;
        double avg_latency_us =
            count > 0 ? (double)total_latency / (double)count / TUI_NANOSECONDS_TO_MICROSECONDS
                      : 0.0;

        mvwprintw(tui.main_win, row++, 1, "%-12s: %8lu calls, %10.2f µs avg latency",
                  category_names[i], count, avg_latency_us);
    }

    box(tui.main_win, 0, 0);
}

static void tui_draw_status(void)
{
    if (!tui.status_win) {
        return;
    }

    werase(tui.status_win);

    if (has_colors()) {
        wattron(tui.status_win, COLOR_PAIR(6));
    }

    /* Status information */
    mvwprintw(tui.status_win, 0, 1, "Samples: %lu | Dropped: %lu | Rate: %.1f MB/s | Active: %lu",
              tui.realtime_stats.samples_processed, tui.realtime_stats.samples_dropped,
              tui.realtime_stats.data_rate_mbps, tui.realtime_stats.active_processes);

    if (tui.has_bpf_stats) {
        mvwprintw(tui.status_win, 0, tui.screen_width - TUI_STATUS_BPF_OFFSET, "BPF: %d/%d progs",
                  tui.bpf_stats.programs_attached, tui.bpf_stats.programs_loaded);
    }

    if (has_colors()) {
        wattroff(tui.status_win, COLOR_PAIR(6));
    }
}

static void tui_sort_processes(void)
{
    if (tui.process_count <= 1) {
        return;
    }

    qsort(tui.processes, tui.process_count, sizeof(struct rt_process_metrics),
          tui_compare_processes);
}

static int tui_compare_processes(const void *first_proc, const void *second_proc)
{
    const struct rt_process_metrics *proc_a = (const struct rt_process_metrics *)first_proc;
    const struct rt_process_metrics *proc_b = (const struct rt_process_metrics *)second_proc;

    int result = 0;

    switch (tui.sort_column) {
    case SORT_PID:
        result = (proc_a->pid > proc_b->pid) - (proc_a->pid < proc_b->pid);
        break;
    case SORT_NAME:
        result = strcmp(proc_a->comm, proc_b->comm);
        break;
    case SORT_CPU:
        result = (proc_a->cpu_trend > proc_b->cpu_trend) - (proc_a->cpu_trend < proc_b->cpu_trend);
        break;
    case SORT_MEMORY:
        result = (proc_a->memory_trend > proc_b->memory_trend) -
                 (proc_a->memory_trend < proc_b->memory_trend);
        break;
    case SORT_IO:
        result = (proc_a->io_trend > proc_b->io_trend) - (proc_a->io_trend < proc_b->io_trend);
        break;
    case SORT_NETWORK:
        result = (proc_a->network_trend > proc_b->network_trend) -
                 (proc_a->network_trend < proc_b->network_trend);
        break;
    case SORT_SYSCALL:
        result = (proc_a->syscall_trend > proc_b->syscall_trend) -
                 (proc_a->syscall_trend < proc_b->syscall_trend);
        break;
    default:
        result = 0;
    }

    return tui.sort_descending ? -result : result;
}

static const char *tui_format_trend(double trend)
{
    if (trend > TUI_TREND_THRESHOLD_LARGE) {
        return "+++";
    }
    if (trend > TUI_TREND_THRESHOLD_HIGH) {
        return "++";
    }
    if (trend > TUI_TREND_THRESHOLD_MEDIUM) {
        return "+";
    }
    if (trend < -TUI_TREND_THRESHOLD_LARGE) {
        return "---";
    }
    if (trend < -TUI_TREND_THRESHOLD_HIGH) {
        return "--";
    }
    if (trend < -TUI_TREND_THRESHOLD_MEDIUM) {
        return "-";
    }
    return "=";
}

static void tui_handle_resize(void)
{
    int new_height, new_width;
    getmaxyx(stdscr, new_height, new_width);

    if (new_height != tui.screen_height || new_width != tui.screen_width) {
        tui.screen_height = new_height;
        tui.screen_width = new_width;

        /* Check minimum size */
        if (tui.screen_height < TUI_MIN_HEIGHT || tui.screen_width < TUI_MIN_WIDTH) {
            return;
        }

        /* Recreate windows */
        tui_cleanup_windows();
        tui_setup_windows();

        /* Clear and redraw everything */
        clear();
        refresh();
    }
}

static uint64_t tui_get_current_time_ms(void)
{
    const uint64_t ms_per_sec = 1000;
    const uint64_t ns_per_ms = 1000000;
    struct timespec timespec_val;
    if (clock_gettime(CLOCK_MONOTONIC, &timespec_val) != 0) {
        return 0;
    }
    return (uint64_t)timespec_val.tv_sec * ms_per_sec + (uint64_t)timespec_val.tv_nsec / ns_per_ms;
}

static bool tui_should_refresh(unsigned int poll_interval_ms)
{
    uint64_t current_time = tui_get_current_time_ms();
    if (current_time - tui.last_refresh_time >= poll_interval_ms) {
        tui.last_refresh_time = current_time;
        return true;
    }
    return false;
}

/* Convert bytes per second to megabytes per second */
static double tui_convert_bytes_to_mb(double bytes_per_sec)
{
    return bytes_per_sec / (TUI_BYTES_TO_MEGABYTES * TUI_BYTES_TO_MEGABYTES);
}

/* Convert calls per second to calls per microsecond */
static double tui_convert_calls_to_microsec(double calls_per_sec)
{
    return calls_per_sec / TUI_SECONDS_TO_MICROSECONDS;
}

/* Get current CPU usage percentage from most recent window value */
static double tui_get_current_cpu_percent(const struct rt_process_metrics *proc)
{
    if (!proc) {
        return 0.0;
    }
    return sliding_window_latest(&proc->cpu_usage_window);
}

/* Get current memory usage in megabytes */
static double tui_get_current_memory_mb(const struct rt_process_metrics *proc)
{
    if (!proc) {
        return 0.0;
    }
    return tui_convert_bytes_to_mb((double)proc->prev_memory_bytes);
}

/* Get current I/O rate in MB/s from most recent window value */
static double tui_get_current_io_rate_mb(const struct rt_process_metrics *proc)
{
    if (!proc) {
        return 0.0;
    }
    return tui_convert_bytes_to_mb(sliding_window_latest(&proc->io_rate_window));
}

/* Get current network rate in MB/s from most recent window value */
static double tui_get_current_network_rate_mb(const struct rt_process_metrics *proc)
{
    if (!proc) {
        return 0.0;
    }
    return tui_convert_bytes_to_mb(sliding_window_latest(&proc->network_rate_window));
}

/* Get current syscall rate from most recent window value */
static double tui_get_current_syscall_rate(const struct rt_process_metrics *proc)
{
    if (!proc) {
        return 0.0;
    }
    return sliding_window_latest(&proc->syscall_rate_window);
}
