#include "cli.h"
#include "safe_string.h"
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Constants */
#define CONFIG_LINE_BUFFER_SIZE 256
#define TMP_PATH_PREFIX_LEN 5 /* Length of "/tmp/" */
#define DECIMAL_BASE 10       /* Base for decimal number parsing */

/* BPF cleanup defaults */
#define DEFAULT_BPF_CLEANUP_INTERVAL_SECONDS 3

/* Long option values for extended options */
#define OPT_NO_CPU 1
#define OPT_NO_SYSCALLS 2
#define OPT_NO_IO 3
#define OPT_SAVE_CONFIG 4
#define OPT_NO_MEMORY 5
#define OPT_NO_NETWORK 6
#define OPT_SAVE_EVENT_LOG 1001
#define OPT_BPF_STATS 1002
#define OPT_MIN_BYTES 1003
#define OPT_TCP 1004
#define OPT_SYSCALL_CATEGORY 1005

/* Command-line option definitions */
static struct option long_options[] = {
    {"cpu", no_argument, 0, 'c'},
    {"syscalls", no_argument, 0, 's'},
    {"io", no_argument, 0, 'i'},
    {"memory", no_argument, 0, 'M'},
    {"network", no_argument, 0, 'n'},
    {"containers", no_argument, 0, 'C'},
    {"tui", no_argument, 0, 't'},
    {"json", no_argument, 0, 'j'},
    {"output", required_argument, 0, 'o'},
    {"event-log", required_argument, 0, OPT_SAVE_EVENT_LOG},
    {"config", required_argument, 0, 'f'},
    {"poll-interval", required_argument, 0, 'p'},
    {"window", required_argument, 0, 'w'},
    {"max-procs", required_argument, 0, 'm'},
    {"pid", required_argument, 0, 'P'},
    {"sample-rate", required_argument, 0, 'r'},
    {"min-bytes", required_argument, 0, OPT_MIN_BYTES},
    {"tcp", no_argument, 0, OPT_TCP},
    {"syscall-category", required_argument, 0, OPT_SYSCALL_CATEGORY},
    {"no-cpu", no_argument, 0, OPT_NO_CPU},
    {"no-syscalls", no_argument, 0, OPT_NO_SYSCALLS},
    {"no-io", no_argument, 0, OPT_NO_IO},
    {"no-memory", no_argument, 0, OPT_NO_MEMORY},
    {"no-network", no_argument, 0, OPT_NO_NETWORK},
    {"bpf-stats", no_argument, 0, OPT_BPF_STATS},
    {"save-config", required_argument, 0, OPT_SAVE_CONFIG},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {0, 0, 0, 0}};

/* Short options string */
static const char *short_options = "csiMnCtjo:f:p:w:m:P:r:hv";

/* Forward declarations */
static int parse_syscall_categories(const char *categories_str, __u64 *bitmask);
static int syscall_bitmask_to_string(__u64 bitmask, char *buffer, size_t buffer_size);

void cli_init_options(struct cli_options *options)
{
    if (!options) {
        return;
    }

    memset(options, 0, sizeof(*options));

    /* Initialize with default configuration */
    options->config.monitor_cpu = true;
    options->config.monitor_syscalls = true;
    options->config.monitor_io = true;
    options->config.monitor_memory = true;
    options->config.monitor_network = false; /* Network monitoring disabled by default */
    options->config.monitor_containers = false;
    options->config.track_tcp_only = false; /* Track all network protocols by default */
    options->config.poll_interval_ms = DEFAULT_POLL_INTERVAL;
    options->config.aggregation_window_ms = DEFAULT_AGGREGATION_WINDOW;
    options->config.enable_tui = false;
    options->config.enable_json_output = false;
    options->config.output_file[0] = '\0';
    options->config.event_log_file[0] = '\0';
    options->config.max_processes = MAX_PROCESSES;
    options->config.pid = 0;         /* Default: monitor all processes */
    options->config.sample_rate = 0; /* Default: sample all processes */
    /* BPF map cleanup defaults */
    options->config.bpf_cleanup_interval_seconds = DEFAULT_BPF_CLEANUP_INTERVAL_SECONDS;
    options->config.bpf_stats = false; /* BPF stats disabled by default */

    options->config.min_bytes = 0; /* No minimum bytes filter by default */
    /* Initialize syscall category bitmask to 0 (track everything by default) */
    options->config.syscall_bitmask = 0;

    options->show_help = false;
    options->show_version = false;
    options->config_file = NULL;
}

void cli_cleanup_options(struct cli_options *options)
{
    if (!options) {
        return;
    }

    if (options->config_file) {
        free(options->config_file);
        options->config_file = NULL;
    }
}

void cli_print_usage(const char *program_name)
{
    printf("HPMon - eBPF-based System Performance Monitor\n");
    printf("Version: %s\n\n", hpmon_version_string());
    printf("Usage: %s [OPTIONS]\n\n", program_name);
    printf("Options:\n");
    printf("  -c, --cpu              Monitor CPU usage (default: enabled)\n");
    printf("  -s, --syscalls         Monitor system calls (default: enabled)\n");
    printf("      --syscall-category CAT Filter syscalls by category "
           "(io,memory,process,network,time,signal,other)\n");
    printf("                             Use comma-separated list, empty=track all (default: track "
           "all)\n");
    printf("  -i, --io               Monitor disk I/O (default: enabled)\n");
    printf("  -M, --memory           Monitor memory allocation (default: enabled)\n");
    printf("  -n, --network          Monitor network I/O (default: disabled)\n");
    printf("  -C, --containers       Monitor containers (default: disabled)\n");
    printf("      --tcp              Track only TCP network operations (default: track all)\n");
    printf("      --no-cpu           Disable CPU monitoring\n");
    printf("      --no-syscalls      Disable syscall monitoring\n");
    printf("      --no-io            Disable I/O monitoring\n");
    printf("      --no-memory        Disable memory monitoring\n");
    printf("      --no-network       Disable network monitoring\n");
    printf("  -t, --tui              Enable terminal UI (default: disabled)\n");
    printf("  -j, --json             Enable JSON output (default: disabled)\n");
    printf("  -o, --output FILE      Output file for JSON data\n");
    printf("  -f, --config FILE      Load configuration from file\n");
    printf("      --event-log FILE   Output BPF events to file (default: disabled)\n");
    printf("      --bpf-stats        Show BPF statistics (default: disabled)\n");
    printf("      --save-config FILE Save current configuration to file\n");
    printf("  -p, --poll-interval MS Poll interval in milliseconds (default: %d)\n",
           DEFAULT_POLL_INTERVAL);
    printf("  -w, --window MS        Aggregation window in milliseconds "
           "(default: %d)\n",
           DEFAULT_AGGREGATION_WINDOW);
    printf("  -m, --max-procs N      Maximum processes to track (default: %d)\n", MAX_PROCESSES);
    printf("  -P, --pid PID          Monitor specific process ID (default: 0, monitor all)\n");
    printf("  -r, --sample-rate N    Sample every Nth process (default: 0, sample all)\n");
    printf("      --min-bytes N      Minimum bytes for IO/network operations (default: 0)\n");
    printf("  -h, --help             Show this help message\n");
    printf("  -v, --version          Show version information\n\n");
    printf("Configuration Files (searched in order):\n");
    printf("  1. %s\n", LOCAL_CONFIG_FILE);
    printf("  2. ~/.hpmon.conf\n");
    printf("  3. %s\n", DEFAULT_CONFIG_FILE);
    printf("\nExamples:\n");
    printf("  %s                     # Monitor with default settings\n", program_name);
    printf("  %s -t                  # Monitor with terminal UI\n", program_name);
    printf("  %s -j -o output.json   # Monitor with JSON output\n", program_name);
    printf("  %s -C                  # Monitor containers\n", program_name);
    printf("  %s -f my.conf          # Use custom config file\n", program_name);
    printf("  %s -P 1234             # Monitor only process with PID 1234\n", program_name);
    printf("  %s -r 5                # Sample every 5th process\n", program_name);
    printf("  %s --min-bytes 1024    # Only track IO/network >= 1KB\n", program_name);
    printf("  %s --tcp               # Only track TCP network operations\n", program_name);
    printf("  %s --syscall-category io,memory  # Only track IO and memory syscalls\n",
           program_name);
    printf("  %s --save-config my.conf --no-cpu  # Save config with CPU disabled\n", program_name);
    printf("\nNote: This tool requires root privileges or CAP_BPF capability.\n");
}

void cli_print_version(void)
{
    printf("HPMon version %s\n", hpmon_version_string());
    printf("eBPF-based system performance monitoring tool\n");
    printf("Built with libbpf support\n");
    printf("Copyright (C) 2025 HPMon Project\n");
}

int cli_check_privileges(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Error: HPMon requires root privileges or CAP_BPF capability.\n");
        fprintf(stderr, "Please run with sudo or set the appropriate capabilities.\n");
        return -1;
    }
    return 0;
}

int cli_validate_config(const struct hpmon_config *config)
{
    if (!config) {
        fprintf(stderr, "Error: Invalid configuration pointer\n");
        return -1;
    }

    /* Validate poll interval */
    if (config->poll_interval_ms < MIN_POLL_INTERVAL ||
        config->poll_interval_ms > MAX_POLL_INTERVAL) {
        fprintf(stderr, "Error: Poll interval must be between %d and %d ms\n", MIN_POLL_INTERVAL,
                MAX_POLL_INTERVAL);
        return -1;
    }

    /* Validate aggregation window */
    if (config->aggregation_window_ms < MIN_AGGREGATION_WINDOW ||
        config->aggregation_window_ms > MAX_AGGREGATION_WINDOW) {
        fprintf(stderr, "Error: Aggregation window must be between %d and %d ms\n",
                MIN_AGGREGATION_WINDOW, MAX_AGGREGATION_WINDOW);
        return -1;
    }

    /* Validate max processes */
    if (config->max_processes < MIN_MAX_PROCESSES || config->max_processes > MAX_MAX_PROCESSES) {
        fprintf(stderr, "Error: Max processes must be between %d and %d\n", MIN_MAX_PROCESSES,
                MAX_MAX_PROCESSES);
        return -1;
    }

    /* Validate sample rate */
    if (config->sample_rate > config->max_processes) {
        fprintf(stderr, "Error: Sample rate (%u) cannot be greater than max processes (%u)\n",
                config->sample_rate, config->max_processes);
        return -1;
    }

    /* Validate that at least one monitoring type is enabled */
    if (!config->monitor_cpu && !config->monitor_syscalls && !config->monitor_io &&
        !config->monitor_memory && !config->monitor_network) {
        fprintf(stderr, "Error: At least one monitoring type must be enabled\n");
        return -1;
    }

    /* Validate output file if specified */
    if (strlen(config->output_file) > 0) {
        /* Check if the directory is writable */
        char *dir = strdup(config->output_file);
        if (!dir) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return -1;
        }

        char *last_slash = strrchr(dir, '/');
        if (last_slash) {
            *last_slash = '\0';
            if (access(dir, W_OK) != 0) {
                fprintf(stderr, "Error: Output directory '%s' is not writable\n", dir);
                free(dir);
                return -1;
            }
        }
        free(dir);
    }

    return 0;
}

static char *expand_home_path(const char *path)
{
    if (!path) {
        return NULL;
    }

    if (path[0] != '~') {
        return strdup(path);
    }

    struct passwd *passwd_entry = getpwuid(getuid());
    if (!passwd_entry) {
        return strdup(path);
    }

    size_t home_len = strlen(passwd_entry->pw_dir);
    size_t path_len = strlen(path + 1); /* Skip the ~ */
    char *expanded = malloc(home_len + path_len + 1);
    if (!expanded) {
        return NULL;
    }

    strcpy(expanded, passwd_entry->pw_dir);
    strcat(expanded, path + 1);
    return expanded;
}

/* Helper function to sanitize paths in error messages */
static const char *sanitize_path_for_error(const char *path)
{
    if (!path) {
        return "<null>";
    }

    /* If path contains home directory, show relative path */
    const char *home = getenv("HOME");
    if (home && strncmp(path, home, strlen(home)) == 0) {
        return path + strlen(home);
    }

    /* If path is in /tmp, show just the filename */
    if (strncmp(path, "/tmp/", TMP_PATH_PREFIX_LEN) == 0) {
        const char *filename = strrchr(path, '/');
        return filename ? filename : path;
    }

    /* For other paths, show just the filename */
    const char *filename = strrchr(path, '/');
    return filename ? filename : path;
}

int cli_load_config_file(const char *filename, struct hpmon_config *config)
{
    if (!config) {
        return -1;
    }

    char *expanded_path = expand_home_path(filename);
    if (!expanded_path) {
        fprintf(stderr, "Error: Memory allocation failed for path expansion\n");
        return -1;
    }

    FILE *file = fopen(expanded_path, "r");
    if (!file) {
        free(expanded_path);
        return -1;
    }

    char line[CONFIG_LINE_BUFFER_SIZE];
    int line_number = 0;
    int ret = 0;
    int critical_errors = 0; /* Track critical parsing errors */

    /* Store original config values for potential rollback */
    struct hpmon_config original_config = *config;

    while (fgets(line, sizeof(line), file)) {
        line_number++;

        /* Check if line was truncated (buffer overflow risk) */
        size_t line_len = strlen(line);
        if (line_len > 0 && line[line_len - 1] != '\n' && !feof(file)) {
            fprintf(stderr, "Error: Configuration line %d in %s is too long (max %d characters)\n",
                    line_number, sanitize_path_for_error(expanded_path),
                    CONFIG_LINE_BUFFER_SIZE - 1);
            critical_errors++;
            ret = -1;
            break;
        }

        /* Remove trailing newline */
        line[strcspn(line, "\n")] = '\0';

        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        /* Parse key=value pairs */
        char *equals = strchr(line, '=');
        if (!equals) {
            fprintf(stderr, "Warning: Invalid configuration line %d in %s: %s\n", line_number,
                    sanitize_path_for_error(expanded_path), line);
            continue;
        }

        *equals = '\0';
        char *key = line;
        char *value = equals + 1;

        /* Trim whitespace */
        while (*key == ' ' || *key == '\t') {
            key++;
        }
        while (*value == ' ' || *value == '\t') {
            value++;
        }

        /* Remove trailing whitespace */
        char *end = key + strlen(key) - 1;
        while (end > key && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        end = value + strlen(value) - 1;
        while (end > value && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        /* Validate that key and value are not empty after trimming */
        if (strlen(key) == 0 || strlen(value) == 0) {
            fprintf(stderr, "Warning: Empty key or value at line %d in %s\n", line_number,
                    sanitize_path_for_error(expanded_path));
            continue;
        }

        /* Parse configuration options */
        if (strcmp(key, "monitor_cpu") == 0) {
            config->monitor_cpu = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "monitor_syscalls") == 0) {
            config->monitor_syscalls = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "monitor_io") == 0) {
            config->monitor_io = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "monitor_memory") == 0) {
            config->monitor_memory = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "monitor_network") == 0) {
            config->monitor_network = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "track_tcp_only") == 0) {
            config->track_tcp_only = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "monitor_containers") == 0) {
            config->monitor_containers = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_tui") == 0) {
            config->enable_tui = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "enable_json_output") == 0) {
            config->enable_json_output = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "bpf_stats") == 0) {
            config->bpf_stats = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "poll_interval_ms") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Warning: Invalid poll_interval_ms value '%s' at line %d in %s\n",
                        value, line_number, sanitize_path_for_error(expanded_path));
            } else {
                config->poll_interval_ms = (unsigned int)val;
            }
        } else if (strcmp(key, "aggregation_window_ms") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr,
                        "Warning: Invalid aggregation_window_ms value '%s' at line %d in %s\n",
                        value, line_number, sanitize_path_for_error(expanded_path));
            } else {
                config->aggregation_window_ms = (unsigned int)val;
            }
        } else if (strcmp(key, "max_processes") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Warning: Invalid max_processes value '%s' at line %d in %s\n",
                        value, line_number, sanitize_path_for_error(expanded_path));
            } else {
                config->max_processes = (unsigned int)val;
            }
        } else if (strcmp(key, "pid") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Warning: Invalid pid value '%s' at line %d in %s\n", value,
                        line_number, sanitize_path_for_error(expanded_path));
            } else {
                config->pid = (unsigned int)val;
            }
        } else if (strcmp(key, "sample_rate") == 0) {
            char *endptr;
            long val = strtol(value, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Warning: Invalid sample_rate value '%s' at line %d in %s\n", value,
                        line_number, sanitize_path_for_error(expanded_path));
            } else {
                config->sample_rate = (unsigned int)val;
            }
        } else if (strcmp(key, "output_file") == 0) {
            safe_strcpy(config->output_file, sizeof(config->output_file), value);
        } else if (strcmp(key, "event_log_file") == 0) {
            safe_strcpy(config->event_log_file, sizeof(config->event_log_file), value);
        } else if (strcmp(key, "min_bytes") == 0) {
            char *endptr;
            unsigned long long val = strtoull(value, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val > UINT64_MAX) {
                fprintf(stderr, "Warning: Invalid min_bytes value '%s' at line %d in %s\n", value,
                        line_number, sanitize_path_for_error(expanded_path));
            } else {
                config->min_bytes = (__u64)val;
            }
        } else if (strcmp(key, "syscall_categories") == 0) {
            if (parse_syscall_categories(value, &config->syscall_bitmask) != 0) {
                fprintf(stderr, "Warning: Invalid syscall_categories value '%s' at line %d in %s\n",
                        value, line_number, sanitize_path_for_error(expanded_path));
            }
        } else {
            fprintf(stderr, "Warning: Unknown configuration option '%s' at line %d in %s\n", key,
                    line_number, sanitize_path_for_error(expanded_path));
        }
    }

    fclose(file);
    free(expanded_path);

    /* If critical errors occurred, rollback to original configuration */
    if (critical_errors > 0) {
        fprintf(stderr,
                "Warning: %d critical error(s) in configuration file, rolling back changes\n",
                critical_errors);
        *config = original_config;
        return -1;
    }

    return ret;
}

/* Helper function to convert syscall bitmask to comma-separated string */
static int syscall_bitmask_to_string(__u64 bitmask, char *buffer, size_t buffer_size)
{
    struct {
        const char *name;
        int bit;
    } category_map[] = {{"io", SYSCALL_CAT_FILE_IO},      {"memory", SYSCALL_CAT_MEMORY},
                        {"process", SYSCALL_CAT_PROCESS}, {"network", SYSCALL_CAT_NETWORK},
                        {"time", SYSCALL_CAT_TIME},       {"signal", SYSCALL_CAT_SIGNAL},
                        {"other", SYSCALL_CAT_OTHER},     {NULL, 0}};

    size_t pos;
    int first;
    int idx;

    if (!buffer) {
        return -1;
    }

    /* If bitmask is 0, it means track everything (default) */
    if (bitmask == 0) {
        buffer[0] = '\0';
        return 0;
    }

    buffer[0] = '\0';
    pos = 0;
    first = 1;

    for (idx = 0; category_map[idx].name; idx++) {
        if (bitmask & (1ULL << category_map[idx].bit)) {
            size_t name_len = strlen(category_map[idx].name);
            size_t comma_len = first ? 0 : 1;

            if (pos + comma_len + name_len >= buffer_size) {
                return -1; /* Buffer too small */
            }

            if (!first) {
                buffer[pos++] = ',';
            }

            strcpy(buffer + pos, category_map[idx].name);
            pos += name_len;
            first = 0;
        }
    }

    return 0;
}

int cli_save_config_file(const char *filename, const struct hpmon_config *config)
{
    char *expanded_path;
    FILE *file;
    char categories_str[MAX_PATH_LEN];

    if (!filename || !config) {
        return -1;
    }

    expanded_path = expand_home_path(filename);
    if (!expanded_path) {
        fprintf(stderr, "Error: Memory allocation failed for path expansion\n");
        return -1;
    }

    file = fopen(expanded_path, "w");
    if (!file) {
        fprintf(stderr, "Error: Could not open %s for writing: %s\n",
                sanitize_path_for_error(expanded_path), strerror(errno));
        free(expanded_path);
        return -1;
    }

    fprintf(file, "# HPMon Configuration File\n");
    fprintf(file, "# Generated automatically\n\n");

    fprintf(file, "# Monitoring options\n");
    fprintf(file, "monitor_cpu=%s\n", config->monitor_cpu ? "true" : "false");
    fprintf(file, "monitor_syscalls=%s\n", config->monitor_syscalls ? "true" : "false");
    fprintf(file, "monitor_io=%s\n", config->monitor_io ? "true" : "false");
    fprintf(file, "monitor_memory=%s\n", config->monitor_memory ? "true" : "false");
    fprintf(file, "monitor_network=%s\n", config->monitor_network ? "true" : "false");
    fprintf(file, "track_tcp_only=%s\n", config->track_tcp_only ? "true" : "false");
    fprintf(file, "monitor_containers=%s\n", config->monitor_containers ? "true" : "false");

    /* Save syscall categories if configured */
    if (config->syscall_bitmask != 0) {
        if (syscall_bitmask_to_string(config->syscall_bitmask, categories_str,
                                      sizeof(categories_str)) == 0) {
            fprintf(file, "syscall_categories=%s\n", categories_str);
        }
    }

    fprintf(file, "\n# Output options\n");
    fprintf(file, "enable_tui=%s\n", config->enable_tui ? "true" : "false");
    fprintf(file, "enable_json_output=%s\n", config->enable_json_output ? "true" : "false");
    fprintf(file, "bpf_stats=%s\n", config->bpf_stats ? "true" : "false");
    if (strlen(config->output_file) > 0) {
        fprintf(file, "output_file=%s\n", config->output_file);
    }
    if (strlen(config->event_log_file) > 0) {
        fprintf(file, "event_log_file=%s\n", config->event_log_file);
    }

    fprintf(file, "\n# Performance options\n");
    fprintf(file, "poll_interval_ms=%u\n", config->poll_interval_ms);
    fprintf(file, "aggregation_window_ms=%u\n", config->aggregation_window_ms);
    fprintf(file, "max_processes=%u\n", config->max_processes);
    fprintf(file, "pid=%u\n", config->pid);
    fprintf(file, "sample_rate=%u\n", config->sample_rate);
    fprintf(file, "min_bytes=%llu\n", (unsigned long long)config->min_bytes);

    fclose(file);
    free(expanded_path);

    printf("Configuration saved to %s\n", filename);
    return 0;
}

int cli_auto_load_config(struct hpmon_config *config)
{
    const char *config_files[] = {LOCAL_CONFIG_FILE, "~/.hpmon.conf", DEFAULT_CONFIG_FILE, NULL};

    for (int i = 0; config_files[i]; i++) {
        if (cli_load_config_file(config_files[i], config) == 0) {
            printf("Loaded configuration from %s\n", config_files[i]);
            return 0;
        }
    }

    return -1; /* No config file found */
}

void cli_print_config(const struct hpmon_config *config)
{
    char categories_str[MAX_PATH_LEN];

    if (!config) {
        return;
    }

    printf("Current Configuration:\n");
    printf("  CPU monitoring: %s\n", config->monitor_cpu ? "enabled" : "disabled");
    printf("  Syscall monitoring: %s\n", config->monitor_syscalls ? "enabled" : "disabled");

    /* Print syscall categories if filtering is enabled */
    if (config->syscall_bitmask != 0) {
        if (syscall_bitmask_to_string(config->syscall_bitmask, categories_str,
                                      sizeof(categories_str)) == 0) {
            printf("  Syscall categories: %s\n", categories_str);
        }
    } else {
        printf("  Syscall categories: all (no filtering)\n");
    }
    printf("  I/O monitoring: %s\n", config->monitor_io ? "enabled" : "disabled");
    printf("  Memory monitoring: %s\n", config->monitor_memory ? "enabled" : "disabled");
    printf("  Network monitoring: %s\n", config->monitor_network ? "enabled" : "disabled");
    printf("  TCP-only tracking: %s\n", config->track_tcp_only ? "enabled" : "disabled");
    printf("  Container monitoring: %s\n", config->monitor_containers ? "enabled" : "disabled");
    printf("  Poll interval: %u ms\n", config->poll_interval_ms);
    printf("  Aggregation window: %u ms\n", config->aggregation_window_ms);
    printf("  Max processes: %u\n", config->max_processes);
    printf("  Process filter PID: %u%s\n", config->pid, config->pid == 0 ? " (monitor all)" : "");
    printf("  Sample rate: %u%s\n", config->sample_rate,
           config->sample_rate == 0 ? " (sample all)" : "");
    printf("  Min bytes filter: %llu%s\n", (unsigned long long)config->min_bytes,
           config->min_bytes == 0 ? " (no filter)" : "");

    if (config->enable_tui) {
        printf("  Terminal UI: enabled\n");
    }

    printf("  Event log file: %s\n",
           strlen(config->event_log_file) > 0 ? config->event_log_file : "disabled");

    if (config->enable_json_output) {
        printf("  JSON output: %s\n",
               strlen(config->output_file) > 0 ? config->output_file : "stdout");
    }

    printf("  BPF statistics: %s\n", config->bpf_stats ? "enabled" : "disabled");
}

void init_bpf_config_from_cli(struct hpmon_config *config)
{
    if (!config) {
        return;
    }

    config->bpf.cpu.sample_rate = config->sample_rate;
    config->bpf.io.sample_rate = config->sample_rate;
    config->bpf.mem.sample_rate = config->sample_rate;
    config->bpf.net.sample_rate = config->sample_rate;

    config->bpf.cpu.tgid = config->pid;
    config->bpf.io.tgid = config->pid;
    config->bpf.mem.tgid = config->pid;
    config->bpf.net.tgid = config->pid;
    config->bpf.sys.tgid = config->pid;

    config->bpf.io.min_bytes_threshold = config->min_bytes;
    config->bpf.net.min_bytes_threshold = config->min_bytes;
    config->bpf.net.track_tcp_only = config->track_tcp_only ? 1 : 0;

    config->bpf.sys.syscall_bitmask = config->syscall_bitmask;
}

/* Helper function to parse syscall categories from comma-separated string */
static int parse_syscall_categories(const char *categories_str, __u64 *bitmask)
{
    struct {
        const char *name;
        int bit;
    } category_map[] = {{"io", SYSCALL_CAT_FILE_IO},      {"memory", SYSCALL_CAT_MEMORY},
                        {"process", SYSCALL_CAT_PROCESS}, {"network", SYSCALL_CAT_NETWORK},
                        {"time", SYSCALL_CAT_TIME},       {"signal", SYSCALL_CAT_SIGNAL},
                        {"other", SYSCALL_CAT_OTHER},     {NULL, 0}};

    char *str_copy;
    char *token;
    int idx, found;
    char *end;

    if (!categories_str || !bitmask) {
        return -1;
    }

    *bitmask = 0;

    /* If empty string, use default (track everything) */
    if (strlen(categories_str) == 0) {
        *bitmask = 0;
        return 0;
    }

    /* Make a copy of the string to tokenize */
    str_copy = strdup(categories_str);
    if (!str_copy) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        return -1;
    }

    token = strtok(str_copy, ",");
    while (token) {
        /* Trim whitespace */
        while (*token == ' ' || *token == '\t') {
            token++;
        }
        end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        /* Find matching category */
        found = 0;
        for (idx = 0; category_map[idx].name; idx++) {
            if (strcmp(token, category_map[idx].name) == 0) {
                *bitmask |= (1ULL << category_map[idx].bit);
                found = 1;
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "Error: Unknown syscall category '%s'\n", token);
            fprintf(stderr,
                    "Valid categories: io, memory, process, network, time, signal, other\n");
            free(str_copy);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(str_copy);
    return 0;
}

int cli_parse_arguments(int argc, char *argv[], struct cli_options *options)
{
    if (!options) {
        return CLI_ERROR;
    }

    int option_char;
    char *save_config_file = NULL;

    /* Reset getopt state - NOTE: This is not thread-safe due to global optind.
     * If this function needs to be called from multiple threads, external
     * synchronization is required. */
    optind = 1;

    while ((option_char = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (option_char) {
        case OPT_SAVE_EVENT_LOG: {
            size_t len = strlen(optarg);
            if (len >= sizeof(options->config.event_log_file)) {
                fprintf(stderr, "Error: Event log filename too long\n");
                free(save_config_file);
                return CLI_ERROR;
            }
            safe_strcpy(options->config.event_log_file, sizeof(options->config.event_log_file),
                        optarg);
            break;
        }
        case 'c':
            options->config.monitor_cpu = true;
            break;
        case 's':
            options->config.monitor_syscalls = true;
            break;
        case 'i':
            options->config.monitor_io = true;
            break;
        case 'M':
            options->config.monitor_memory = true;
            break;
        case 'n':
            options->config.monitor_network = true;
            break;
        case 'C':
            options->config.monitor_containers = true;
            break;
        case 't':
            options->config.enable_tui = true;
            break;
        case 'j':
            options->config.enable_json_output = true;
            break;
        case 'o': {
            size_t len = strlen(optarg);
            if (len >= sizeof(options->config.output_file)) {
                fprintf(stderr, "Error: Output filename too long\n");
                free(save_config_file);
                return CLI_ERROR;
            }
            safe_strcpy(options->config.output_file, sizeof(options->config.output_file), optarg);
            break;
        }
        case 'f':
            if (options->config_file) {
                free(options->config_file);
                options->config_file = NULL;
            }
            options->config_file = strdup(optarg);
            if (!options->config_file) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                free(save_config_file);
                return CLI_ERROR;
            }
            break;
        case 'p': {
            char *endptr;
            long val = strtol(optarg, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Error: Invalid poll interval value '%s'\n", optarg);
                free(save_config_file);
                return CLI_ERROR;
            }
            options->config.poll_interval_ms = (unsigned int)val;
            break;
        }
        case 'w': {
            char *endptr;
            long val = strtol(optarg, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Error: Invalid aggregation window value '%s'\n", optarg);
                free(save_config_file);
                return CLI_ERROR;
            }
            options->config.aggregation_window_ms = (unsigned int)val;
            break;
        }
        case 'm': {
            char *endptr;
            long val = strtol(optarg, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Error: Invalid max processes value '%s'\n", optarg);
                free(save_config_file);
                return CLI_ERROR;
            }
            options->config.max_processes = (unsigned int)val;
            break;
        }
        case 'P': {
            char *endptr;
            long val = strtol(optarg, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Error: Invalid PID value '%s'\n", optarg);
                free(save_config_file);
                return CLI_ERROR;
            }
            options->config.pid = (unsigned int)val;
            break;
        }
        case 'r': {
            char *endptr;
            long val = strtol(optarg, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val < 0 || val > UINT32_MAX) {
                fprintf(stderr, "Error: Invalid sample rate value '%s'\n", optarg);
                free(save_config_file);
                return CLI_ERROR;
            }
            options->config.sample_rate = (unsigned int)val;
            break;
        }
        case OPT_NO_CPU: /* --no-cpu */
            options->config.monitor_cpu = false;
            break;
        case OPT_NO_SYSCALLS: /* --no-syscalls */
            options->config.monitor_syscalls = false;
            break;
        case OPT_NO_IO: /* --no-io */
            options->config.monitor_io = false;
            break;
        case OPT_NO_MEMORY: /* --no-memory */
            options->config.monitor_memory = false;
            break;
        case OPT_NO_NETWORK: /* --no-network */
            options->config.monitor_network = false;
            break;
        case OPT_BPF_STATS: /* --bpf-stats */
            options->config.bpf_stats = true;
            break;
        case OPT_MIN_BYTES: /* --min-bytes */
        {
            char *endptr;
            unsigned long long val = strtoull(optarg, &endptr, DECIMAL_BASE);
            if (*endptr != '\0' || val > UINT64_MAX) {
                fprintf(stderr, "Error: Invalid min-bytes value '%s'\n", optarg);
                free(save_config_file);
                return CLI_ERROR;
            }
            options->config.min_bytes = (__u64)val;
            break;
        }
        case OPT_TCP: /* --tcp */
            options->config.track_tcp_only = true;
            break;
        case OPT_SYSCALL_CATEGORY: /* --syscall-category */
        {
            if (parse_syscall_categories(optarg, &options->config.syscall_bitmask) != 0) {
                free(save_config_file);
                return CLI_ERROR;
            }
            break;
        }
        case OPT_SAVE_CONFIG: /* --save-config */
            if (save_config_file) {
                free(save_config_file);
                save_config_file = NULL;
            }
            save_config_file = strdup(optarg);
            if (!save_config_file) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return CLI_ERROR;
            }
            break;
        case 'h':
            options->show_help = true;
            break;
        case 'v':
            options->show_version = true;
            break;
        case '?':
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            free(save_config_file);
            return CLI_ERROR;
        default:
            free(save_config_file);
            return CLI_ERROR;
        }
    }

    /* Handle help and version requests */
    if (options->show_help) {
        cli_print_usage(argv[0]);
        free(save_config_file);
        return CLI_EXIT_SUCCESS;
    }

    if (options->show_version) {
        cli_print_version();
        free(save_config_file);
        return CLI_EXIT_SUCCESS;
    }

    /* Load configuration file if specified */
    if (options->config_file) {
        if (cli_load_config_file(options->config_file, &options->config) != 0) {
            fprintf(stderr, "Error: Could not load configuration file '%s'\n",
                    options->config_file);
            free(save_config_file);
            return CLI_ERROR;
        }
    }

    /* Validate the configuration */
    if (cli_validate_config(&options->config) != 0) {
        free(save_config_file);
        return CLI_ERROR;
    }

    /* Save configuration if requested */
    if (save_config_file) {
        int ret = cli_save_config_file(save_config_file, &options->config);
        free(save_config_file);
        if (ret != 0) {
            return CLI_ERROR;
        }
        return CLI_EXIT_SUCCESS; /* Exit after saving config */
    }

    init_bpf_config_from_cli(&options->config);

    return CLI_SUCCESS;
}
