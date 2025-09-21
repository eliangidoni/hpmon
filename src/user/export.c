// SPDX-License-Identifier: MIT
/* HPMon Data Export Engine
 *
 * This module implements comprehensive data export functionality
 * supporting multiple formats and integration with monitoring systems.
 */

#include "export.h"
#include "data_collector.h"
#include "safe_string.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Constants to avoid magic numbers */
#define DEFAULT_HEALTH_SCORE 100.0
#define PERFECT_HEALTH_SCORE 100.0
#define ESTIMATED_RECORDS_PER_HOUR 60

/* Error handling conventions:
 * - Standard errno codes for system-related errors (file I/O, memory allocation)
 * - EINVAL for invalid parameters
 * - ENODATA for missing data conditions
 * - EBUSY for concurrency issues
 * - ENOTSUP for unsupported operations
 */

/* Global export engine state */
static struct {
    bool initialized;
    struct export_stats stats;
    struct historical_storage history;
    const struct hpmon_config *config;
} g_export_engine = {0};

/* Format strings for different export types */
static const char *format_names[] = {"json", "csv", "prometheus", "influxdb", "custom"};

/* Helper function declarations */
static int write_json_basic_stats(FILE *file_ptr);
static int write_json_detailed_processes(FILE *file_ptr);
static int write_csv_header(FILE *file_ptr, const struct export_config *config);
static int write_csv_process_data(FILE *file_ptr, const struct export_config *config);
static int write_prometheus_metrics(FILE *file_ptr);
static int write_influxdb_metrics(FILE *file_ptr, const char *measurement);
static uint64_t get_current_timestamp(void);
static int ensure_directory_exists(const char *filepath);

/* Initialize the export engine */
int export_engine_init(const struct hpmon_config *config)
{
    if (!config) {
        return -EINVAL;
    }

    if (g_export_engine.initialized) {
        return -EALREADY;
    }

    /* Initialize export engine state */
    memset(&g_export_engine, 0, sizeof(g_export_engine));
    g_export_engine.config = config;

    /* Initialize historical storage */
    g_export_engine.history.retention_hours = DEFAULT_RETENTION_HOURS;
    g_export_engine.history.initialized = true;

    /* Initialize statistics */
    g_export_engine.stats.exports_performed = 0;
    g_export_engine.stats.total_records_exported = 0;
    g_export_engine.stats.total_bytes_exported = 0;

    printf("Export Engine: Initialized with %u hour retention\n",
           g_export_engine.history.retention_hours);

    g_export_engine.initialized = true;
    return 0;
}

/* Cleanup the export engine */
void export_engine_cleanup(void)
{
    if (!g_export_engine.initialized) {
        return;
    }

    printf("Export Engine: Cleanup complete\n");
    memset(&g_export_engine, 0, sizeof(g_export_engine));
}

/* Export data to a file or stream */
int export_data(const char *filename, const struct export_config *export_config)
{
    int ret = 0;
    uint64_t start_time, export_duration;
    size_t bytes_written = 0;

    if (!g_export_engine.initialized || !export_config) {
        return -EINVAL;
    }

    /* Validate configuration */
    if (!export_validate_config(export_config)) {
        return -EINVAL;
    }

    start_time = get_current_timestamp();

    /* Ensure directory exists if filename provided */
    if (filename) {
        ensure_directory_exists(filename);
    }

    /* Export based on format */
    switch (export_config->format) {
    case EXPORT_FORMAT_JSON:
        if (export_config->data_type == EXPORT_DATA_NETWORK_METRICS) {
            ret = export_network_data(filename, export_config);
        } else if (export_config->data_type == EXPORT_DATA_MEMORY_METRICS) {
            ret = export_memory_data(filename, export_config);
        } else {
            ret = export_json_stats(filename,
                                    export_config->data_type == EXPORT_DATA_DETAILED_PROCESSES);
        }
        break;

    case EXPORT_FORMAT_CSV:
        if (export_config->data_type == EXPORT_DATA_NETWORK_METRICS) {
            ret = export_network_data(filename, export_config);
        } else if (export_config->data_type == EXPORT_DATA_MEMORY_METRICS) {
            ret = export_memory_data(filename, export_config);
        } else {
            ret = export_csv_stats(filename, export_config);
        }
        break;

    case EXPORT_FORMAT_PROMETHEUS:
        ret = export_prometheus_metrics(filename);
        break;

    case EXPORT_FORMAT_INFLUXDB:
        ret = export_influxdb_metrics(filename, "hpmon");
        break;

    default:
        ret = -ENOTSUP;
        break;
    }

    /* Update statistics with overflow protection */
    export_duration = get_current_timestamp() - start_time;

    /* Prevent overflow in statistics counters */
    if (g_export_engine.stats.exports_performed < UINT64_MAX) {
        g_export_engine.stats.exports_performed++;
    }

    g_export_engine.stats.last_export_time = start_time;
    g_export_engine.stats.last_export_duration_ms = export_duration;

    if (filename) {
        struct stat file_stats;
        if (stat(filename, &file_stats) == 0) {
            bytes_written = file_stats.st_size;
        }
        safe_strncpy(g_export_engine.stats.last_export_destination, filename,
                     sizeof(g_export_engine.stats.last_export_destination));
    } else {
        safe_strncpy(g_export_engine.stats.last_export_destination, "stdout",
                     sizeof(g_export_engine.stats.last_export_destination));
    }

    safe_strncpy(g_export_engine.stats.last_export_format, format_names[export_config->format],
                 sizeof(g_export_engine.stats.last_export_format));

    /* Prevent overflow in total bytes counter */
    if (g_export_engine.stats.total_bytes_exported <= UINT64_MAX - bytes_written) {
        g_export_engine.stats.total_bytes_exported += bytes_written;
    }

    return ret;
}

/* Export current statistics in JSON format */
int export_json_stats(const char *filename, bool include_detailed)
{
    FILE *file_ptr;
    int ret = 0;

    if (!g_export_engine.initialized) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    fprintf(file_ptr, "{\n");
    fprintf(file_ptr, "  \"hpmon\": {\n");
    fprintf(file_ptr, "    \"version\": \"%s\",\n", hpmon_version_string());
    fprintf(file_ptr, "    \"timestamp\": %lu,\n", get_current_timestamp());
    fprintf(file_ptr, "    \"export_time\": \"%s\"\n",
            export_format_timestamp(get_current_timestamp(), NULL, 0));
    fprintf(file_ptr, "  },\n");

    /* Basic statistics */
    ret = write_json_basic_stats(file_ptr);
    if (ret != 0) {
        goto cleanup;
    }

    /* Detailed processes if requested */
    if (include_detailed) {
        fprintf(file_ptr, ",\n");
        ret = write_json_detailed_processes(file_ptr);
        if (ret != 0) {
            goto cleanup;
        }
    }

    fprintf(file_ptr, "\n}\n");

cleanup:
    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            /* Log error but don't override the main return code if it was successful */
            if (ret == 0) {
                ret = -errno;
            }
        }
    }

    return ret;
}

/* Export current statistics in CSV format */
int export_csv_stats(const char *filename, const struct export_config *export_config)
{
    FILE *file_ptr;
    int ret = 0;

    if (!g_export_engine.initialized || !export_config) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    /* Write header if requested */
    if (export_config->include_header) {
        ret = write_csv_header(file_ptr, export_config);
        if (ret != 0) {
            goto cleanup;
        }
    }

    /* Write data based on type */
    switch (export_config->data_type) {
    case EXPORT_DATA_BASIC_STATS:
    case EXPORT_DATA_DETAILED_PROCESSES:
        ret = write_csv_process_data(file_ptr, export_config);
        break;

    default:
        ret = -ENOTSUP;
        break;
    }

cleanup:
    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            /* Log error but don't override the main return code if it was successful */
            if (ret == 0) {
                ret = -errno;
            }
        }
    }

    return ret;
}

/* Export in Prometheus metrics format */
int export_prometheus_metrics(const char *filename)
{
    FILE *file_ptr;
    int ret = 0;

    if (!g_export_engine.initialized) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    ret = write_prometheus_metrics(file_ptr);

    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            /* Log error but don't override the main return code if it was successful */
            if (ret == 0) {
                ret = -errno;
            }
        }
    }

    return ret;
}

/* Export in InfluxDB line protocol format */
int export_influxdb_metrics(const char *filename, const char *measurement_name)
{
    FILE *file_ptr;
    int ret = 0;

    if (!g_export_engine.initialized || !measurement_name) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    ret = write_influxdb_metrics(file_ptr, measurement_name);

    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            /* Log error but don't override the main return code if it was successful */
            if (ret == 0) {
                ret = -errno;
            }
        }
    }

    return ret;
}

/* Export network metrics data */
int export_network_data(const char *filename, const struct export_config *export_config)
{
    FILE *file_ptr;
    struct process_data processes[MAX_TRACKED_PROCESSES];
    size_t process_count;
    int ret = 0;

    if (!g_export_engine.initialized || !export_config) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    if (data_collector_get_processes(processes, MAX_TRACKED_PROCESSES, &process_count) != 0) {
        if (filename && file_ptr != stdout) {
            fclose(file_ptr);
        }
        return -ENODATA;
    }

    if (export_config->format == EXPORT_FORMAT_JSON) {
        fprintf(file_ptr, "{\n");
        fprintf(file_ptr, "  \"hpmon_network_metrics\": {\n");
        fprintf(file_ptr, "    \"version\": \"%s\",\n", hpmon_version_string());
        fprintf(file_ptr, "    \"timestamp\": %lu,\n", get_current_timestamp());
        fprintf(file_ptr, "    \"processes\": [\n");

        size_t network_processes = 0;
        for (size_t i = 0; i < process_count; i++) {
            const struct process_data *proc = &processes[i];

            if (!proc->active || (proc->network_rx_bytes == 0 && proc->network_tx_bytes == 0)) {
                continue;
            }

            if (network_processes > 0) {
                fprintf(file_ptr, ",\n");
            }

            fprintf(file_ptr, "      {\n");
            fprintf(file_ptr, "        \"pid\": %u,\n", proc->pid);
            fprintf(file_ptr, "        \"comm\": \"%s\",\n", proc->comm);
            fprintf(file_ptr, "        \"network_rx_bytes\": %lu,\n", proc->network_rx_bytes);
            fprintf(file_ptr, "        \"network_tx_bytes\": %lu,\n", proc->network_tx_bytes);
            fprintf(file_ptr, "        \"network_rx_packets\": %lu,\n", proc->network_rx_packets);
            fprintf(file_ptr, "        \"network_tx_packets\": %lu,\n", proc->network_tx_packets);
            fprintf(file_ptr, "        \"network_tcp_connections\": %lu,\n",
                    proc->network_tcp_connections);
            fprintf(file_ptr, "        \"network_udp_packets\": %lu,\n", proc->network_udp_packets);
            fprintf(file_ptr, "        \"network_rx_rate_mbps\": %u,\n",
                    proc->network_rx_rate_mbps);
            fprintf(file_ptr, "        \"network_tx_rate_mbps\": %u\n", proc->network_tx_rate_mbps);
            fprintf(file_ptr, "      }");

            network_processes++;
        }

        fprintf(file_ptr, "\n    ],\n");
        fprintf(file_ptr, "    \"network_process_count\": %zu\n", network_processes);
        fprintf(file_ptr, "  }\n");
        fprintf(file_ptr, "}\n");
    } else if (export_config->format == EXPORT_FORMAT_CSV) {
        /* CSV header for network metrics */
        fprintf(file_ptr, "timestamp,pid,comm,rx_bytes,tx_bytes,rx_packets,tx_packets,tcp_"
                          "connections,udp_packets,rx_rate_mbps,tx_rate_mbps\n");

        uint64_t timestamp = get_current_timestamp();
        for (size_t i = 0; i < process_count; i++) {
            const struct process_data *proc = &processes[i];

            if (!proc->active || (proc->network_rx_bytes == 0 && proc->network_tx_bytes == 0)) {
                continue;
            }

            fprintf(file_ptr, "%lu,%u,%s,%lu,%lu,%lu,%lu,%lu,%lu,%u,%u\n", timestamp, proc->pid,
                    proc->comm, proc->network_rx_bytes, proc->network_tx_bytes,
                    proc->network_rx_packets, proc->network_tx_packets,
                    proc->network_tcp_connections, proc->network_udp_packets,
                    proc->network_rx_rate_mbps, proc->network_tx_rate_mbps);
        }
    } else {
        ret = -ENOTSUP;
    }

    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            if (ret == 0) {
                ret = -errno;
            }
        }
    }

    return ret;
}

/* Export memory metrics data */
int export_memory_data(const char *filename, const struct export_config *export_config)
{
    FILE *file_ptr;
    struct process_data processes[MAX_TRACKED_PROCESSES];
    size_t process_count;
    int ret = 0;

    if (!g_export_engine.initialized || !export_config) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    if (data_collector_get_processes(processes, MAX_TRACKED_PROCESSES, &process_count) != 0) {
        if (filename && file_ptr != stdout) {
            fclose(file_ptr);
        }
        return -ENODATA;
    }

    if (export_config->format == EXPORT_FORMAT_JSON) {
        fprintf(file_ptr, "{\n");
        fprintf(file_ptr, "  \"hpmon_memory_metrics\": {\n");
        fprintf(file_ptr, "    \"version\": \"%s\",\n", hpmon_version_string());
        fprintf(file_ptr, "    \"timestamp\": %lu,\n", get_current_timestamp());
        fprintf(file_ptr, "    \"processes\": [\n");

        size_t memory_processes = 0;
        for (size_t i = 0; i < process_count; i++) {
            const struct process_data *proc = &processes[i];

            if (!proc->active || proc->memory_current_bytes == 0) {
                continue;
            }

            if (memory_processes > 0) {
                fprintf(file_ptr, ",\n");
            }

            fprintf(file_ptr, "      {\n");
            fprintf(file_ptr, "        \"pid\": %u,\n", proc->pid);
            fprintf(file_ptr, "        \"comm\": \"%s\",\n", proc->comm);
            fprintf(file_ptr, "        \"memory_alloc_bytes\": %lu,\n", proc->memory_alloc_bytes);
            fprintf(file_ptr, "        \"memory_free_bytes\": %lu,\n", proc->memory_free_bytes);
            fprintf(file_ptr, "        \"memory_current_bytes\": %lu,\n",
                    proc->memory_current_bytes);
            fprintf(file_ptr, "        \"memory_peak_bytes\": %lu,\n", proc->memory_peak_bytes);
            fprintf(file_ptr, "        \"memory_page_faults\": %lu,\n", proc->memory_page_faults);
            fprintf(file_ptr, "        \"memory_alloc_rate_mbps\": %u\n",
                    proc->memory_alloc_rate_mbps);
            fprintf(file_ptr, "      }");

            memory_processes++;
        }

        fprintf(file_ptr, "\n    ],\n");
        fprintf(file_ptr, "    \"memory_process_count\": %zu\n", memory_processes);
        fprintf(file_ptr, "  }\n");
        fprintf(file_ptr, "}\n");
    } else if (export_config->format == EXPORT_FORMAT_CSV) {
        /* CSV header for memory metrics */
        fprintf(file_ptr, "timestamp,pid,comm,alloc_bytes,free_bytes,current_bytes,peak_bytes,page_"
                          "faults,alloc_rate_mbps\n");

        uint64_t timestamp = get_current_timestamp();
        for (size_t i = 0; i < process_count; i++) {
            const struct process_data *proc = &processes[i];

            if (!proc->active || proc->memory_current_bytes == 0) {
                continue;
            }

            fprintf(file_ptr, "%lu,%u,%s,%lu,%lu,%lu,%lu,%lu,%u\n", timestamp, proc->pid,
                    proc->comm, proc->memory_alloc_bytes, proc->memory_free_bytes,
                    proc->memory_current_bytes, proc->memory_peak_bytes, proc->memory_page_faults,
                    proc->memory_alloc_rate_mbps);
        }
    } else {
        ret = -ENOTSUP;
    }

    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            if (ret == 0) {
                ret = -errno;
            }
        }
    }

    return ret;
}

/* Store current data snapshot for historical tracking */
int store_historical_snapshot(void)
{
    struct historical_record *record;
    struct collection_stats stats;
    uint64_t current_time;
    int ret = 0;

    if (!g_export_engine.initialized || !g_export_engine.history.initialized) {
        return -EINVAL;
    }

    /* Get current data */
    if (data_collector_get_stats(&stats) != 0) {
        return -ENODATA;
    }

    current_time = get_current_timestamp();

    /* Get next record slot */
    record = &g_export_engine.history.records[g_export_engine.history.write_index];

    /* Store the snapshot */
    record->timestamp = current_time;
    record->stats = stats;

    /* Get process data */
    data_collector_get_processes(record->processes, MAX_TRACKED_PROCESSES, &record->process_count);

    /* Update storage state */
    g_export_engine.history.write_index =
        (g_export_engine.history.write_index + 1) % MAX_HISTORICAL_RECORDS;

    if (g_export_engine.history.record_count < MAX_HISTORICAL_RECORDS) {
        g_export_engine.history.record_count++;
    } else {
        g_export_engine.history.is_full = true;
    }

    g_export_engine.history.newest_timestamp = current_time;
    if (g_export_engine.history.record_count == 1) {
        g_export_engine.history.oldest_timestamp = current_time;
    }

    return ret;
}

/* Export historical data */
int export_historical_data(const char *filename, const struct export_config *export_config)
{
    FILE *file_ptr;
    size_t records_exported = 0;
    uint64_t start_time = export_config->time_range_start;
    uint64_t end_time = export_config->time_range_end;

    if (!g_export_engine.initialized || !export_config) {
        return -EINVAL;
    }

    file_ptr = filename ? fopen(filename, "w") : stdout;
    if (!file_ptr) {
        return -errno;
    }

    /* If no time range specified, export all */
    if (start_time == 0 && end_time == 0) {
        /* Validate that historical storage has valid data */
        if (g_export_engine.history.record_count == 0) {
            if (filename && file_ptr != stdout) {
                fclose(file_ptr);
            }
            return -ENODATA;
        }
        start_time = g_export_engine.history.oldest_timestamp;
        end_time = g_export_engine.history.newest_timestamp;
    }

    if (export_config->format == EXPORT_FORMAT_JSON) {
        fprintf(file_ptr, "{\n");
        fprintf(file_ptr, "  \"hpmon_historical_data\": {\n");
        fprintf(file_ptr, "    \"version\": \"%s\",\n", hpmon_version_string());
        fprintf(file_ptr, "    \"export_timestamp\": %lu,\n", get_current_timestamp());
        fprintf(file_ptr, "    \"time_range\": {\n");
        fprintf(file_ptr, "      \"start\": %lu,\n", start_time);
        fprintf(file_ptr, "      \"end\": %lu\n", end_time);
        fprintf(file_ptr, "    },\n");
        fprintf(file_ptr, "    \"records\": [\n");

        /* Export matching records */
        for (size_t i = 0; i < g_export_engine.history.record_count; i++) {
            const struct historical_record *record = &g_export_engine.history.records[i];

            if (record->timestamp >= start_time && record->timestamp <= end_time) {
                if (records_exported > 0) {
                    fprintf(file_ptr, ",\n");
                }

                fprintf(file_ptr, "      {\n");
                fprintf(file_ptr, "        \"timestamp\": %lu,\n", record->timestamp);
                fprintf(file_ptr, "        \"active_processes\": %lu,\n",
                        record->stats.active_processes);
                fprintf(file_ptr, "        \"total_processes\": %lu,\n",
                        record->stats.total_processes);
                fprintf(file_ptr, "        \"total_syscalls\": %lu,\n",
                        record->stats.total_syscalls);
                fprintf(file_ptr, "        \"total_io_bytes\": %lu\n",
                        record->stats.total_io_bytes);
                fprintf(file_ptr, "      }");

                records_exported++;
                if (export_config->max_records > 0 &&
                    records_exported >= export_config->max_records) {
                    break;
                }
            }
        }

        fprintf(file_ptr, "\n    ],\n");
        fprintf(file_ptr, "    \"records_exported\": %zu\n", records_exported);
        fprintf(file_ptr, "  }\n");
        fprintf(file_ptr, "}\n");
    }

    g_export_engine.stats.last_export_record_count = records_exported;
    g_export_engine.stats.total_records_exported += records_exported;

    if (filename && file_ptr != stdout) {
        if (fclose(file_ptr) != 0) {
            return -errno;
        }
    }

    return 0;
}

/* Get export engine statistics */
int export_engine_get_stats(struct export_stats *stats)
{
    if (!g_export_engine.initialized || !stats) {
        return -EINVAL;
    }

    *stats = g_export_engine.stats;
    return 0;
}

/* Configure historical data retention */
int export_configure_retention(uint32_t retention_hours)
{
    if (!g_export_engine.initialized) {
        return -EINVAL;
    }

    if (retention_hours < 1 || retention_hours > HOURS_PER_YEAR) { /* 1 hour to 1 year */
        return -EINVAL;
    }

    /* Additional validation for system limitations */
    size_t estimated_records_per_hour = ESTIMATED_RECORDS_PER_HOUR; /* Assume 1 record per minute */
    size_t estimated_total_records = retention_hours * estimated_records_per_hour;

    if (estimated_total_records > MAX_HISTORICAL_RECORDS) {
        /* Retention period would exceed storage capacity - adjust assumption */
        /* For larger retention periods, assume less frequent recording */
        size_t adjusted_rate = MAX_HISTORICAL_RECORDS / retention_hours;
        if (adjusted_rate < 1) {
            /* Retention period is too large even with minimal recording */
            return -E2BIG;
        }
    }

    g_export_engine.history.retention_hours = retention_hours;
    return 0;
}

/* Cleanup old historical data based on retention policy */
int export_cleanup_historical_data(void)
{
    uint64_t current_time = get_current_timestamp();
    uint64_t retention_threshold =
        current_time - ((uint64_t)g_export_engine.history.retention_hours *
                        SECONDS_PER_HOUR); /* Convert hours to seconds */
    int cleaned_count = 0;
    size_t write_idx = 0;

    if (!g_export_engine.initialized || !g_export_engine.history.initialized) {
        return -EINVAL;
    }

    /* Compact array by keeping only valid records */
    for (size_t i = 0; i < g_export_engine.history.record_count; i++) {
        if (g_export_engine.history.records[i].timestamp >= retention_threshold) {
            /* Keep this record - move it to the write position if needed */
            if (write_idx != i) {
                g_export_engine.history.records[write_idx] = g_export_engine.history.records[i];
            }
            write_idx++;
        } else {
            /* This record is too old - count it as cleaned */
            cleaned_count++;
        }
    }

    /* Update the record count to reflect the compacted array */
    g_export_engine.history.record_count = write_idx;

    /* Update write index to point to next available slot */
    g_export_engine.history.write_index = write_idx % MAX_HISTORICAL_RECORDS;

    /* Update oldest timestamp if we have records */
    if (g_export_engine.history.record_count > 0) {
        g_export_engine.history.oldest_timestamp = g_export_engine.history.records[0].timestamp;
        /* Find the actual oldest timestamp */
        for (size_t i = 1; i < g_export_engine.history.record_count; i++) {
            if (g_export_engine.history.records[i].timestamp <
                g_export_engine.history.oldest_timestamp) {
                g_export_engine.history.oldest_timestamp =
                    g_export_engine.history.records[i].timestamp;
            }
        }
    }

    /* Update is_full flag */
    g_export_engine.history.is_full =
        (g_export_engine.history.record_count == MAX_HISTORICAL_RECORDS);

    return cleaned_count;
}

/* Create default export configuration */
struct export_config export_create_default_config(enum export_format format)
{
    struct export_config config = {0};

    config.format = format;
    config.data_type = EXPORT_DATA_BASIC_STATS;
    config.include_header = true;
    config.include_timestamp = true;
    config.include_metadata = true;
    config.compress_output = false;
    config.delimiter = DEFAULT_CSV_DELIMITER;
    config.field_separator = DEFAULT_FIELD_SEPARATOR;
    config.max_records = 0; /* Unlimited */
    config.time_range_start = 0;
    config.time_range_end = 0;

    return config;
}

/* Validate export configuration */
bool export_validate_config(const struct export_config *config)
{
    if (!config) {
        return false;
    }

    if (config->format < EXPORT_FORMAT_JSON || config->format > EXPORT_FORMAT_CUSTOM) {
        return false;
    }

    if (config->data_type < EXPORT_DATA_BASIC_STATS || config->data_type > EXPORT_DATA_ALL) {
        return false;
    }

    /* Validate CSV delimiter - should not be a reserved character */
    if (config->format == EXPORT_FORMAT_CSV) {
        char delimiter = config->delimiter;
        if (delimiter == '\0' || delimiter == '\n' || delimiter == '\r' || delimiter == '"' ||
            delimiter == '\\') {
            return false;
        }
    }

    /* Validate time range if specified */
    if (config->time_range_start > 0 && config->time_range_end > 0) {
        if (config->time_range_start >= config->time_range_end) {
            return false;
        }
    }

    return true;
}

/* Get supported export formats as string */
const char *export_get_supported_formats(void)
{
    return "json,csv,prometheus,influxdb,custom";
}

/* Format timestamp for export */
const char *export_format_timestamp(uint64_t timestamp, char *buffer, size_t buffer_size)
{
    static char static_buffer[EXPORT_TIMESTAMP_BUFFER_SIZE];
    char *buf = buffer ? buffer : static_buffer;
    size_t buf_size = buffer ? buffer_size : sizeof(static_buffer);

    time_t time_val = (time_t)timestamp;
    struct tm *tm_info = gmtime(&time_val);

    strftime(buf, buf_size, "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return buf;
}

/* Escape string for CSV format */
const char *export_csv_escape_string(const char *input, char *output, size_t output_size)
{
    if (!input || !output || output_size < 3) {
        if (output && output_size > 0) {
            output[0] = '\0';
        }
        return output ? output : "";
    }

    /* Check if we need to wrap in quotes */
    if (strchr(input, ',') || strchr(input, '"') || strchr(input, '\n')) {
        size_t input_len = strlen(input);
        size_t pos = 0;

        /* Start with opening quote */
        if (pos < output_size - 1) {
            output[pos++] = '"';
        }

        /* Copy input, escaping quotes */
        for (size_t i = 0; i < input_len && pos < output_size - 2; i++) {
            if (input[i] == '"') {
                /* Escape quote by doubling it */
                if (pos < output_size - 3) {
                    output[pos++] = '"';
                    output[pos++] = '"';
                }
            } else {
                output[pos++] = input[i];
            }
        }

        /* Add closing quote */
        if (pos < output_size - 1) {
            output[pos++] = '"';
        }

        output[pos] = '\0';
    } else {
        /* No escaping needed, just copy */
        safe_strncpy(output, input, output_size);
    }

    return output;
}

/* Calculate export file size estimate */
size_t export_estimate_file_size(const struct export_config *export_config)
{
    if (!export_config) {
        return 0;
    }

    size_t base_size = EXPORT_BASE_SIZE_BYTES; /* Base overhead */

    switch (export_config->format) {
    case EXPORT_FORMAT_JSON:
        return base_size * 4; /* JSON is verbose */
    case EXPORT_FORMAT_CSV:
        return base_size * 2; /* CSV is compact */
    case EXPORT_FORMAT_PROMETHEUS:
    case EXPORT_FORMAT_INFLUXDB:
        return base_size * 3; /* Metrics format */
    default:
        return base_size;
    }
}

/* Helper function implementations */

static int write_json_basic_stats(FILE *file_ptr)
{
    struct collection_stats stats;

    if (data_collector_get_stats(&stats) != 0) {
        return -ENODATA;
    }

    fprintf(file_ptr, "  \"statistics\": {\n");
    fprintf(file_ptr, "    \"total_processes\": %lu,\n", stats.total_processes);
    fprintf(file_ptr, "    \"active_processes\": %lu,\n", stats.active_processes);
    fprintf(file_ptr, "    \"container_processes\": %lu,\n", stats.container_processes);
    fprintf(file_ptr, "    \"high_cpu_processes\": %lu,\n", stats.high_cpu_processes);
    fprintf(file_ptr, "    \"high_io_processes\": %lu,\n", stats.high_io_processes);
    fprintf(file_ptr, "    \"high_network_processes\": %lu,\n", stats.high_network_processes);
    fprintf(file_ptr, "    \"high_memory_processes\": %lu,\n", stats.high_memory_processes);
    fprintf(file_ptr, "    \"total_syscalls\": %lu,\n", stats.total_syscalls);
    fprintf(file_ptr, "    \"total_io_bytes\": %lu,\n", stats.total_io_bytes);
    fprintf(file_ptr, "    \"total_network_bytes\": %lu,\n", stats.total_network_bytes);
    fprintf(file_ptr, "    \"total_memory_bytes\": %lu,\n", stats.total_memory_bytes);
    fprintf(file_ptr, "    \"collections_performed\": %lu\n", stats.collections_performed);
    fprintf(file_ptr, "  }");

    return 0;
}

static int write_json_detailed_processes(FILE *file_ptr)
{
    struct process_data processes[MAX_TRACKED_PROCESSES];
    size_t process_count;

    if (data_collector_get_processes(processes, MAX_TRACKED_PROCESSES, &process_count) != 0) {
        return -ENODATA;
    }

    fprintf(file_ptr, "  \"processes\": [\n");

    for (size_t i = 0; i < process_count; i++) {
        const struct process_data *proc = &processes[i];

        if (!proc->active) {
            continue;
        }

        if (i > 0) {
            fprintf(file_ptr, ",\n");
        }

        fprintf(file_ptr, "    {\n");
        fprintf(file_ptr, "      \"pid\": %u,\n", proc->pid);
        fprintf(file_ptr, "      \"comm\": \"%s\",\n", proc->comm);
        fprintf(file_ptr, "      \"cpu_usage_percent\": %u,\n", proc->cpu_usage_percent);
        fprintf(file_ptr, "      \"cpu_time_ns\": %lu,\n", proc->cpu_time_ns);
        fprintf(file_ptr, "      \"syscall_count\": %lu,\n", proc->syscall_count);
        fprintf(file_ptr, "      \"io_read_bytes\": %lu,\n", proc->io_read_bytes);
        fprintf(file_ptr, "      \"io_write_bytes\": %lu,\n", proc->io_write_bytes);
        fprintf(file_ptr, "      \"io_read_ops\": %lu,\n", proc->io_read_ops);
        fprintf(file_ptr, "      \"io_write_ops\": %lu,\n", proc->io_write_ops);
        fprintf(file_ptr, "      \"memory_alloc_bytes\": %lu,\n", proc->memory_alloc_bytes);
        fprintf(file_ptr, "      \"memory_free_bytes\": %lu,\n", proc->memory_free_bytes);
        fprintf(file_ptr, "      \"memory_current_bytes\": %lu,\n", proc->memory_current_bytes);
        fprintf(file_ptr, "      \"memory_peak_bytes\": %lu,\n", proc->memory_peak_bytes);
        fprintf(file_ptr, "      \"memory_page_faults\": %lu,\n", proc->memory_page_faults);
        fprintf(file_ptr, "      \"network_rx_bytes\": %lu,\n", proc->network_rx_bytes);
        fprintf(file_ptr, "      \"network_tx_bytes\": %lu,\n", proc->network_tx_bytes);
        fprintf(file_ptr, "      \"network_rx_packets\": %lu,\n", proc->network_rx_packets);
        fprintf(file_ptr, "      \"network_tx_packets\": %lu,\n", proc->network_tx_packets);
        fprintf(file_ptr, "      \"network_tcp_connections\": %lu,\n",
                proc->network_tcp_connections);
        fprintf(file_ptr, "      \"network_udp_packets\": %lu,\n", proc->network_udp_packets);
        fprintf(file_ptr, "      \"is_container\": %s\n", proc->is_container ? "true" : "false");
        fprintf(file_ptr, "    }");
    }

    fprintf(file_ptr, "\n  ]");
    return 0;
}

static int write_csv_header(FILE *file_ptr, const struct export_config *config)
{
    fprintf(file_ptr,
            "timestamp%cpid%ccomm%ccpu_percent%csyscalls%cio_bytes%cio_ops%c"
            "memory_current%cmemory_peak%cmemory_alloc%cnetwork_rx%cnetwork_tx%c"
            "network_packets%cis_container\n",
            config->delimiter, config->delimiter, config->delimiter, config->delimiter,
            config->delimiter, config->delimiter, config->delimiter, config->delimiter,
            config->delimiter, config->delimiter, config->delimiter, config->delimiter,
            config->delimiter);
    return 0;
}

static int write_csv_process_data(FILE *file_ptr, const struct export_config *config)
{
    struct process_data processes[MAX_TRACKED_PROCESSES];
    size_t process_count;
    uint64_t timestamp = get_current_timestamp();

    if (data_collector_get_processes(processes, MAX_TRACKED_PROCESSES, &process_count) != 0) {
        return -ENODATA;
    }

    for (size_t i = 0; i < process_count; i++) {
        const struct process_data *proc = &processes[i];

        if (!proc->active) {
            continue;
        }

        fprintf(file_ptr, "%lu%c%u%c%s%c%u%c%lu%c%lu%c%lu%c%lu%c%lu%c%lu%c%lu%c%lu%c%lu%c%s\n",
                timestamp, config->delimiter, proc->pid, config->delimiter, proc->comm,
                config->delimiter, proc->cpu_usage_percent, config->delimiter, proc->syscall_count,
                config->delimiter, proc->io_read_bytes + proc->io_write_bytes, config->delimiter,
                proc->io_read_ops + proc->io_write_ops, config->delimiter,
                proc->memory_current_bytes, config->delimiter, proc->memory_peak_bytes,
                config->delimiter, proc->memory_alloc_bytes, config->delimiter,
                proc->network_rx_bytes, config->delimiter, proc->network_tx_bytes,
                config->delimiter, proc->network_rx_packets + proc->network_tx_packets,
                config->delimiter, proc->is_container ? "true" : "false");
    }

    return 0;
}

static int write_prometheus_metrics(FILE *file_ptr)
{
    struct collection_stats stats;
    uint64_t current_timestamp = get_current_timestamp();
    uint64_t timestamp;

    if (data_collector_get_stats(&stats) != 0) {
        return -ENODATA;
    }

    /* Safe timestamp multiplication with overflow protection */
    if (current_timestamp > UINT64_MAX / PROMETHEUS_TIMESTAMP_MULTIPLIER) {
        /* Use current timestamp as-is to avoid overflow */
        timestamp = current_timestamp;
    } else {
        timestamp = current_timestamp * PROMETHEUS_TIMESTAMP_MULTIPLIER;
    }

    /* Basic metrics */
    fprintf(file_ptr, "# HELP hpmon_active_processes Number of active processes\n");
    fprintf(file_ptr, "# TYPE hpmon_active_processes gauge\n");
    fprintf(file_ptr, "hpmon_active_processes %lu %lu\n", stats.active_processes, timestamp);

    fprintf(file_ptr, "# HELP hpmon_total_syscalls Total number of system calls\n");
    fprintf(file_ptr, "# TYPE hpmon_total_syscalls counter\n");
    fprintf(file_ptr, "hpmon_total_syscalls %lu %lu\n", stats.total_syscalls, timestamp);

    fprintf(file_ptr, "# HELP hpmon_total_io_bytes Total I/O bytes\n");
    fprintf(file_ptr, "# TYPE hpmon_total_io_bytes counter\n");
    fprintf(file_ptr, "hpmon_total_io_bytes %lu %lu\n", stats.total_io_bytes, timestamp);

    /* Network metrics */
    fprintf(file_ptr, "# HELP hpmon_total_network_bytes Total network bytes transferred\n");
    fprintf(file_ptr, "# TYPE hpmon_total_network_bytes counter\n");
    fprintf(file_ptr, "hpmon_total_network_bytes %lu %lu\n", stats.total_network_bytes, timestamp);

    fprintf(file_ptr, "# HELP hpmon_high_network_processes Processes with high network activity\n");
    fprintf(file_ptr, "# TYPE hpmon_high_network_processes gauge\n");
    fprintf(file_ptr, "hpmon_high_network_processes %lu %lu\n", stats.high_network_processes,
            timestamp);

    /* Memory metrics */
    fprintf(file_ptr, "# HELP hpmon_total_memory_bytes Total memory allocated in bytes\n");
    fprintf(file_ptr, "# TYPE hpmon_total_memory_bytes counter\n");
    fprintf(file_ptr, "hpmon_total_memory_bytes %lu %lu\n", stats.total_memory_bytes, timestamp);

    fprintf(file_ptr, "# HELP hpmon_high_memory_processes Processes with high memory usage\n");
    fprintf(file_ptr, "# TYPE hpmon_high_memory_processes gauge\n");
    fprintf(file_ptr, "hpmon_high_memory_processes %lu %lu\n", stats.high_memory_processes,
            timestamp);

    return 0;
}

static int write_influxdb_metrics(FILE *file_ptr, const char *measurement)
{
    struct collection_stats stats;
    uint64_t current_timestamp = get_current_timestamp();
    uint64_t timestamp;

    if (data_collector_get_stats(&stats) != 0) {
        return -ENODATA;
    }

    /* Safe timestamp multiplication with overflow protection */
    if (current_timestamp > UINT64_MAX / INFLUXDB_TIMESTAMP_MULTIPLIER) {
        /* Use current timestamp as-is to avoid overflow */
        timestamp = current_timestamp;
    } else {
        timestamp = current_timestamp * INFLUXDB_TIMESTAMP_MULTIPLIER;
    }

    /* Basic metrics */
    fprintf(file_ptr,
            "%s,host=localhost active_processes=%lu,total_syscalls=%lu,total_io_bytes=%lu,"
            "total_network_bytes=%lu,total_memory_bytes=%lu,high_network_processes=%lu,"
            "high_memory_processes=%lu %lu\n",
            measurement, stats.active_processes, stats.total_syscalls, stats.total_io_bytes,
            stats.total_network_bytes, stats.total_memory_bytes, stats.high_network_processes,
            stats.high_memory_processes, timestamp);

    return 0;
}

static uint64_t get_current_timestamp(void)
{
    return (uint64_t)time(NULL);
}

static int ensure_directory_exists(const char *filepath)
{
    char *dir_path = strdup(filepath);
    char *last_slash;
    int ret = 0;

    if (!dir_path) {
        return -ENOMEM;
    }

    last_slash = strrchr(dir_path, '/');

    if (last_slash) {
        *last_slash = '\0';
        if (mkdir(dir_path, DEFAULT_DIRECTORY_PERMISSIONS) != 0) {
            /* Directory might already exist, check if that's the case */
            if (errno != EEXIST) {
                ret = -errno;
            }
        }
    }

    free(dir_path);
    return ret;
}
