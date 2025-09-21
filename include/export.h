/* HPMon Data Export Engine Header
 *
 * This header defines the interface for exporting collected data
 * in various formats for analysis and integration with monitoring systems.
 */

#ifndef EXPORT_H
#define EXPORT_H

#include "data_collector.h"
#include "hpmon.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Export format types */
enum export_format {
    EXPORT_FORMAT_JSON = 0,
    EXPORT_FORMAT_CSV,
    EXPORT_FORMAT_PROMETHEUS,
    EXPORT_FORMAT_INFLUXDB,
    EXPORT_FORMAT_CUSTOM
};

/* Export data types */
enum export_data_type {
    EXPORT_DATA_BASIC_STATS = 0,
    EXPORT_DATA_DETAILED_PROCESSES,
    EXPORT_DATA_NETWORK_METRICS,
    EXPORT_DATA_MEMORY_METRICS,
    EXPORT_DATA_ALL
};

/* Export configuration */
struct export_config {
    enum export_format format;
    enum export_data_type data_type;
    bool include_header;
    bool include_timestamp;
    bool include_metadata;
    bool compress_output;
    char delimiter;              /* For CSV format */
    const char *field_separator; /* For custom formats */
    size_t max_records;          /* 0 = unlimited */
    uint64_t time_range_start;   /* Unix timestamp */
    uint64_t time_range_end;     /* Unix timestamp */
};

/* Export buffer and string size constants */
#define EXPORT_FORMAT_STRING_SIZE 32       /* Size for format strings */
#define EXPORT_DESTINATION_STRING_SIZE 256 /* Size for destination paths */

/* Export statistics */
struct export_stats {
    uint64_t exports_performed;
    uint64_t total_records_exported;
    uint64_t total_bytes_exported;
    uint64_t last_export_time;
    uint64_t last_export_duration_ms;
    uint32_t last_export_record_count;
    char last_export_format[EXPORT_FORMAT_STRING_SIZE];
    char last_export_destination[EXPORT_DESTINATION_STRING_SIZE];
};

/* Historical data record */
struct historical_record {
    uint64_t timestamp;
    struct collection_stats stats;
    size_t process_count;
    struct process_data processes[MAX_TRACKED_PROCESSES];
};

/* Maximum number of historical records */
#define MAX_HISTORICAL_RECORDS 1000

/* Historical data storage */
struct historical_storage {
    struct historical_record records[MAX_HISTORICAL_RECORDS];
    size_t record_count;
    size_t write_index;
    bool is_full;
    uint64_t oldest_timestamp;
    uint64_t newest_timestamp;
    uint32_t retention_hours;
    bool initialized;
};

/* Default configurations */
#define DEFAULT_CSV_DELIMITER ','
#define DEFAULT_FIELD_SEPARATOR "|"
#define DEFAULT_RETENTION_HOURS 24
#define MAX_EXPORT_BUFFER_SIZE (1024 * 1024) /* 1MB */

/* Function declarations */

/**
 * Initialize the export engine
 * @param config: HPMon configuration
 * @returns  0 on success, negative on error
 */
int export_engine_init(const struct hpmon_config *config);

/**
 * Cleanup the export engine
 */
void export_engine_cleanup(void);

/**
 * Export data to a file or stream
 * @param filename: Output file path (NULL for stdout)
 * @param export_config: Export configuration
 * @returns  0 on success, negative on error
 */
int export_data(const char *filename, const struct export_config *export_config);

/**
 * Export current statistics in JSON format
 * @param filename: Output file path (NULL for stdout)
 * @param include_detailed: Include detailed process information
 * @returns  0 on success, negative on error
 */
int export_json_stats(const char *filename, bool include_detailed);

/**
 * Export current statistics in CSV format
 * @param filename: Output file path (NULL for stdout)
 * @param export_config: Export configuration
 * @returns  0 on success, negative on error
 */
int export_csv_stats(const char *filename, const struct export_config *export_config);

/**
 * Export in Prometheus metrics format
 * @param filename: Output file path (NULL for stdout)
 * @returns  0 on success, negative on error
 */
int export_prometheus_metrics(const char *filename);

/**
 * Export in InfluxDB line protocol format
 * @param filename: Output file path (NULL for stdout)
 * @param measurement_name: InfluxDB measurement name
 * @returns  0 on success, negative on error
 */
int export_influxdb_metrics(const char *filename, const char *measurement_name);

/**
 * Export network metrics data
 * @param filename: Output file path (NULL for stdout)
 * @param export_config: Export configuration
 * @returns  0 on success, negative on error
 */
int export_network_data(const char *filename, const struct export_config *export_config);

/**
 * Export memory metrics data
 * @param filename: Output file path (NULL for stdout)
 * @param export_config: Export configuration
 * @returns  0 on success, negative on error
 */
int export_memory_data(const char *filename, const struct export_config *export_config);

/**
 * Store current data snapshot for historical tracking
 * @returns  0 on success, negative on error
 */
int store_historical_snapshot(void);

/**
 * Export historical data
 * @param filename: Output file path (NULL for stdout)
 * @param export_config: Export configuration with time range
 * @returns  0 on success, negative on error
 */
int export_historical_data(const char *filename, const struct export_config *export_config);

/**
 * Get export engine statistics
 * @param stats: Output statistics structure
 * @returns  0 on success, negative on error
 */
int export_engine_get_stats(struct export_stats *stats);

/**
 * Configure historical data retention
 * @param retention_hours: Hours to retain historical data
 * @returns  0 on success, negative on error
 */
int export_configure_retention(uint32_t retention_hours);

/**
 * Cleanup old historical data based on retention policy
 * @returns  Number of records cleaned up
 */
int export_cleanup_historical_data(void);

/**
 * Create default export configuration
 * @param format: Export format to use
 * @returns Default configuration structure
 */
struct export_config export_create_default_config(enum export_format format);

/**
 * Validate export configuration
 * @param config: Configuration to validate
 * @returns  true if valid, false otherwise
 */
bool export_validate_config(const struct export_config *config);

/**
 * Get supported export formats as string
 * @returns  Comma-separated list of supported formats
 */
const char *export_get_supported_formats(void);

/* Utility functions */

/**
 * Format timestamp for export
 * @param timestamp: Unix timestamp
 * @param buffer: Output buffer
 * @param buffer_size: Size of output buffer
 * @returns  Formatted timestamp string
 */
const char *export_format_timestamp(uint64_t timestamp, char *buffer, size_t buffer_size);

/**
 * Escape string for CSV format
 * @param input: Input string
 * @param output: Output buffer
 * @param output_size: Size of output buffer
 * @returns  Escaped string
 */
const char *export_csv_escape_string(const char *input, char *output, size_t output_size);

/**
 * Calculate export file size estimate
 * @param export_config: Export configuration
 * @returns  Estimated file size in bytes
 */
size_t export_estimate_file_size(const struct export_config *export_config);

#endif /* EXPORT_H */
