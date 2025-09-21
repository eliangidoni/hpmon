/* HPMon Export Engine Test Suite
 *
 * Comprehensive test suite for the export engine functionality
 */

#include "data_collector.h"
#include "export.h"
#include "hpmon.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test helper functions */
static void print_test_result(const char *test_name, bool passed);
static struct hpmon_config create_test_config(void);
static bool file_exists(const char *filename);
static void cleanup_test_files(void);

/* Test function declarations */
static bool test_export_engine_init(void);
static bool test_export_configurations(void);
static bool test_json_export(void);
static bool test_csv_export(void);
static bool test_prometheus_export(void);
static bool test_influxdb_export(void);
static bool test_historical_storage(void);
static bool test_export_statistics(void);
static bool test_retention_policy(void);
static bool test_utility_functions(void);
static bool test_export_integration(void);

/* Test file names */
#define TEST_JSON_FILE "/tmp/hpmon_test.json"
#define TEST_CSV_FILE "/tmp/hpmon_test.csv"
#define TEST_PROMETHEUS_FILE "/tmp/hpmon_test.prom"
#define TEST_INFLUXDB_FILE "/tmp/hpmon_test.influx"
#define TEST_HISTORICAL_FILE "/tmp/hpmon_historical.json"

int main(void)
{
    bool all_passed = true;

    printf("HPMon Export Engine Test Suite\n");
    printf("==============================\n\n");

    /* Initialize HPMon components needed for export testing */
    struct hpmon_config config = create_test_config();

    /* Initialize minimal components for testing */
    printf("Initializing minimal components for export testing...\n");

    /* Initialize data collector (needed for export testing) */
    if (data_collector_init(&config) != 0) {
        printf("Warning: Failed to initialize data collector - using mock data\n");
    }

    /* Initialize export engine directly */
    if (export_engine_init(&config) != 0) {
        printf("Error: Failed to initialize export engine\n");
        return 1;
    }

    /* Run tests */
    all_passed &= test_export_engine_init();
    all_passed &= test_export_configurations();
    all_passed &= test_json_export();
    all_passed &= test_csv_export();
    all_passed &= test_prometheus_export();
    all_passed &= test_influxdb_export();
    all_passed &= test_historical_storage();
    all_passed &= test_export_statistics();
    all_passed &= test_retention_policy();
    all_passed &= test_utility_functions();
    all_passed &= test_export_integration();

    /* Cleanup */
    cleanup_test_files();
    export_engine_cleanup();
    data_collector_cleanup();

    printf("\n");
    if (all_passed) {
        printf("✅ All export engine tests PASSED!\n");
        return 0;
    } else {
        printf("❌ Some export engine tests FAILED!\n");
        return 1;
    }
}

static bool test_export_engine_init(void)
{
    printf("Testing export engine initialization...\n");

    struct hpmon_config config = create_test_config();

    /* Test that export engine is already initialized */
    struct export_stats stats;
    int ret = export_engine_get_stats(&stats);
    bool test1 = (ret == 0); /* Should succeed if already initialized */
    print_test_result("  Export engine initialization", test1);

    /* Test double initialization (engine should already be initialized) */
    ret = export_engine_init(&config);
    bool test2 = (ret == -EALREADY);
    print_test_result("  Double initialization prevention", test2);

    /* Test invalid config */
    ret = export_engine_init(NULL);
    bool test3 = (ret == -EINVAL);
    print_test_result("  Invalid config handling", test3);

    return test1 && test2 && test3;
}
static bool test_export_configurations(void)
{
    printf("Testing export configurations...\n");

    /* Test default configuration creation */
    struct export_config json_config = export_create_default_config(EXPORT_FORMAT_JSON);
    bool test1 = (json_config.format == EXPORT_FORMAT_JSON && json_config.include_header == true);
    print_test_result("  Default JSON config creation", test1);

    struct export_config csv_config = export_create_default_config(EXPORT_FORMAT_CSV);
    bool test2 =
        (csv_config.format == EXPORT_FORMAT_CSV && csv_config.delimiter == DEFAULT_CSV_DELIMITER);
    print_test_result("  Default CSV config creation", test2);

    /* Test configuration validation */
    bool test3 = export_validate_config(&json_config);
    print_test_result("  Valid config validation", test3);

    json_config.format = 999; /* Invalid format */
    bool test4 = !export_validate_config(&json_config);
    print_test_result("  Invalid config rejection", test4);

    bool test5 = !export_validate_config(NULL);
    print_test_result("  NULL config rejection", test5);

    /* Test supported formats string */
    const char *formats = export_get_supported_formats();
    bool test6 = (strstr(formats, "json") != NULL && strstr(formats, "csv") != NULL);
    print_test_result("  Supported formats listing", test6);

    return test1 && test2 && test3 && test4 && test5 && test6;
}

static bool test_json_export(void)
{
    printf("Testing JSON export...\n");

    /* Test basic JSON export to stdout */
    int ret = export_json_stats(NULL, false);
    bool test1 = (ret == 0);
    print_test_result("  JSON export to stdout", test1);

    /* Test JSON export to file */
    ret = export_json_stats(TEST_JSON_FILE, true);
    bool test2 = (ret == 0 && file_exists(TEST_JSON_FILE));
    print_test_result("  JSON export to file", test2);

    /* Test detailed JSON export */
    ret = export_json_stats(TEST_JSON_FILE, true);
    bool test3 = (ret == 0);
    print_test_result("  Detailed JSON export", test3);

    /* Test JSON export with configuration */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_JSON);
    config.data_type = EXPORT_DATA_DETAILED_PROCESSES;
    ret = export_data(TEST_JSON_FILE, &config);
    bool test4 = (ret == 0);
    print_test_result("  JSON export with config", test4);

    return test1 && test2 && test3 && test4;
}

static bool test_csv_export(void)
{
    printf("Testing CSV export...\n");

    /* Test CSV export with header */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_CSV);
    config.include_header = true;
    config.data_type = EXPORT_DATA_DETAILED_PROCESSES;

    int ret = export_csv_stats(TEST_CSV_FILE, &config);
    bool test1 = (ret == 0 && file_exists(TEST_CSV_FILE));
    print_test_result("  CSV export with header", test1);

    /* Test CSV export without header */
    config.include_header = false;
    ret = export_csv_stats(TEST_CSV_FILE, &config);
    bool test2 = (ret == 0);
    print_test_result("  CSV export without header", test2);

    /* Test custom delimiter */
    config.delimiter = ';';
    ret = export_csv_stats(TEST_CSV_FILE, &config);
    bool test3 = (ret == 0);
    print_test_result("  CSV export with custom delimiter", test3);

    /* Test CSV export via generic export function */
    config.delimiter = ',';
    ret = export_data(TEST_CSV_FILE, &config);
    bool test4 = (ret == 0);
    print_test_result("  CSV export via generic function", test4);

    return test1 && test2 && test3 && test4;
}

static bool test_prometheus_export(void)
{
    printf("Testing Prometheus export...\n");

    /* Test Prometheus metrics export */
    int ret = export_prometheus_metrics(TEST_PROMETHEUS_FILE);
    bool test1 = (ret == 0 && file_exists(TEST_PROMETHEUS_FILE));
    print_test_result("  Prometheus metrics export", test1);

    /* Test Prometheus export to stdout */
    ret = export_prometheus_metrics(NULL);
    bool test2 = (ret == 0);
    print_test_result("  Prometheus export to stdout", test2);

    /* Test Prometheus export via generic function */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_PROMETHEUS);
    ret = export_data(TEST_PROMETHEUS_FILE, &config);
    bool test3 = (ret == 0);
    print_test_result("  Prometheus export via generic function", test3);

    return test1 && test2 && test3;
}

static bool test_influxdb_export(void)
{
    printf("Testing InfluxDB export...\n");

    /* Test InfluxDB line protocol export */
    int ret = export_influxdb_metrics(TEST_INFLUXDB_FILE, "hpmon_test");
    bool test1 = (ret == 0 && file_exists(TEST_INFLUXDB_FILE));
    print_test_result("  InfluxDB line protocol export", test1);

    /* Test InfluxDB export to stdout */
    ret = export_influxdb_metrics(NULL, "hpmon");
    bool test2 = (ret == 0);
    print_test_result("  InfluxDB export to stdout", test2);

    /* Test InfluxDB export via generic function */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_INFLUXDB);
    ret = export_data(TEST_INFLUXDB_FILE, &config);
    bool test3 = (ret == 0);
    print_test_result("  InfluxDB export via generic function", test3);

    /* Test invalid measurement name */
    ret = export_influxdb_metrics(TEST_INFLUXDB_FILE, NULL);
    bool test4 = (ret == -EINVAL);
    print_test_result("  Invalid measurement name handling", test4);

    return test1 && test2 && test3 && test4;
}

static bool test_historical_storage(void)
{
    printf("Testing historical data storage...\n");

    /* Test storing snapshots */
    int ret = store_historical_snapshot();
    bool test1 = (ret == 0);
    print_test_result("  Historical snapshot storage", test1);

    /* Store a few more snapshots */
    for (int i = 0; i < 5; i++) {
        store_historical_snapshot();
        usleep(1000); /* Small delay to ensure different timestamps */
    }

    /* Test historical data export */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_JSON);
    config.data_type = EXPORT_DATA_ALL;
    ret = export_historical_data(TEST_HISTORICAL_FILE, &config);
    bool test2 = (ret == 0 && file_exists(TEST_HISTORICAL_FILE));
    print_test_result("  Historical data export", test2);

    /* Test time range export */
    config.time_range_start = (uint64_t)time(NULL) - 3600; /* Last hour */
    config.time_range_end = (uint64_t)time(NULL);
    ret = export_historical_data(TEST_HISTORICAL_FILE, &config);
    bool test3 = (ret == 0);
    print_test_result("  Time range historical export", test3);

    /* Test max records limit */
    config.max_records = 2;
    config.time_range_start = 0;
    config.time_range_end = 0;
    ret = export_historical_data(TEST_HISTORICAL_FILE, &config);
    bool test4 = (ret == 0);
    print_test_result("  Limited records historical export", test4);

    return test1 && test2 && test3 && test4;
}

static bool test_export_statistics(void)
{
    printf("Testing export statistics...\n");

    /* Get initial statistics */
    struct export_stats stats;
    int ret = export_engine_get_stats(&stats);
    bool test1 = (ret == 0);
    print_test_result("  Export statistics retrieval", test1);

    uint64_t initial_exports = stats.exports_performed;

    /* Perform an export to update statistics */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_JSON);
    export_data(TEST_JSON_FILE, &config);

    /* Check updated statistics */
    ret = export_engine_get_stats(&stats);
    bool test2 = (ret == 0 && stats.exports_performed > initial_exports);
    print_test_result("  Export statistics update", test2);

    bool test3 = (stats.last_export_time > 0);
    print_test_result("  Last export time recording", test3);

    bool test4 = (strlen(stats.last_export_format) > 0);
    print_test_result("  Export format recording", test4);

    /* Test invalid statistics call */
    ret = export_engine_get_stats(NULL);
    bool test5 = (ret == -EINVAL);
    print_test_result("  Invalid statistics call handling", test5);

    return test1 && test2 && test3 && test4 && test5;
}

static bool test_retention_policy(void)
{
    printf("Testing retention policy...\n");

    /* Test setting retention policy */
    int ret = export_configure_retention(48); /* 48 hours */
    bool test1 = (ret == 0);
    print_test_result("  Retention policy configuration", test1);

    /* Test invalid retention values */
    ret = export_configure_retention(0);
    bool test2 = (ret == -EINVAL);
    print_test_result("  Invalid retention rejection (0)", test2);

    ret = export_configure_retention(10000); /* Too many hours */
    bool test3 = (ret == -EINVAL);
    print_test_result("  Invalid retention rejection (too large)", test3);

    /* Test cleanup function */
    ret = export_cleanup_historical_data();
    bool test4 = (ret >= 0); /* Should return number of cleaned records */
    print_test_result("  Historical data cleanup", test4);

    return test1 && test2 && test3 && test4;
}

static bool test_utility_functions(void)
{
    printf("Testing utility functions...\n");

    /* Test timestamp formatting */
    uint64_t test_timestamp = 1609459200; /* 2021-01-01 00:00:00 UTC */
    char buffer[64];
    const char *formatted = export_format_timestamp(test_timestamp, buffer, sizeof(buffer));
    bool test1 = (formatted != NULL && strstr(formatted, "2021-01-01") != NULL);
    print_test_result("  Timestamp formatting", test1);

    /* Test CSV string escaping */
    char escape_buffer[128];
    const char *escaped =
        export_csv_escape_string("test,with,commas", escape_buffer, sizeof(escape_buffer));
    bool test2 = (escaped != NULL && escaped[0] == '"');
    print_test_result("  CSV string escaping", test2);

    /* Test file size estimation */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_JSON);
    size_t estimated_size = export_estimate_file_size(&config);
    bool test3 = (estimated_size > 0);
    print_test_result("  File size estimation", test3);

    /* Test NULL parameter handling */
    formatted = export_format_timestamp(test_timestamp, NULL, 0);
    bool test4 = (formatted != NULL);
    print_test_result("  NULL buffer timestamp formatting", test4);

    estimated_size = export_estimate_file_size(NULL);
    bool test5 = (estimated_size == 0);
    print_test_result("  NULL config size estimation", test5);

    return test1 && test2 && test3 && test4 && test5;
}

static bool test_export_integration(void)
{
    printf("Testing export integration...\n");

    /* Test export with all data types */
    struct export_config config = export_create_default_config(EXPORT_FORMAT_JSON);

    config.data_type = EXPORT_DATA_ALL;
    int ret = export_data(TEST_JSON_FILE, &config);
    bool test1 = (ret == 0);
    print_test_result("  Export all data types", test1);

    /* Test export with metadata */
    config.include_metadata = true;
    config.include_timestamp = true;
    ret = export_data(TEST_JSON_FILE, &config);
    bool test2 = (ret == 0);
    print_test_result("  Export with metadata", test2);

    /* Test network metrics export */
    config.data_type = EXPORT_DATA_NETWORK_METRICS;
    ret = export_data(TEST_JSON_FILE, &config);
    bool test3 = (ret == 0);
    print_test_result("  Network metrics export", test3);

    /* Test memory metrics export */
    config.data_type = EXPORT_DATA_MEMORY_METRICS;
    ret = export_data(TEST_JSON_FILE, &config);
    bool test4 = (ret == 0);
    print_test_result("  Memory metrics export", test4);

    /* Test network metrics CSV export */
    config.format = EXPORT_FORMAT_CSV;
    config.data_type = EXPORT_DATA_NETWORK_METRICS;
    ret = export_data(TEST_CSV_FILE, &config);
    bool test5 = (ret == 0);
    print_test_result("  Network metrics CSV export", test5);

    /* Test memory metrics CSV export */
    config.data_type = EXPORT_DATA_MEMORY_METRICS;
    ret = export_data(TEST_CSV_FILE, &config);
    bool test6 = (ret == 0);
    print_test_result("  Memory metrics CSV export", test6);

    /* Test unsupported format handling */
    config.format = EXPORT_FORMAT_CUSTOM;
    ret = export_data(TEST_JSON_FILE, &config);
    bool test7 = (ret == -ENOTSUP);
    print_test_result("  Unsupported format handling", test7);

    /* Test invalid configuration */
    config.format = 999;
    ret = export_data(TEST_JSON_FILE, &config);
    bool test8 = (ret == -EINVAL);
    print_test_result("  Invalid configuration handling", test8);

    return test1 && test2 && test3 && test4 && test5 && test6 && test7 && test8;
}

/* Helper function implementations */

static void print_test_result(const char *test_name, bool passed)
{
    printf("%s: %s\n", test_name, passed ? "✅ PASS" : "❌ FAIL");
}

static struct hpmon_config create_test_config(void)
{
    struct hpmon_config config = {0};

    config.monitor_cpu = true;
    config.monitor_syscalls = true;
    config.monitor_io = true;
    config.monitor_memory = true;
    config.monitor_containers = false;
    config.poll_interval_ms = 100;
    config.max_processes = 100;

    return config;
}
static bool file_exists(const char *filename)
{
    return access(filename, F_OK) == 0;
}

static void cleanup_test_files(void)
{
    unlink(TEST_JSON_FILE);
    unlink(TEST_CSV_FILE);
    unlink(TEST_PROMETHEUS_FILE);
    unlink(TEST_INFLUXDB_FILE);
    unlink(TEST_HISTORICAL_FILE);
}
