// SPDX-License-Identifier: MIT
/* HPMon Container Tracker
 *
 * This module implements container detection and tracking by analyzing
 * cgroup information to map processes to containers. It supports
 * Docker, Podman, containerd container runtimes, and Kubernetes pods.
 */

/* Container tracker constants */
#define SECURE_LOG_FILE_PERMISSIONS 0640
#define TIMESTAMP_BUFFER_SIZE 64

#include "container_tracker.h"
#include "safe_string.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* Global container tracking state */
static struct container_tracker g_tracker = {0};
static bool g_tracker_initialized = false;

/* Secure logging infrastructure */
#define SECURE_LOG_FACILITY LOG_LOCAL0 /* Dedicated facility for security events */
#define SECURE_LOG_FILE "/var/log/hpmon-security.log"
#define MAX_LOG_MESSAGE_LEN 256

/* Secure logging state */
static int g_secure_log_fd = -1;
static bool g_syslog_opened = false;

/* Initialize secure logging subsystem */
static int init_secure_logging(void)
{
    /* Open syslog with appropriate options */
    if (!g_syslog_opened) {
        openlog("hpmon-container", LOG_PID | LOG_CONS, SECURE_LOG_FACILITY);
        g_syslog_opened = true;
    }

    /* Attempt to open dedicated log file (optional) */
    g_secure_log_fd =
        open(SECURE_LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, SECURE_LOG_FILE_PERMISSIONS);
    if (g_secure_log_fd < 0) {
        /* Log to syslog that dedicated log file couldn't be opened */
        syslog(LOG_WARNING, "Could not open secure log file %s: %s", SECURE_LOG_FILE,
               strerror(errno));
    }

    return 0;
}

/* Cleanup secure logging subsystem */
static void cleanup_secure_logging(void)
{
    if (g_secure_log_fd >= 0) {
        close(g_secure_log_fd);
        g_secure_log_fd = -1;
    }

    if (g_syslog_opened) {
        closelog();
        g_syslog_opened = false;
    }
}

/* Function declarations */
static int extract_container_id(const char *cgroup_path, char *container_id, size_t max_len);
static int read_process_cgroup(pid_t pid, char *cgroup_path, size_t max_len);
static int parse_k8s_metadata(const char *cgroup_path, struct container_info *info);
static int read_k8s_pod_info(const char *pod_uid, struct container_info *info);

/* Hash table functions for efficient PID lookups */
static unsigned int hash_pid(pid_t pid);
static void hash_table_init(void);
static void hash_table_clear(void);
static int hash_table_lookup(pid_t pid);
static void hash_table_insert(pid_t pid, int container_index);
static void hash_table_remove(pid_t pid);

/* Sanitized error reporting to prevent information disclosure */
static void log_sanitized_error(const char *operation, int error_code)
{
    char timestamp[TIMESTAMP_BUFFER_SIZE];
    char log_message[MAX_LOG_MESSAGE_LEN];
    time_t now;
    struct tm *tm_info;

    /* Get current timestamp */
    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Create sanitized log message - no sensitive information */
    snprintf(log_message, sizeof(log_message),
             "[%s] Container tracker operation failed: op=%s, error_class=%d", timestamp,
             operation ? operation : "unknown", error_code < 0 ? -error_code : error_code);

    /* Log to syslog with appropriate priority */
    int syslog_priority;
    switch (error_code) {
    case CONTAINER_ERROR_PERMISSION:
        syslog_priority = LOG_WARNING;
        break;
    case CONTAINER_ERROR_CORRUPTION:
        syslog_priority = LOG_ERR;
        break;
    case CONTAINER_ERROR_MEMORY:
        syslog_priority = LOG_CRIT;
        break;
    default:
        syslog_priority = LOG_INFO;
        break;
    }

    /* Ensure syslog is initialized */
    if (!g_syslog_opened) {
        init_secure_logging();
    }

    /* Log to syslog */
    syslog(syslog_priority, "%s", log_message);

    /* Also write to secure log file if available */
    if (g_secure_log_fd >= 0) {
        char full_message[MAX_LOG_MESSAGE_LEN + 2];
        snprintf(full_message, sizeof(full_message), "%s\n", log_message);

        ssize_t bytes_written = write(g_secure_log_fd, full_message, strlen(full_message));
        if (bytes_written < 0) {
            /* If write fails, log to syslog but don't recurse */
            syslog(LOG_WARNING, "Failed to write to secure log file: %s", strerror(errno));
        }
    }
}

/* Container runtime patterns for cgroup parsing */
static const struct runtime_pattern {
    const char *name;
    const char *pattern;
    size_t pattern_len;
    bool is_k8s;
} g_runtime_patterns[] = {
    {"docker", "/docker/", 8, false},
    {"containerd", "/containerd/", 12, false},
    {"podman", "/machine.slice/libpod-", 22, false},
    {"systemd", "/system.slice/docker-", 21, false},
    {"crio", "/crio-", 6, false},
    {"kubepods", "/kubepods/", 10, true},
    {"kubelet", "/kubelet/", 9, true},
    {NULL, NULL, 0, false} /* sentinel */
};

/* Document pod UID display length rationale and make it configurable */
/* POD_UID_DISPLAY_LEN: Display first 8 characters of pod UID for human readability.
 * Full pod UIDs are 36 characters (standard UUID format), but showing first 8 chars
 * provides sufficient uniqueness for display purposes while keeping output concise.
 * This matches kubectl's default behavior for truncating long identifiers. */
#define POD_UID_DISPLAY_LEN 8
#define FULL_POD_UID_LEN 36 /* Standard UUID length */

/* Constants for validation and limits */
#define MAX_CONTAINER_ID_CHARS 256  /* Reasonable upper limit for container IDs */
#define MAX_PID_VALUE 4194304       /* Maximum PID value on Linux */
#define HASH_MULTIPLIER 2654435761U /* Prime number for hash function */

/* Hash table implementation for efficient PID lookups */
static unsigned int hash_pid(pid_t pid)
{
    /* Simple hash function for PID values */
    return ((unsigned int)pid * HASH_MULTIPLIER) % CONTAINER_HASH_SIZE;
}

static void hash_table_init(void)
{
    /* Clear hash table */
    memset((void *)g_tracker.hash_table, 0, sizeof(g_tracker.hash_table));
    g_tracker.hash_pool_used = 0;
}

static void hash_table_clear(void)
{
    hash_table_init();
}

static int hash_table_lookup(pid_t pid)
{
    unsigned int hash = hash_pid(pid);
    struct container_hash_entry *entry = g_tracker.hash_table[hash];

    while (entry) {
        if (entry->pid == pid) {
            return entry->container_index;
        }
        entry = entry->next;
    }
    return -1; /* Not found */
}

static void hash_table_insert(pid_t pid, int container_index)
{
    if (g_tracker.hash_pool_used >= MAX_CONTAINERS) {
        return; /* No more hash entries available */
    }

    unsigned int hash = hash_pid(pid);
    struct container_hash_entry *entry = &g_tracker.hash_pool[g_tracker.hash_pool_used++];

    entry->pid = pid;
    entry->container_index = container_index;
    entry->next = g_tracker.hash_table[hash];
    g_tracker.hash_table[hash] = entry;
}

static void hash_table_remove(pid_t pid)
{
    unsigned int hash = hash_pid(pid);
    struct container_hash_entry **entry_ptr = &g_tracker.hash_table[hash];

    while (*entry_ptr) {
        if ((*entry_ptr)->pid == pid) {
            *entry_ptr = (*entry_ptr)->next;
            return;
        }
        entry_ptr = &(*entry_ptr)->next;
    }
}

/* Cache string operations to avoid repeated calculations in hot paths */
struct pattern_cache {
    char cached_path[MAX_CGROUP_PATH_LEN]; /* Store copy of path instead of pointer */
    const struct runtime_pattern *matched_pattern;
    char cached_id[MAX_CONTAINER_ID_LEN];
    bool valid;
};
static struct pattern_cache g_pattern_cache = {0};

/* Helper function to extract container ID from cgroup path */
static int extract_container_id(const char *cgroup_path, char *container_id, size_t max_len)
{
    if (!cgroup_path || !container_id || max_len == 0) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Initialize output buffer */
    container_id[0] = '\0';

    /* Check cache first to avoid repeated string operations */
    if (g_pattern_cache.valid && strcmp(g_pattern_cache.cached_path, cgroup_path) == 0) {
        if (strlen(g_pattern_cache.cached_id) < max_len) {
            strcpy(container_id, g_pattern_cache.cached_id);
            return CONTAINER_SUCCESS;
        }
        return CONTAINER_ERROR_TRUNCATION;
    }

    /* Cache the current path for future lookups */
    safe_strncpy(g_pattern_cache.cached_path, cgroup_path, sizeof(g_pattern_cache.cached_path));
    g_pattern_cache.valid = false;

    /* Pre-calculate string length once */
    size_t cgroup_path_len = strlen(cgroup_path);

    /* Try each runtime pattern */
    for (const struct runtime_pattern *pattern = g_runtime_patterns; pattern->name; pattern++) {
        /* Use faster string search by avoiding repeated strstr calls */
        const char *match = NULL;
        for (const char *pos = cgroup_path;
             pos <= cgroup_path + cgroup_path_len - pattern->pattern_len; pos++) {
            if (strncmp(pos, pattern->pattern, pattern->pattern_len) == 0) {
                match = pos;
                break;
            }
        }

        if (!match) {
            continue;
        }

        /* Move past the pattern */
        const char *id_start = match + pattern->pattern_len;

        /* Find the end of the container ID (usually a '/' or end of string) */
        const char *id_end = strchr(id_start, '/');
        if (!id_end) {
            id_end = id_start + strlen(id_start);
        }

        /* Calculate ID length and validate */
        size_t id_len = id_end - id_start;
        if (id_len == 0 || id_len >= max_len) {
            continue;
        }

        /* Additional bounds checking to prevent manipulation */
        if (id_len > MAX_CONTAINER_ID_CHARS) { /* Reasonable upper limit for container IDs */
            continue;
        }

        /* Validate characters in the ID to prevent injection */
        for (size_t i = 0; i < id_len; i++) {
            char current_char = id_start[i];
            if (!((current_char >= '0' && current_char <= '9') ||
                  (current_char >= 'a' && current_char <= 'f') ||
                  (current_char >= 'A' && current_char <= 'F') || current_char == '-' ||
                  current_char == '_')) {
                goto next_pattern; /* Invalid character, try next pattern */
            }
        }

        /* Extract the container ID */
        strncpy(container_id, id_start, id_len);
        container_id[id_len] = '\0';

        /* Validate that we have a reasonable container ID (at least 12 characters for Docker) */
        if (strlen(container_id) >= MIN_CONTAINER_ID_LEN) {
            /* Cache successful result */
            if (id_len < sizeof(g_pattern_cache.cached_id)) {
                strcpy(g_pattern_cache.cached_id, container_id);
                g_pattern_cache.matched_pattern = pattern;
                g_pattern_cache.valid = true;
            }
            return CONTAINER_SUCCESS;
        }

    next_pattern:; /* Label for goto when invalid characters are found */
    }

    return CONTAINER_ERROR_NOT_FOUND; /* No container ID found */
}

/* Read and parse cgroup information for a process */
static int read_process_cgroup(pid_t pid, char *cgroup_path, size_t max_len)
{
    char proc_path[MAX_PROC_PATH_LEN];
    FILE *proc_file;
    char line[MAX_LINE_LEN];
    int result = CONTAINER_ERROR_NOT_FOUND;

    if (!cgroup_path || max_len == 0) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Validate PID to prevent path injection vulnerability */
    if (pid <= 0 || pid > MAX_PID_VALUE) { /* Max PID on Linux */
        return CONTAINER_ERROR_INVALID;
    }

    /* Initialize output buffer */
    cgroup_path[0] = '\0';

    /* Construct path to /proc/PID/cgroup */
    if (snprintf(proc_path, sizeof(proc_path), "/proc/%d/cgroup", pid) >= (int)sizeof(proc_path)) {
        return CONTAINER_ERROR_TRUNCATION;
    }

    proc_file = fopen(proc_path, "r");
    if (!proc_file) {
        /* Use sanitized error reporting */
        log_sanitized_error("cgroup_read", errno);
        return CONTAINER_ERROR_IO;
    }

    /* Read cgroup file line by line */
    while (fgets(line, sizeof(line), proc_file)) {
        /* Remove trailing newline */
        char *newline = strchr(line, '\n');
        if (newline) {
            *newline = '\0';
        }

        /* cgroup format: hierarchy-ID:controller-list:cgroup-path
         * We're interested in the cgroup-path part */
        char *first_colon = strchr(line, ':');
        if (!first_colon) {
            continue;
        }

        char *second_colon = strchr(first_colon + 1, ':');
        if (!second_colon) {
            continue;
        }

        /* Extract the cgroup path */
        const char *path = second_colon + 1;

        /* Validate null termination before string operations */
        size_t path_len = strnlen(path, max_len - 1);

        /* Copy the longest/most specific path we find */
        if (path_len > strlen(cgroup_path) && path_len < max_len - 1) {
            safe_strncpy(cgroup_path, path, max_len);
            result = CONTAINER_SUCCESS;
        }
    }

    /* Ensure file is always closed, even on success */
    fclose(proc_file);
    return result;
}

/* Parse Kubernetes metadata from cgroup path */
static int parse_k8s_metadata(const char *cgroup_path, struct container_info *info)
{
    if (!cgroup_path || !info) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Look for kubepods pattern: /kubepods/burstable/pod<uid>/<container_id> */
    /* or /kubepods/besteffort/pod<uid>/<container_id> */
    /* or /kubepods/guaranteed/pod<uid>/<container_id> */

    const char *kubepods = strstr(cgroup_path, "/kubepods/");
    if (!kubepods) {
        return CONTAINER_ERROR_NOT_FOUND;
    }

    /* Find pod UID */
    const char *pod_start = strstr(kubepods, "/pod");
    if (!pod_start) {
        return CONTAINER_ERROR_NOT_FOUND;
    }
    pod_start += 4; /* skip "/pod" */

    const char *pod_end = strchr(pod_start, '/');
    if (!pod_end) {
        return CONTAINER_ERROR_NOT_FOUND;
    }

    /* Extract pod UID */
    size_t pod_uid_len = pod_end - pod_start;
    if (pod_uid_len == 0 || pod_uid_len >= MAX_CONTAINER_ID_LEN) {
        return CONTAINER_ERROR_INVALID;
    }

    char pod_uid_str[MAX_CONTAINER_ID_LEN];
    strncpy(pod_uid_str, pod_start, pod_uid_len);
    pod_uid_str[pod_uid_len] = '\0';

    /* Mark as Kubernetes pod */
    info->is_k8s_pod = true;

    /* Try to read pod metadata from /proc/<pid>/environ or /var/lib/kubelet/pods */
    return read_k8s_pod_info(pod_uid_str, info);
}

/* Read Kubernetes pod information from environment or kubelet directory */
static int read_k8s_pod_info(const char *pod_uid, struct container_info *info)
{
    char pod_dir[MAX_LINE_LEN];
    char metadata_file[MAX_LINE_LEN];
    FILE *file;
    char line[MAX_LINE_LEN];

    if (!pod_uid || !info) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Validate PID before using it in path construction */
    if (info->pid <= 0 || info->pid > MAX_PID_VALUE) { /* Max PID on Linux */
        return CONTAINER_ERROR_INVALID;
    }

    /* Try to read from kubelet pod directory */
    if (snprintf(pod_dir, sizeof(pod_dir), "/var/lib/kubelet/pods/%s", pod_uid) >=
        (int)sizeof(pod_dir)) {
        return CONTAINER_ERROR_TRUNCATION; /* Path too long */
    }
    if (snprintf(metadata_file, sizeof(metadata_file), "%s/etc-hosts", pod_dir) >=
        (int)sizeof(metadata_file)) {
        return CONTAINER_ERROR_TRUNCATION; /* Path too long */
    }

    /* Check if kubelet directory exists (running on Kubernetes node) */
    struct stat stat_info;
    if (stat(pod_dir, &stat_info) == 0 && S_ISDIR(stat_info.st_mode)) {
        /* Try to extract namespace and pod name from annotations */
        if (snprintf(metadata_file, sizeof(metadata_file), "%s/annotations", pod_dir) >=
            (int)sizeof(metadata_file)) {
            return CONTAINER_ERROR_TRUNCATION; /* Path too long */
        }
        file = fopen(metadata_file, "r");
        if (file) {
            while (fgets(line, sizeof(line), file)) {
                /* Validate line length before processing */
                size_t line_len = strnlen(line, sizeof(line));
                if (line_len >= sizeof(line) - 1) {
                    /* Line too long, might be corrupted */
                    continue;
                }

                /* Look for namespace annotation */
                if (strstr(line, "io.kubernetes.pod.namespace=")) {
                    char *ns_start = strchr(line, '=');
                    if (ns_start) {
                        ns_start++;
                        char *ns_end = strchr(ns_start, '\n');
                        if (ns_end) {
                            *ns_end = '\0';
                        }
                        /* Validate string before copying */
                        if (strnlen(ns_start, sizeof(info->namespace_name)) <
                            sizeof(info->namespace_name)) {
                            safe_strncpy(info->namespace_name, ns_start,
                                         sizeof(info->namespace_name));
                        }
                    }
                }
                /* Look for pod name annotation */
                else if (strstr(line, "io.kubernetes.pod.name=")) {
                    char *name_start = strchr(line, '=');
                    if (name_start) {
                        name_start++;
                        char *name_end = strchr(name_start, '\n');
                        if (name_end) {
                            *name_end = '\0';
                        }
                        /* Validate string before copying */
                        if (strnlen(name_start, sizeof(info->pod_name)) < sizeof(info->pod_name)) {
                            safe_strncpy(info->pod_name, name_start, sizeof(info->pod_name));
                        }
                    }
                }
            }
            fclose(file);
            return CONTAINER_SUCCESS;
        }
        /* Use sanitized error reporting */
        log_sanitized_error("k8s_metadata_read", errno);
    }

    /* Fallback: try to read from process environment */
    char env_file[MAX_PROC_PATH_LEN];
    if (snprintf(env_file, sizeof(env_file), "/proc/%d/environ", info->pid) >=
        (int)sizeof(env_file)) {
        return CONTAINER_ERROR_TRUNCATION; /* Path too long */
    }
    file = fopen(env_file, "r");
    if (file) {
        char env_data[MAX_LINE_LEN * 4];
        size_t bytes_read = fread(env_data, 1, sizeof(env_data) - 1, file);
        /* Always close file in all code paths */
        fclose(file);

        /* Validate that we actually read some data and null-terminate */
        if (bytes_read == 0) {
            return CONTAINER_ERROR_IO;
        }
        env_data[bytes_read] = '\0';

        /* Parse environment variables (null-separated) */
        char *env_var = env_data;
        char *env_end = env_data + bytes_read;
        while (env_var < env_end && *env_var != '\0') {
            /* Prevent infinite loop if string is not null-terminated */
            size_t var_len = strnlen(env_var, env_end - env_var);
            if (var_len == 0 || env_var + var_len >= env_end) {
                break;
            }

            if (strstr(env_var, "KUBERNETES_NAMESPACE=") == env_var) {
                char *namespace_ptr = env_var + strlen("KUBERNETES_NAMESPACE=");
                /* Validate string before copying */
                if (strnlen(namespace_ptr, sizeof(info->namespace_name)) <
                    sizeof(info->namespace_name)) {
                    safe_strncpy(info->namespace_name, namespace_ptr, sizeof(info->namespace_name));
                }
            } else if (strstr(env_var, "KUBERNETES_POD_NAME=") == env_var) {
                char *name = env_var + strlen("KUBERNETES_POD_NAME=");
                /* Validate string before copying */
                if (strnlen(name, sizeof(info->pod_name)) < sizeof(info->pod_name)) {
                    safe_strncpy(info->pod_name, name, sizeof(info->pod_name));
                }
            }
            env_var += var_len + 1;
        }
    } else {
        /* Use sanitized error reporting for environment file access */
        log_sanitized_error("proc_environ_read", errno);
    }

    /* If we couldn't get the real names, use the UID */
    if (info->pod_name[0] == '\0') {
        if (snprintf(info->pod_name, sizeof(info->pod_name), "pod-%.*s", POD_UID_DISPLAY_LEN,
                     pod_uid) >= (int)sizeof(info->pod_name)) {
            /* Fallback to a simple name if truncation occurred */
            safe_strncpy(info->pod_name, "pod-unknown", sizeof(info->pod_name));
        }
    }
    if (info->namespace_name[0] == '\0') {
        safe_strncpy(info->namespace_name, "default", sizeof(info->namespace_name));
    }

    return CONTAINER_SUCCESS;
}

/* Initialize container tracker */
int container_tracker_init(void)
{
    if (g_tracker_initialized) {
        return CONTAINER_SUCCESS;
    }

    /* Initialize secure logging first */
    int log_ret = init_secure_logging();
    if (log_ret != 0) {
        /* Continue without secure logging, but note the failure */
        fprintf(stderr, "Warning: Secure logging initialization failed\n");
    }

    /* Initialize container cache */
    memset(&g_tracker, 0, sizeof(g_tracker));
    g_tracker.container_count = 0;
    g_tracker.metrics_count = 0;

    /* Initialize hash table */
    hash_table_init();

    g_tracker_initialized = true;
    return CONTAINER_SUCCESS;
}

/* Cleanup container tracker */
void container_tracker_cleanup(void)
{
    if (!g_tracker_initialized) {
        return;
    }

    /* Clear container cache and hash table */
    memset(&g_tracker, 0, sizeof(g_tracker));
    hash_table_clear();

    /* Cleanup secure logging */
    cleanup_secure_logging();

    g_tracker_initialized = false;
}

/* Get container information for a process */
int container_tracker_get_info(pid_t pid, struct container_info *info)
{
    char cgroup_path[MAX_CGROUP_PATH_LEN];
    char container_id[MAX_CONTAINER_ID_LEN];
    struct container_entry *entry;
    int idx;
    bool found_in_cache = false;

    if (!info || pid <= 0) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Initialize output structure */
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    info->is_container = false;
    info->is_k8s_pod = false;

    if (!g_tracker_initialized) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Use hash table for O(1) lookup instead of O(n) linear search */
    idx = hash_table_lookup(pid);
    if (idx >= 0 && idx < g_tracker.container_count) {
        entry = &g_tracker.containers[idx];
        /* Found cached entry */
        info->is_container = entry->is_container;
        if (entry->is_container) {
            /* Validate strings before copying */
            if (strnlen(entry->container_id, sizeof(entry->container_id)) <
                sizeof(entry->container_id)) {
                safe_strncpy(info->container_id, entry->container_id, sizeof(info->container_id));
            }
            if (strnlen(entry->runtime, sizeof(entry->runtime)) < sizeof(entry->runtime)) {
                safe_strncpy(info->runtime, entry->runtime, sizeof(info->runtime));
            }

            if (entry->is_k8s_pod) {
                info->is_k8s_pod = entry->is_k8s_pod;
                if (strnlen(entry->pod_name, sizeof(entry->pod_name)) < sizeof(entry->pod_name)) {
                    safe_strncpy(info->pod_name, entry->pod_name, sizeof(info->pod_name));
                }
                if (strnlen(entry->namespace_name, sizeof(entry->namespace_name)) <
                    sizeof(entry->namespace_name)) {
                    safe_strncpy(info->namespace_name, entry->namespace_name,
                                 sizeof(info->namespace_name));
                }
                if (strnlen(entry->k8s_labels, sizeof(entry->k8s_labels)) <
                    sizeof(entry->k8s_labels)) {
                    safe_strncpy(info->k8s_labels, entry->k8s_labels, sizeof(info->k8s_labels));
                }
            }
        }
        found_in_cache = true;
    }

    if (found_in_cache) {
        return CONTAINER_SUCCESS;
    }

    /* Read process cgroup information */
    int cgroup_result = read_process_cgroup(pid, cgroup_path, sizeof(cgroup_path));
    if (cgroup_result != CONTAINER_SUCCESS) {
        /* Process not found or no cgroup info - not a container */
        goto cache_result;
    }

    /* Try to extract container ID */
    if (extract_container_id(cgroup_path, container_id, sizeof(container_id)) ==
        CONTAINER_SUCCESS) {
        /* Successfully extracted container ID */
        info->is_container = true;
        safe_strncpy(info->container_id, container_id, sizeof(info->container_id));

        /* Determine runtime based on cgroup path */
        for (const struct runtime_pattern *pattern = g_runtime_patterns; pattern->name; pattern++) {
            if (strstr(cgroup_path, pattern->pattern)) {
                safe_strncpy(info->runtime, pattern->name, sizeof(info->runtime));

                /* If this is a Kubernetes pattern, parse K8s metadata */
                if (pattern->is_k8s) {
                    parse_k8s_metadata(cgroup_path, info);
                }
                break;
            }
        }

        /* Default runtime if not detected */
        if (info->runtime[0] == '\0') {
            safe_strncpy(info->runtime, "unknown", sizeof(info->runtime));
        }
    }

cache_result:
    /* Cache update without locking */
    /* Check if we have space and still initialized */
    if (g_tracker_initialized && g_tracker.container_count < MAX_CONTAINERS) {
        entry = &g_tracker.containers[g_tracker.container_count];

        /* Initialize all fields to prevent uninitialized memory */
        memset(entry, 0, sizeof(*entry));

        entry->pid = pid;
        entry->is_container = info->is_container;

        if (info->is_container) {
            /* Validate source strings before copying */
            if (strnlen(info->container_id, sizeof(info->container_id)) <
                sizeof(info->container_id)) {
                safe_strncpy(entry->container_id, info->container_id, sizeof(entry->container_id));
            }
            if (strnlen(info->runtime, sizeof(info->runtime)) < sizeof(info->runtime)) {
                safe_strncpy(entry->runtime, info->runtime, sizeof(entry->runtime));
            }

            if (info->is_k8s_pod) {
                entry->is_k8s_pod = info->is_k8s_pod;
                if (strnlen(info->pod_name, sizeof(info->pod_name)) < sizeof(info->pod_name)) {
                    safe_strncpy(entry->pod_name, info->pod_name, sizeof(entry->pod_name));
                }
                if (strnlen(info->namespace_name, sizeof(info->namespace_name)) <
                    sizeof(info->namespace_name)) {
                    safe_strncpy(entry->namespace_name, info->namespace_name,
                                 sizeof(entry->namespace_name));
                }
                /* Only copy k8s_labels if it's been initialized (not empty) */
                if (info->k8s_labels[0] != '\0' &&
                    strnlen(info->k8s_labels, sizeof(info->k8s_labels)) <
                        sizeof(info->k8s_labels)) {
                    safe_strncpy(entry->k8s_labels, info->k8s_labels, sizeof(entry->k8s_labels));
                }
            }
        }

        /* Set creation time */
        entry->start_time = time(NULL);
        entry->is_active = true;

        /* Add to hash table for fast lookup */
        hash_table_insert(pid, g_tracker.container_count);

        g_tracker.container_count++;
    }

    return CONTAINER_SUCCESS;
}

/* Check if a process is running in a container */
bool container_tracker_is_container(pid_t pid)
{
    struct container_info info;

    if (container_tracker_get_info(pid, &info) == 0) {
        return info.is_container;
    }

    return false;
}

/* Get container ID for a process */
int container_tracker_get_id(pid_t pid, char *container_id, size_t max_len)
{
    struct container_info info;

    if (!container_id || max_len == 0) {
        return CONTAINER_ERROR_INVALID;
    }

    int result = container_tracker_get_info(pid, &info);
    if (result == CONTAINER_SUCCESS && info.is_container) {
        safe_strncpy(container_id, info.container_id, max_len);
        return CONTAINER_SUCCESS;
    }

    container_id[0] = '\0';
    return (result == CONTAINER_SUCCESS) ? CONTAINER_ERROR_NOT_FOUND : result;
}

/* Get list of all detected containers */
int container_tracker_get_containers(struct container_summary *containers, size_t max_containers,
                                     size_t *count)
{
    int unique_count = 0;
    int idx, jdx;
    bool found;

    if (!containers || !count || max_containers == 0) {
        return CONTAINER_ERROR_INVALID;
    }

    *count = 0;

    /* Build list of unique containers */
    for (idx = 0; idx < g_tracker.container_count && (size_t)unique_count < max_containers; idx++) {
        if (!g_tracker.containers[idx].is_container) {
            continue;
        }

        /* Check if we already have this container ID */
        found = false;
        for (jdx = 0; jdx < unique_count; jdx++) {
            if (strcmp(containers[jdx].container_id, g_tracker.containers[idx].container_id) == 0) {
                found = true;
                containers[jdx].process_count++;
                break;
            }
        }

        if (!found) {
            /* New container */
            safe_strncpy(containers[unique_count].container_id,
                         g_tracker.containers[idx].container_id,
                         sizeof(containers[unique_count].container_id));
            safe_strncpy(containers[unique_count].runtime, g_tracker.containers[idx].runtime,
                         sizeof(containers[unique_count].runtime));
            containers[unique_count].process_count = 1;

            /* Add Kubernetes information if available */
            containers[unique_count].is_k8s_pod = g_tracker.containers[idx].is_k8s_pod;
            if (g_tracker.containers[idx].is_k8s_pod) {
                safe_strncpy(containers[unique_count].pod_name, g_tracker.containers[idx].pod_name,
                             sizeof(containers[unique_count].pod_name));
                safe_strncpy(containers[unique_count].namespace_name,
                             g_tracker.containers[idx].namespace_name,
                             sizeof(containers[unique_count].namespace_name));
            }

            /* Initialize metrics to zero */
            containers[unique_count].cpu_usage_percent = 0.0;
            containers[unique_count].memory_usage_bytes = 0;
            containers[unique_count].io_read_bytes = 0;
            containers[unique_count].io_write_bytes = 0;
            containers[unique_count].syscall_count = 0;

            unique_count++;
        }
    }

    *count = unique_count;
    return CONTAINER_SUCCESS;
}

/* Clear container cache (useful when processes exit) */
void container_tracker_clear_cache(void)
{
    if (!g_tracker_initialized) {
        return;
    }

    g_tracker.container_count = 0;
    memset(g_tracker.containers, 0, sizeof(g_tracker.containers));
    /* Clear hash table as well */
    hash_table_clear();
}

/* Remove a specific PID from cache */
void container_tracker_remove_pid(pid_t pid)
{
    int idx;
    if (!g_tracker_initialized) {
        return;
    }

    /* Use hash table to find entry efficiently */
    idx = hash_table_lookup(pid);
    if (idx >= 0 && idx < g_tracker.container_count && g_tracker.containers[idx].pid == pid) {
        /* Remove from hash table first */
        hash_table_remove(pid);

        /* Shift remaining entries down */
        memmove(&g_tracker.containers[idx], &g_tracker.containers[idx + 1],
                (g_tracker.container_count - idx - 1) * sizeof(struct container_entry));
        g_tracker.container_count--;

        /* Rebuild hash table since indices changed */
        hash_table_clear();
        for (int i = 0; i < g_tracker.container_count; i++) {
            hash_table_insert(g_tracker.containers[i].pid, i);
        }
    }
}

/* Print container tracker statistics */
void container_tracker_print_stats(void)
{
    struct container_summary containers[MAX_CONTAINERS];
    size_t count;
    int idx;

    if (!g_tracker_initialized) {
        printf("Container tracker not initialized\n");
        return;
    }

    printf("Container Tracker Statistics:\n");
    printf("  Total cached processes: %d\n", g_tracker.container_count);

    if (container_tracker_get_containers(containers, MAX_CONTAINERS, &count) == 0) {
        printf("  Unique containers detected: %zu\n", count);

        for (idx = 0; idx < (int)count; idx++) {
            printf("    Container: %.12s... (%s) - %d processes\n", containers[idx].container_id,
                   containers[idx].runtime, containers[idx].process_count);
        }
    } else {
        printf("  Failed to enumerate containers\n");
    }
}

/* Get Kubernetes pod information for a process */
int container_tracker_get_k8s_info(pid_t pid, char *pod_name, char *namespace_name, size_t max_len)
{
    struct container_info info;

    if (!pod_name || !namespace_name || max_len == 0) {
        return CONTAINER_ERROR_INVALID;
    }

    int result = container_tracker_get_info(pid, &info);
    if (result == CONTAINER_SUCCESS && info.is_k8s_pod) {
        safe_strncpy(pod_name, info.pod_name, max_len);
        safe_strncpy(namespace_name, info.namespace_name, max_len);
        return CONTAINER_SUCCESS;
    }

    pod_name[0] = '\0';
    namespace_name[0] = '\0';
    return (result == CONTAINER_SUCCESS) ? CONTAINER_ERROR_NOT_FOUND : result;
}

/* Update container resource usage metrics */
int container_tracker_update_metrics(const char *container_id, double cpu_percent,
                                     unsigned long memory_bytes, unsigned long io_read,
                                     unsigned long io_write, unsigned long syscalls)
{
    int idx;
    struct container_summary *metric = NULL;

    if (!container_id || !g_tracker_initialized) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Find existing metric entry or create new one */
    for (idx = 0; idx < g_tracker.metrics_count; idx++) {
        if (strcmp(g_tracker.metrics[idx].container_id, container_id) == 0) {
            metric = &g_tracker.metrics[idx];
            break;
        }
    }

    if (!metric && g_tracker.metrics_count < MAX_CONTAINERS) {
        /* Create new metric entry */
        metric = &g_tracker.metrics[g_tracker.metrics_count];
        safe_strncpy(metric->container_id, container_id, sizeof(metric->container_id));

        /* Try to get additional container info */
        for (idx = 0; idx < g_tracker.container_count; idx++) {
            if (strcmp(g_tracker.containers[idx].container_id, container_id) == 0) {
                safe_strncpy(metric->runtime, g_tracker.containers[idx].runtime,
                             sizeof(metric->runtime));
                metric->is_k8s_pod = g_tracker.containers[idx].is_k8s_pod;
                if (metric->is_k8s_pod) {
                    safe_strncpy(metric->pod_name, g_tracker.containers[idx].pod_name,
                                 sizeof(metric->pod_name));
                    safe_strncpy(metric->namespace_name, g_tracker.containers[idx].namespace_name,
                                 sizeof(metric->namespace_name));
                }
                break;
            }
        }

        g_tracker.metrics_count++;
    }

    if (metric) {
        /* Update metrics */
        metric->cpu_usage_percent = cpu_percent;
        metric->memory_usage_bytes = memory_bytes;
        metric->io_read_bytes = io_read;
        metric->io_write_bytes = io_write;
        metric->syscall_count = syscalls;
        return CONTAINER_SUCCESS;
    }

    return CONTAINER_ERROR_MEMORY;
}

/* Track container lifecycle event */
int container_tracker_track_event(const char *container_id, const char *event_type)
{
    int idx;

    if (!container_id || !event_type || !g_tracker_initialized) {
        return CONTAINER_ERROR_INVALID;
    }

    /* Find container entry */
    for (idx = 0; idx < g_tracker.container_count; idx++) {
        if (strcmp(g_tracker.containers[idx].container_id, container_id) == 0) {
            if (strcmp(event_type, "start") == 0 || strcmp(event_type, "restart") == 0) {
                g_tracker.containers[idx].is_active = true;
                g_tracker.containers[idx].start_time = time(NULL);
            } else if (strcmp(event_type, "stop") == 0) {
                g_tracker.containers[idx].is_active = false;
            }
            return CONTAINER_SUCCESS;
        }
    }

    return CONTAINER_ERROR_NOT_FOUND;
}

/* Get aggregated metrics for all containers */
int container_tracker_get_metrics(struct container_summary *metrics, size_t max_containers,
                                  size_t *count)
{
    int idx;

    if (!metrics || !count || max_containers == 0 || !g_tracker_initialized) {
        return CONTAINER_ERROR_INVALID;
    }

    *count = 0;

    for (idx = 0; idx < g_tracker.metrics_count && *count < max_containers; idx++) {
        metrics[*count] = g_tracker.metrics[idx];
        (*count)++;
    }

    return CONTAINER_SUCCESS;
}
