/* HPMon Container Tracker Header
 *
 * This header defines the interface for container detection and tracking
 * functionality that maps processes to containers using cgroup information.
 */

#ifndef CONTAINER_TRACKER_H
#define CONTAINER_TRACKER_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>

/* Maximum containers we can track */
#define MAX_CONTAINERS 100
#define MAX_CONTAINER_ID_LEN 64
#define MAX_RUNTIME_NAME_LEN 32
#define MAX_POD_NAME_LEN 64
#define MAX_NAMESPACE_LEN 64
#define MAX_K8S_LABEL_LEN 128

/* Container tracker constants */
#define MIN_CONTAINER_ID_LEN 12
#define MAX_PROC_PATH_LEN 256
#define MAX_LINE_LEN 1024
#define MAX_CGROUP_PATH_LEN 512

/* Standardized error codes for consistent error handling */
#define CONTAINER_SUCCESS 0
#define CONTAINER_ERROR_INVALID (-1)    /* Invalid parameters */
#define CONTAINER_ERROR_NOT_FOUND (-2)  /* Container/process not found */
#define CONTAINER_ERROR_IO (-3)         /* I/O operation failed */
#define CONTAINER_ERROR_MEMORY (-4)     /* Memory allocation failed */
#define CONTAINER_ERROR_PERMISSION (-5) /* Permission denied */
#define CONTAINER_ERROR_TRUNCATION (-6) /* Path/buffer truncation */
#define CONTAINER_ERROR_CORRUPTION (-7) /* Data corruption detected */

/* Hash table for efficient cache lookups */
#define CONTAINER_HASH_SIZE 101 /* Prime number for better distribution */

/* Hash table entry for efficient PID lookups */
struct container_hash_entry {
    pid_t pid;
    int container_index;               /* Index into containers array */
    struct container_hash_entry *next; /* Collision handling via chaining */
};

/* Container information structure */
struct container_info {
    pid_t pid;
    bool is_container;
    char container_id[MAX_CONTAINER_ID_LEN];
    char runtime[MAX_RUNTIME_NAME_LEN]; /* docker, containerd, podman, etc. */

    /* Kubernetes-specific information */
    bool is_k8s_pod;
    char pod_name[MAX_POD_NAME_LEN];
    char namespace_name[MAX_NAMESPACE_LEN];
    char k8s_labels[MAX_K8S_LABEL_LEN];
};

/* Container summary for enumeration */
struct container_summary {
    char container_id[MAX_CONTAINER_ID_LEN];
    char runtime[MAX_RUNTIME_NAME_LEN];
    int process_count;

    /* Kubernetes information */
    bool is_k8s_pod;
    char pod_name[MAX_POD_NAME_LEN];
    char namespace_name[MAX_NAMESPACE_LEN];

    /* Resource usage metrics */
    double cpu_usage_percent;
    unsigned long memory_usage_bytes;
    unsigned long io_read_bytes;
    unsigned long io_write_bytes;
    unsigned long syscall_count;
};

/* Internal container cache entry */
struct container_entry {
    pid_t pid;
    bool is_container;
    char container_id[MAX_CONTAINER_ID_LEN];
    char runtime[MAX_RUNTIME_NAME_LEN];

    /* Kubernetes information */
    bool is_k8s_pod;
    char pod_name[MAX_POD_NAME_LEN];
    char namespace_name[MAX_NAMESPACE_LEN];
    char k8s_labels[MAX_K8S_LABEL_LEN];

    /* Lifecycle tracking */
    time_t start_time;
    bool is_active;
};

/* Container tracker state */
struct container_tracker {
    struct container_entry containers[MAX_CONTAINERS];
    int container_count;

    /* Hash table for O(1) PID lookups */
    struct container_hash_entry *hash_table[CONTAINER_HASH_SIZE];
    struct container_hash_entry hash_pool[MAX_CONTAINERS]; /* Pre-allocated entries */
    int hash_pool_used;

    /* Resource metrics tracking */
    struct container_summary metrics[MAX_CONTAINERS];
    int metrics_count;
};

/* Function declarations */

/**
 * Initialize the container tracker
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* on error
 */
int container_tracker_init(void);

/**
 * Cleanup the container tracker
 */
void container_tracker_cleanup(void);

/**
 * Get container information for a process
 * @param pid: Process ID to check
 * @param info: Output container information
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* on error
 */
int container_tracker_get_info(pid_t pid, struct container_info *info);

/**
 * Check if a process is running in a container
 * @param pid: Process ID to check
 * @returns true if in container, false otherwise
 */
bool container_tracker_is_container(pid_t pid);

/**
 * Get container ID for a process
 * @param pid: Process ID to check
 * @param container_id: Output buffer for container ID
 * @param max_len: Maximum length of output buffer
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* if not a container or error
 */
int container_tracker_get_id(pid_t pid, char *container_id, size_t max_len);

/**
 * Get list of all detected containers
 * @param containers: Output array of container summaries
 * @param max_containers: Maximum number of containers to return
 * @param count: Output number of containers found
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* on error
 */
int container_tracker_get_containers(struct container_summary *containers, size_t max_containers,
                                     size_t *count);

/**
 * Clear the container cache
 */
void container_tracker_clear_cache(void);

/**
 * Remove a specific PID from cache
 * @param pid: Process ID to remove
 */
void container_tracker_remove_pid(pid_t pid);

/**
 * Print container tracker statistics
 */
void container_tracker_print_stats(void);

/**
 * Get Kubernetes pod information for a process
 * @param pid: Process ID to check
 * @param pod_name: Output buffer for pod name
 * @param namespace_name: Output buffer for namespace name
 * @param max_len: Maximum length of output buffers
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* if not a Kubernetes pod or error
 */
int container_tracker_get_k8s_info(pid_t pid, char *pod_name, char *namespace_name, size_t max_len);

/**
 * Update container resource usage metrics
 * @param container_id: Container ID to update
 * @param cpu_percent: CPU usage percentage
 * @param memory_bytes: Memory usage in bytes
 * @param io_read: Bytes read from disk
 * @param io_write: Bytes written to disk
 * @param syscalls: Number of system calls
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* on error
 */
int container_tracker_update_metrics(const char *container_id, double cpu_percent,
                                     unsigned long memory_bytes, unsigned long io_read,
                                     unsigned long io_write, unsigned long syscalls);

/**
 * Track container lifecycle event
 * @param container_id: Container ID
 * @param event_type: Event type ("start", "stop", "restart")
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* on error
 */
int container_tracker_track_event(const char *container_id, const char *event_type);

/**
 * Get aggregated metrics for all containers
 * @param metrics: Output array of container summaries with metrics
 * @param max_containers: Maximum number of containers to return
 * @param count: Output number of containers found
 * @returns CONTAINER_SUCCESS on success, CONTAINER_ERROR_* on error
 */
int container_tracker_get_metrics(struct container_summary *metrics, size_t max_containers,
                                  size_t *count);

#endif /* CONTAINER_TRACKER_H */
