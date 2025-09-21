#define _POSIX_C_SOURCE 199309L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define _POSIX_C_SOURCE 199309L

#define BUFFER_SIZE 1024
#define MEMORY_SIZE 4096

/* Global variables to store the test configuration */
static int NUMBER_RUNS = 1;
static int DURATION_SECONDS = 0;   /* 0 means run by count, >0 means run for duration */
static int USE_MULTITHREADING = 0; /* 0 means single-threaded, 1 means multi-threaded */

#define NUM_THREADS 8

/* Thread data structure */
typedef struct {
    int thread_id;
    int (*test_function)(void);
    int success_count;
    int total_runs;
    struct timespec start_time;
} thread_data_t;

/* Function prototypes */
static int get_test_configuration(void);
static int parse_duration_string(const char *duration_str);
static int should_continue_testing(int run_number, struct timespec start_time);
static int test_network_connection(void);
static int test_file_operations(void);
static int test_memory_allocation(void);
static void print_menu(void);
static double get_elapsed_time_ms(struct timespec start, struct timespec end);
static void *thread_worker(void *arg);
static int run_single_threaded_test(int (*test_function)(void), struct timespec start_time,
                                    int *total_runs_out);
static int run_multi_threaded_test(int (*test_function)(void), struct timespec start_time);

int main(void)
{
    int choice;
    struct timespec start_time, end_time;
    double elapsed_ms;

    printf("HPMon Load Test Program\n");
    printf("======================\n");
    printf("Process ID (PID): %d\n\n", getpid());

    /* Get test configuration from user */
    get_test_configuration();

    /* Seed the random number generator */
    srand(time(NULL));

    while (1) {
        print_menu();
        printf("Enter your choice (1-5): ");

        /* Record start time when user makes a choice */
        clock_gettime(CLOCK_MONOTONIC, &start_time);

        if (scanf("%d", &choice) != 1) {
            /* Clear invalid input */
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            printf("Invalid input. Please enter a number between 1-5.\n\n");
            continue;
        }

        switch (choice) {
        case 1:
            if (USE_MULTITHREADING) {
                if (DURATION_SECONDS > 0) {
                    printf(
                        "\n--- Testing Network Connection (Multi-threaded, for %d seconds) ---\n",
                        DURATION_SECONDS);
                } else {
                    printf("\n--- Testing Network Connection (Multi-threaded, %d runs per thread) "
                           "---\n",
                           NUMBER_RUNS);
                }
                run_multi_threaded_test(test_network_connection, start_time);
            } else {
                if (DURATION_SECONDS > 0) {
                    printf(
                        "\n--- Testing Network Connection (Single-threaded, for %d seconds) ---\n",
                        DURATION_SECONDS);
                } else {
                    printf("\n--- Testing Network Connection (Single-threaded, %d runs) ---\n",
                           NUMBER_RUNS);
                }
                int total_runs;
                int success_count =
                    run_single_threaded_test(test_network_connection, start_time, &total_runs);
                printf("Summary: %d/%d tests passed\n", success_count, total_runs);
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            elapsed_ms = get_elapsed_time_ms(start_time, end_time);
            printf("Total execution time: %.2f ms\n\n", elapsed_ms);
            break;

        case 2:
            if (USE_MULTITHREADING) {
                if (DURATION_SECONDS > 0) {
                    printf("\n--- Testing File Operations (Multi-threaded, for %d seconds) ---\n",
                           DURATION_SECONDS);
                } else {
                    printf(
                        "\n--- Testing File Operations (Multi-threaded, %d runs per thread) ---\n",
                        NUMBER_RUNS);
                }
                run_multi_threaded_test(test_file_operations, start_time);
            } else {
                if (DURATION_SECONDS > 0) {
                    printf("\n--- Testing File Operations (Single-threaded, for %d seconds) ---\n",
                           DURATION_SECONDS);
                } else {
                    printf("\n--- Testing File Operations (Single-threaded, %d runs) ---\n",
                           NUMBER_RUNS);
                }
                int total_runs;
                int success_count =
                    run_single_threaded_test(test_file_operations, start_time, &total_runs);
                printf("Summary: %d/%d tests passed\n", success_count, total_runs);
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            elapsed_ms = get_elapsed_time_ms(start_time, end_time);
            printf("Total execution time: %.2f ms\n\n", elapsed_ms);
            break;

        case 3:
            if (USE_MULTITHREADING) {
                if (DURATION_SECONDS > 0) {
                    printf("\n--- Testing Memory Allocation (Multi-threaded, for %d seconds) ---\n",
                           DURATION_SECONDS);
                } else {
                    printf("\n--- Testing Memory Allocation (Multi-threaded, %d runs per thread) "
                           "---\n",
                           NUMBER_RUNS);
                }
                run_multi_threaded_test(test_memory_allocation, start_time);
            } else {
                if (DURATION_SECONDS > 0) {
                    printf(
                        "\n--- Testing Memory Allocation (Single-threaded, for %d seconds) ---\n",
                        DURATION_SECONDS);
                } else {
                    printf("\n--- Testing Memory Allocation (Single-threaded, %d runs) ---\n",
                           NUMBER_RUNS);
                }
                int total_runs;
                int success_count =
                    run_single_threaded_test(test_memory_allocation, start_time, &total_runs);
                printf("Summary: %d/%d tests passed\n", success_count, total_runs);
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            elapsed_ms = get_elapsed_time_ms(start_time, end_time);
            printf("Total execution time: %.2f ms\n\n", elapsed_ms);
            break;

        case 4:
            if (USE_MULTITHREADING) {
                if (DURATION_SECONDS > 0) {
                    printf("\n--- Random Test (Multi-threaded, for %d seconds) ---\n",
                           DURATION_SECONDS);
                } else {
                    printf("\n--- Random Test (Multi-threaded, %d runs per thread) ---\n",
                           NUMBER_RUNS);
                }
                /* Randomly choose one of the three test types */
                int random_choice = (rand() % 3) + 1;
                switch (random_choice) {
                case 1:
                    printf("Randomly selected: Network Connection Test\n");
                    run_multi_threaded_test(test_network_connection, start_time);
                    break;
                case 2:
                    printf("Randomly selected: File Operations Test\n");
                    run_multi_threaded_test(test_file_operations, start_time);
                    break;
                case 3:
                    printf("Randomly selected: Memory Allocation Test\n");
                    run_multi_threaded_test(test_memory_allocation, start_time);
                    break;
                }
            } else {
                if (DURATION_SECONDS > 0) {
                    printf("\n--- Random Test (Single-threaded, for %d seconds) ---\n",
                           DURATION_SECONDS);
                } else {
                    printf("\n--- Random Test (Single-threaded, %d runs) ---\n", NUMBER_RUNS);
                }
                int success_count = 0;
                int total_runs = 0;
                for (int run = 1; should_continue_testing(run, start_time); run++) {
                    total_runs = run;
                    /* Randomly choose between options 1-3 */
                    int random_choice = (rand() % 3) + 1;
                    int result = -1;
                    switch (random_choice) {
                    case 1:
                        result = test_network_connection();
                        break;
                    case 2:
                        result = test_file_operations();
                        break;
                    case 3:
                        result = test_memory_allocation();
                        break;
                    }

                    if (result == 0) {
                        success_count++;
                    }
                }
                printf("Summary: %d/%d tests passed\n", success_count, total_runs);
            }
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            elapsed_ms = get_elapsed_time_ms(start_time, end_time);
            printf("Total execution time: %.2f ms\n\n", elapsed_ms);
            break;

        case 5:
            printf("\nExiting program...\n");
            exit(0);

        default:
            printf("Invalid choice. Please enter a number between 1-5.\n\n");
            break;
        }
    }

    return 0;
}

static int get_test_configuration(void)
{
    char input[100];
    int runs;

    /* First ask about threading preference */
    while (1) {
        printf("Choose threading mode:\n");
        printf("1. Single-threaded\n");
        printf("2. Multi-threaded (8 threads)\n");
        printf("Enter your choice (1-2): ");

        if (scanf("%99s", input) != 1) {
            /* Clear invalid input */
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            printf("Invalid input. Please try again.\n");
            continue;
        }

        if (strcmp(input, "1") == 0) {
            USE_MULTITHREADING = 0;
            printf("Selected: Single-threaded mode\n");
            break;
        } else if (strcmp(input, "2") == 0) {
            USE_MULTITHREADING = 1;
            printf("Selected: Multi-threaded mode (8 threads)\n");
            break;
        } else {
            printf("Invalid choice. Please enter 1 or 2.\n");
        }
    }

    /* Then ask about test duration/count */
    while (1) {
        printf("Enter number of runs OR duration (e.g., '5' for 5 runs, '10m' for 10 minutes): ");

        if (scanf("%99s", input) != 1) {
            /* Clear invalid input */
            int c;
            while ((c = getchar()) != '\n' && c != EOF)
                ;
            printf("Invalid input. Please try again.\n");
            continue;
        }

        /* Try to parse as duration first */
        int duration = parse_duration_string(input);
        if (duration > 0) {
            DURATION_SECONDS = duration;
            NUMBER_RUNS = 0; /* Indicates time-based execution */
            printf("Set to run tests for %d seconds (%s)\n\n", duration, input);
            return 0; /* Success */
        }

        /* Try to parse as number of runs */
        char *endptr;
        runs = (int)strtol(input, &endptr, 10);
        if (*endptr == '\0' && runs > 0) {
            NUMBER_RUNS = runs;
            DURATION_SECONDS = 0; /* Indicates count-based execution */
            printf("Set to run each test %d time(s)\n\n", runs);
            return runs;
        }

        printf("Invalid input. Please enter a positive number (e.g., '5') or duration (e.g., "
               "'10m', '30s', '1h').\n");
    }
}

static void *thread_worker(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    data->success_count = 0;
    data->total_runs = 0;

    for (int run = 1; should_continue_testing(run, data->start_time); run++) {
        data->total_runs = run;
        if (data->test_function() == 0) {
            data->success_count++;
        }
    }

    return NULL;
}

static int run_single_threaded_test(int (*test_function)(void), struct timespec start_time,
                                    int *total_runs_out)
{
    int success_count = 0;
    int total_runs = 0;

    for (int run = 1; should_continue_testing(run, start_time); run++) {
        total_runs = run;
        if (test_function() == 0) {
            success_count++;
        }
    }

    if (total_runs_out) {
        *total_runs_out = total_runs;
    }
    return success_count;
}

static int run_multi_threaded_test(int (*test_function)(void), struct timespec start_time)
{
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    int total_success = 0;
    int total_runs = 0;
    int threads_created = 0;

    /* Create threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].test_function = test_function;
        thread_data[i].success_count = 0;
        thread_data[i].total_runs = 0;
        thread_data[i].start_time = start_time;

        int ret = pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]);
        if (ret != 0) {
            printf("Error creating thread %d: %s\n", i, strerror(ret));
            /* Clean up already created threads */
            for (int j = 0; j < threads_created; j++) {
                if (pthread_join(threads[j], NULL) != 0) {
                    printf("Error joining thread %d during cleanup\n", j);
                }
            }
            return -1;
        }
        threads_created++;
    }

    /* Wait for all threads to complete */
    for (int i = 0; i < NUM_THREADS; i++) {
        int ret = pthread_join(threads[i], NULL);
        if (ret != 0) {
            printf("Error joining thread %d: %s\n", i, strerror(ret));
            /* Continue joining other threads even if one fails */
        }
        total_success += thread_data[i].success_count;
        total_runs += thread_data[i].total_runs;
    }

    printf("Summary: %d/%d tests passed across %d threads\n", total_success, total_runs,
           NUM_THREADS);
    return total_success;
}

static void print_menu(void)
{
    printf("Available test options:\n");
    printf("1. Network Connection Test (connect to localhost:8080)\n");
    printf("2. File Operations Test (write/read /tmp/test)\n");
    printf("3. Memory Allocation Test (allocate 4KB, fill with 'A', free)\n");
    printf("4. Random Test (randomly choose option 1-3)\n");
    printf("5. Exit\n");
    printf("\n");
}

static int test_network_connection(void)
{
    int sockfd;
    struct sockaddr_in server_addr;
    char send_buffer[] = "hello";
    char recv_buffer[BUFFER_SIZE];
    ssize_t bytes_sent, bytes_received;

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }

    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connection failed");
        close(sockfd);
        return -1;
    }

    /* Send "hello" */
    bytes_sent = send(sockfd, send_buffer, strlen(send_buffer), 0);
    if (bytes_sent < 0) {
        perror("send failed");
        close(sockfd);
        return -1;
    }

    /* Receive echo back */
    memset(recv_buffer, 0, sizeof(recv_buffer));
    bytes_received = recv(sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv failed");
        close(sockfd);
        return -1;
    }
    // compare sent and received data
    if (bytes_received != bytes_sent || strncmp(send_buffer, recv_buffer, bytes_sent) != 0) {
        printf("Data mismatch: sent '%s', received '%s'\n", send_buffer, recv_buffer);
        close(sockfd);
        return -1;
    }

    /* Close socket */
    close(sockfd);
    return 0;
}

static int test_file_operations(void)
{
    int fd;
    char filename[256];
    const char *write_data = "hello";
    char read_buffer[BUFFER_SIZE];
    ssize_t bytes_written, bytes_read;

    /* Create unique filename per thread to avoid race conditions */
    snprintf(filename, sizeof(filename), "/tmp/test_%d_%lu", getpid(),
             (unsigned long)pthread_self());

    /* First operation: write to file */
    fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open for writing failed");
        return -1;
    }

    bytes_written = write(fd, write_data, strlen(write_data));
    if (bytes_written < 0) {
        perror("write failed");
        close(fd);
        return -1;
    }

    close(fd);

    /* Second operation: read from file */
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open for reading failed");
        return -1;
    }

    memset(read_buffer, 0, sizeof(read_buffer));
    bytes_read = read(fd, read_buffer, sizeof(read_buffer) - 1);
    if (bytes_read < 0) {
        perror("read failed");
        close(fd);
        return -1;
    }
    close(fd);

    /* Verify content */
    if (strcmp(read_buffer, write_data) != 0) {
        printf("Content verification: FAILED\n");
        unlink(filename); /* Clean up temporary file */
        return -1;
    }

    /* Clean up temporary file */
    unlink(filename);
    return 0;
}

static int test_memory_allocation(void)
{
    void *memory_block;
    size_t i;

    /* Allocate 4KB of memory */
    memory_block = malloc(MEMORY_SIZE);
    if (memory_block == NULL) {
        perror("malloc failed");
        return -1;
    }

    /* Fill memory with 'A' */
    memset(memory_block, 'A', MEMORY_SIZE);

    /* Verify first and last few bytes */
    char *char_ptr = (char *)memory_block;
    for (i = 0; i < 10; i++) {
        if (char_ptr[i] != 'A') {
            printf("Memory verification failed at position %zu\n", i);
            free(memory_block);
            return -1;
        }
    }
    for (i = MEMORY_SIZE - 10; i < MEMORY_SIZE; i++) {
        if (char_ptr[i] != 'A') {
            printf("Memory verification failed at position %zu\n", i);
            free(memory_block);
            return -1;
        }
    }

    /* Free the memory */
    free(memory_block);
    return 0;
}

static double get_elapsed_time_ms(struct timespec start, struct timespec end)
{
    double start_ms = start.tv_sec * 1000.0 + start.tv_nsec / 1000000.0;
    double end_ms = end.tv_sec * 1000.0 + end.tv_nsec / 1000000.0;
    return end_ms - start_ms;
}

static int parse_duration_string(const char *duration_str)
{
    int len = strlen(duration_str);
    if (len < 2) {
        return -1; /* Invalid format */
    }

    char unit = duration_str[len - 1];
    char *endptr;
    long value = strtol(duration_str, &endptr, 10);

    /* Check if the number part is valid and unit is at the end */
    if (endptr != duration_str + len - 1 || value <= 0) {
        return -1; /* Invalid number or negative value */
    }

    switch (unit) {
    case 's':
    case 'S':
        return (int)value;
    case 'm':
    case 'M':
        return (int)value * 60;
    case 'h':
    case 'H':
        return (int)value * 3600;
    default:
        return -1; /* Unknown unit */
    }
}

static int should_continue_testing(int run_number, struct timespec start_time)
{
    if (DURATION_SECONDS > 0) {
        /* Time-based execution */
        sleep(1); /* Sleep for 1 second between runs */
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        double elapsed_seconds = (current_time.tv_sec - start_time.tv_sec) +
                                 (current_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
        return elapsed_seconds < DURATION_SECONDS;
    } else {
        /* Count-based execution */
        return run_number <= NUMBER_RUNS;
    }
}
