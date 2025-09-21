#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define PORT 8080
#define BACKLOG 5
#define BUFFER_SIZE 1024

/* Global variables to handle graceful shutdown */
static volatile int server_running = 1;
static int server_socket_global = -1;

/* Function prototypes */
static void signal_handler(int sig);
static void handle_client(int client_socket);
static int setup_server_socket(void);

int main(void)
{
    int server_socket, client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len;
    pid_t child_pid;

    printf("HPMon Echo Server\n");
    printf("=================\n");
    printf("Starting echo server on localhost:%d\n", PORT);

    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGCHLD, SIG_IGN); /* Automatically reap child processes */

    /* Set up server socket */
    server_socket = setup_server_socket();
    if (server_socket < 0) {
        fprintf(stderr, "Failed to setup server socket\n");
        exit(EXIT_FAILURE);
    }

    /* Store global reference for signal handler */
    server_socket_global = server_socket;

    printf("Server listening on port %d (PID: %d)\n", PORT, getpid());
    printf("Press Ctrl+C to stop the server\n\n");

    /* Main server loop */
    while (server_running) {
        client_addr_len = sizeof(client_addr);

        /* Accept incoming connection */
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);

        if (client_socket < 0) {
            if (!server_running) {
                /* Server is shutting down */
                printf("Server shutting down, no longer accepting connections\n");
                break;
            }
            if (errno == EINTR) {
                /* Interrupted by signal, check if we should continue */
                continue;
            }
            perror("accept failed");
            continue;
        }

        printf("New connection from %s:%d\n", inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));

        /* Fork a child process to handle the client */
        child_pid = fork();

        if (child_pid == 0) {
            /* Child process */
            close(server_socket); /* Child doesn't need server socket */
            handle_client(client_socket);
            close(client_socket);
            exit(EXIT_SUCCESS);
        } else if (child_pid > 0) {
            /* Parent process */
            close(client_socket); /* Parent doesn't need client socket */
        } else {
            /* Fork failed */
            perror("fork failed");
            close(client_socket);
        }
    }

    /* Cleanup */
    if (server_socket >= 0) {
        close(server_socket);
    }
    printf("Server shutdown complete\n");

    return 0;
}

static void signal_handler(int sig)
{
    printf("\nReceived signal %d, shutting down server...\n", sig);
    server_running = 0;

    /* Close the server socket to interrupt accept() */
    if (server_socket_global >= 0) {
        close(server_socket_global);
        server_socket_global = -1;
    }
}

static void handle_client(int client_socket)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received, bytes_sent;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    /* Get client information */
    if (getpeername(client_socket, (struct sockaddr *)&client_addr, &addr_len) == 0) {
        printf("[Child %d] Handling client %s:%d\n", getpid(), inet_ntoa(client_addr.sin_addr),
               ntohs(client_addr.sin_port));
    }

    while (1) {
        /* Receive data from client */
        memset(buffer, 0, sizeof(buffer));
        bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("[Child %d] Client disconnected\n", getpid());
            } else {
                perror("recv failed");
            }
            break;
        }

        /* Null-terminate the received data */
        buffer[bytes_received] = '\0';
        printf("[Child %d] Received: '%s'\n", getpid(), buffer);

        /* Echo the data back to client */
        bytes_sent = send(client_socket, buffer, bytes_received, 0);

        if (bytes_sent < 0) {
            perror("send failed");
            break;
        }

        printf("[Child %d] Echoed %zd bytes back to client\n", getpid(), bytes_sent);

        /* If client sent "quit" or "exit", close connection */
        if (strncmp(buffer, "quit", 4) == 0 || strncmp(buffer, "exit", 4) == 0) {
            printf("[Child %d] Client requested disconnection\n", getpid());
            break;
        }
    }

    printf("[Child %d] Client handler finished\n", getpid());
}

static int setup_server_socket(void)
{
    int server_socket;
    struct sockaddr_in server_addr;
    int opt = 1;

    /* Create socket */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket creation failed");
        return -1;
    }

    /* Set socket options to reuse address */
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_socket);
        return -1;
    }

    /* Set up server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);

    /* Bind socket to address */
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_socket);
        return -1;
    }

    /* Listen for connections */
    if (listen(server_socket, BACKLOG) < 0) {
        perror("listen failed");
        close(server_socket);
        return -1;
    }

    return server_socket;
}
