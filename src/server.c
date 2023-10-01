#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include "server.h"
#include "log.h"

#define CONNECTION_ADDED '+'
#define CONNECTION_REMOVED '-'

typedef struct
{
    int activeConnections;
    pthread_mutex_t activeConnectionsMutex;
} SharedThreadInfo;

typedef struct
{
    SharedThreadInfo *threads;
    int totalActiveConnections;
    int pipe_fd[2];
} ProcessInfo;

typedef struct
{
    int *sockets;
    ServerConfig config;
    int processIndex;
    int threadIndex;
    int debug_mode;
} ThreadData;

#define MAX_UNIQUE_IPS 1024

typedef struct
{
    char ip[INET_ADDRSTRLEN];
    int count;
} IPCounter;

IPCounter ip_counters[MAX_UNIQUE_IPS];
pthread_mutex_t ip_counter_mutex = PTHREAD_MUTEX_INITIALIZER;

ProcessInfo *processInfos;

int server_fd;

char *get_client_ip(int socket_fd)
{
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(socket_fd, (struct sockaddr *)&addr, &addr_size);

    char *ip_str = NULL;

    if (res != -1)
    {
        ip_str = (char *)malloc(INET_ADDRSTRLEN);
        if (!ip_str)
            return NULL;

        inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    }

    return ip_str;
}

void demonize()
{
    pid_t pid;

    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    pid = fork();

    if (pid < 0)
        exit(EXIT_FAILURE);
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (chdir("/") < 0)
        exit(EXIT_FAILURE);

    umask(0);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void init_processInfos(ServerConfig *config)
{
    for (int i = 0; i < config->maximum_process_client; i++)
    {
        pthread_mutexattr_t attr;
        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

        processInfos[i].threads = mmap(NULL, sizeof(SharedThreadInfo) * config->maximum_thread_by_process, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

        for (int j = 0; j < config->maximum_thread_by_process; j++)
        {
            processInfos[i].threads[j].activeConnections = 0;
            pthread_mutex_init(&processInfos[i].threads[j].activeConnectionsMutex, &attr);
        }
    }
}

void free_processInfos(ServerConfig *config)
{
    for (int i = 0; i < config->maximum_process_client; i++)
    {
        free(processInfos[i].threads);
    }
}

void display_info(ServerConfig *config)
{
    for (int i = 0; i < config->maximum_process_client; i++)
    {
        printf("Process %d: \n", i);

        for (int j = 0; j < config->maximum_thread_by_process; j++)
        {
            pthread_mutex_lock(&processInfos[i].threads[j].activeConnectionsMutex);
            int activeConnections = processInfos[i].threads[j].activeConnections;
            pthread_mutex_unlock(&processInfos[i].threads[j].activeConnectionsMutex);

            printf("\tThread %d: %d active connections\n", j, activeConnections);
        }
    }
}

ssize_t read_from_client(int socket_fd, char *buffer, size_t buffer_size)
{
    ssize_t bytes_received = recv(socket_fd, buffer, buffer_size, 0);

    if (bytes_received <= 0)
    {
        if (bytes_received < 0)
        {
            perror("recv");
        }
        return -1;
    }

    buffer[bytes_received] = '\0';

    return bytes_received;
}

void initialize_sockets_and_fds(ThreadData *data, fd_set *readfds, int *max_fd)
{
    data->sockets = malloc(sizeof(int) * data->config.maximum_connections_by_thread);
    memset(data->sockets, -1, sizeof(int) * data->config.maximum_connections_by_thread);
    FD_ZERO(readfds);
    *max_fd = server_fd;
}

void update_active_sockets(ThreadData *data, fd_set *readfds, int *max_fd, int *hasActiveConnections)
{
    FD_SET(server_fd, readfds);
    *hasActiveConnections = 0;
    for (int i = 0; i < data->config.maximum_connections_by_thread; i++)
    {
        if (data->sockets[i] != -1)
        {
            FD_SET(data->sockets[i], readfds);
            *hasActiveConnections = 1;
            if (data->sockets[i] > *max_fd)
            {
                *max_fd = data->sockets[i];
            }
        }
    }
}

void handle_timeouts(ThreadData *data, fd_set *readfds)
{
    for (int i = 0; i < data->config.maximum_connections_by_thread; i++)
    {
        if (data->sockets[i] != -1 && !FD_ISSET(data->sockets[i], readfds))
        {
            close(data->sockets[i]);
            if (data->debug_mode)
            {
                log_error(&data->config, "Connection FD %d closed after delay timeout.", data->sockets[i]);
            }

            FD_CLR(data->sockets[i], readfds);
            data->sockets[i] = -1;

            pthread_mutex_lock(&processInfos[data->processIndex].threads[data->threadIndex].activeConnectionsMutex);
            processInfos[data->processIndex].threads[data->threadIndex].activeConnections--;
            pthread_mutex_unlock(&processInfos[data->processIndex].threads[data->threadIndex].activeConnectionsMutex);
        }
    }
}

int find_or_add_ip(const char *ip)
{
    for (int i = 0; i < MAX_UNIQUE_IPS; i++)
    {
        if (strcmp(ip_counters[i].ip, ip) == 0)
            return i;
        else if (strlen(ip_counters[i].ip) == 0)
        {
            strncpy(ip_counters[i].ip, ip, INET_ADDRSTRLEN);
            ip_counters[i].count = 0;
            return i;
        }
    }

    return -1;
}

void accept_new_connections(ThreadData *data, int *max_fd, fd_set *readfds)
{
    for (int i = 0; i < data->config.maximum_connections_by_thread; i++)
    {
        if (data->sockets[i] == -1)
        {
            struct sockaddr_in client_address;
            socklen_t client_address_len = sizeof(client_address);
            int new_socket = accept(server_fd, (struct sockaddr *)&client_address, &client_address_len);

            if (new_socket >= 0)
            {
                char client_ip[INET_ADDRSTRLEN];
                strncpy(client_ip, inet_ntoa(client_address.sin_addr), INET_ADDRSTRLEN);

                pthread_mutex_lock(&ip_counter_mutex);
                int idx = find_or_add_ip(client_ip);

                if (idx == -1)
                {
                    if (data->debug_mode)
                    {
                        log_error(&data->config, "Too many unique IPs");
                    }

                    close(new_socket);
                    FD_CLR(new_socket, readfds);
                    pthread_mutex_unlock(&ip_counter_mutex);
                    continue;
                }

                if (ip_counters[idx].count >= data->config.max_unique_ip_connections)
                {
                    if (data->debug_mode)
                    {
                        log_error(&data->config, "IP connection limit reached for IP: %s", client_ip);
                    }

                    close(new_socket);
                    FD_CLR(new_socket, readfds);

                    pthread_mutex_unlock(&ip_counter_mutex);
                    continue;
                }

                ip_counters[idx].count++;

                pthread_mutex_unlock(&ip_counter_mutex);

                data->sockets[i] = new_socket;
                if (data->debug_mode)
                {
                    log_access(&data->config, "New connection FD %d from IP %s", new_socket, client_ip);
                }

                if (new_socket > *max_fd)
                {
                    *max_fd = new_socket;
                }

                pthread_mutex_lock(&processInfos[data->processIndex].threads[data->threadIndex].activeConnectionsMutex);
                processInfos[data->processIndex].threads[data->threadIndex].activeConnections++;
                pthread_mutex_unlock(&processInfos[data->processIndex].threads[data->threadIndex].activeConnectionsMutex);
                break;
            }
            else
            {
                perror("Error accepting connection");
            }

            break;
        }
    }
}

void handle_client_data(ThreadData *data, fd_set *readfds)
{
    for (int i = 0; i < data->config.maximum_connections_by_thread; i++)
    {
        if (data->sockets[i] != -1 && FD_ISSET(data->sockets[i], readfds))
        {
            char client_data[4096];
            ssize_t bytes_received = read(data->sockets[i], client_data, sizeof(client_data) - 1);

            if (bytes_received > 0)
            {
                client_data[bytes_received] = '\0';
                if (data->debug_mode)
                    log_access(&data->config, "Received data from FD %d: %s", data->sockets[i], client_data);
            }
            else if (bytes_received == 0)
            {
                char *client_ip = get_client_ip(data->sockets[i]);
                if (client_ip)
                {
                    pthread_mutex_lock(&ip_counter_mutex);
                    int idx = find_or_add_ip(client_ip);

                    if (ip_counters[idx].count > 0)
                    {
                        ip_counters[idx].count--;
                    }
                    pthread_mutex_unlock(&ip_counter_mutex);
                    free(client_ip);
                }

                close(data->sockets[i]);
                FD_CLR(data->sockets[i], readfds);
                data->sockets[i] = -1;

                if (data->debug_mode)
                    log_access(&data->config, "Connection FD %d closed by client.", data->sockets[i]);

                data->sockets[i] = -1;

                pthread_mutex_lock(&processInfos[data->processIndex].threads[data->threadIndex].activeConnectionsMutex);
                processInfos[data->processIndex].threads[data->threadIndex].activeConnections--;
                pthread_mutex_unlock(&processInfos[data->processIndex].threads[data->threadIndex].activeConnectionsMutex);
            }
            else
            {
                // Handle error EAGAIN & EWOULDBLOCK
            }
        }
    }
}

void *thread_handler(void *arg)
{
    ThreadData *data = (ThreadData *)arg;

    fd_set readfds;
    int max_fd;
    int hasActiveConnections;

    initialize_sockets_and_fds(data, &readfds, &max_fd);

    while (1)
    {
        update_active_sockets(data, &readfds, &max_fd, &hasActiveConnections);

        struct timeval timeout;
        timeout.tv_sec = data->config.delay_timeout;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        if (activity < 0)
        {
            perror("select()");
            break;
        }

        if (activity == 0 && hasActiveConnections)
        {
            if (data->debug_mode)
                log_error(&data->config, "Delay timeout reached.");

            handle_timeouts(data, &readfds);
            continue;
        }

        if (FD_ISSET(server_fd, &readfds))
        {
            accept_new_connections(data, &max_fd, &readfds);
        }

        handle_client_data(data, &readfds);
    }

    close(processInfos[data->processIndex].pipe_fd[0]);
    close(processInfos[data->processIndex].pipe_fd[1]);
    free(data->sockets);
    free(data);
    return NULL;
}

void spawn_threads(ServerConfig *config, int processIndex)
{
    pthread_t *threads;
    ThreadData *data;

    threads = malloc(sizeof(pthread_t) * config->maximum_thread_by_process);

    for (int i = 0; i < config->maximum_thread_by_process; i++)
    {
        data = malloc(sizeof(ThreadData));
        data->config = *config;
        data->processIndex = processIndex;
        data->threadIndex = i;
        pthread_create(&threads[i], NULL, thread_handler, data);
    }

    for (int i = 0; i < config->maximum_thread_by_process; i++)
    {
        pthread_join(threads[i], NULL);
    }
    free(threads);
}

void *display_thread(void *arg)
{
    ServerConfig *config = (ServerConfig *)arg;

    while (1)
    {
        sleep(5);

        display_info(config);
    }

    return NULL;
}

void start_server(ServerConfig *config, int debug_mode)
{
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config->listen_port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    printf("Server listen on *:%d\n", config->listen_port);

    processInfos = malloc(sizeof(ProcessInfo) * config->maximum_process_client);
    if (!processInfos)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    init_processInfos(config);

    demonize();

    for (int i = 0; i < config->maximum_process_client; i++)
    {
        if (pipe(processInfos[i].pipe_fd) < 0)
        {
            perror("pipe creation failed");
            exit(EXIT_FAILURE);
        }

        pid_t pid = fork();

        if (pid < 0)
        {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }

        if (pid == 0)
        {
            for (int j = 0; j < config->maximum_thread_by_process; j++)
            {
                ThreadData *data = malloc(sizeof(ThreadData));
                data->config = *config;
                data->processIndex = i;
                data->threadIndex = j;
                data->debug_mode = debug_mode;
                pthread_t thread;
                pthread_create(&thread, NULL, thread_handler, data);
                pthread_detach(thread);
            }
            pause();
        }
    }

    if (debug_mode == 1)
    {
        pthread_t display_thread_id;
        pthread_create(&display_thread_id, NULL, display_thread, config);

        pthread_join(display_thread_id, NULL);

        free_processInfos(config);
    }
    else
    {

        while (1)
        {
            sleep(10);
        }
    }
}