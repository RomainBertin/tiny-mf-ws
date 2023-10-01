#ifndef SERVER_H
#define SERVER_H

typedef struct {
    int max_files_request;
    int max_clients;
    int delay_timeout;
    int maximum_process_client;
    int maximum_thread_by_process;
    int maximum_connections_by_thread;
    int listen_port;
    int max_unique_ip_connections;
    char folder_route[256];
    char access_log[256];
    char error_log[256];
} ServerConfig;

void start_server(ServerConfig *config, int debug_mode);

#endif
