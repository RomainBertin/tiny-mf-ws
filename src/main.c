#include "server.h"
#include "server_config.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    ServerConfig config;
    char *config_path = NULL;
    int opt;
    int debug_mode = 0;
    
    while ((opt = getopt(argc, argv, "c:d")) != -1) {
        switch (opt) {
            case 'c':
                config_path = optarg;
                break;
            case 'd':
                debug_mode = 1;
                break;

            default:
                fprintf(stderr, "Usage: %s -c <config-path>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!config_path) {
        fprintf(stderr, "Please specify a config file with -c option.\n");
        exit(EXIT_FAILURE);
    }

    read_config_file(config_path, &config);

    if (debug_mode) {
        printf("--- Configuration loaded from %s: --- \n", config_path);
        printf("max_files_request: %d\n", config.max_files_request);
        printf("max_clients: %d\n", config.max_clients);
        printf("delay_timeout: %d\n", config.delay_timeout);
        printf("folder_route: %s\n", config.folder_route);
        printf("maximum_process_client: %d\n", config.maximum_process_client);
        printf("maximum_thread_by_process: %d\n", config.maximum_thread_by_process);
        printf("maximum_connections_by_thread: %d\n", config.maximum_connections_by_thread);
        printf("-------------------------------------\n");
    }

    start_server(&config, debug_mode);

    return 0;
}

