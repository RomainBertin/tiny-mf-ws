#include "server_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void handle_config_error(const char *message)
{
    fprintf(stderr, "%s\n", message);
    exit(EXIT_FAILURE);
}

typedef struct
{
    const char *key;
    int flag;
    void (*handler)(const char *value, ServerConfig *config);
} ConfigEntry;

void set_listen_port(const char *value, ServerConfig *config)
{
    config->listen_port = atoi(value);
}

void set_max_files_request(const char *value, ServerConfig *config)
{
    config->max_files_request = atoi(value);
}

void set_max_clients(const char *value, ServerConfig *config)
{
    config->max_clients = atoi(value);
}

void set_delay_timeout(const char *value, ServerConfig *config)
{
    config->delay_timeout = atoi(value);
}

void set_folder_route(const char *value, ServerConfig *config)
{
    strncpy(config->folder_route, value, sizeof(config->folder_route));
}

void set_maximum_process_client(const char *value, ServerConfig *config)
{
    config->maximum_process_client = atoi(value);
}

void set_maximum_thread_by_process(const char *value, ServerConfig *config)
{
    config->maximum_thread_by_process = atoi(value);
}

void set_maximum_connections_by_thread(const char *value, ServerConfig *config)
{
    config->maximum_connections_by_thread = atoi(value);
}

void set_max_unique_ip_connections(const char *value, ServerConfig *config)
{
    config->max_unique_ip_connections = atoi(value);
}

void set_error_log(const char *value, ServerConfig *config)
{
    strncpy(config->error_log, value, sizeof(config->error_log));
}

void set_access_log(const char *value, ServerConfig *config)
{
    strncpy(config->access_log, value, sizeof(config->access_log));
}

void read_config_file(const char *path, ServerConfig *config)
{
    FILE *file = fopen(path, "r");
    if (file == NULL)
    {
        handle_config_error("Error opening config file.");
    }

    char line[2048];
    int config_flags = 0;

    ConfigEntry config_entries[] = {
        {"listen_port", 0x1, set_listen_port},
        {"max_files_request", 0x2, set_max_files_request},
        {"max_clients", 0x4, set_max_clients},
        {"delay_timeout", 0x8, set_delay_timeout},
        {"folder_route", 0x10, set_folder_route},
        {"maximum_process_client", 0x20, set_maximum_process_client},
        {"maximum_thread_by_process", 0x40, set_maximum_thread_by_process},
        {"maximum_connections_by_thread", 0x80, set_maximum_connections_by_thread},
        {"error_log", 0x100, set_error_log},
        {"access_log", 0x200, set_access_log},
        {"max_unique_ip_connections", 0x400, set_max_unique_ip_connections}
    };

    int num_entries = sizeof(config_entries) / sizeof(ConfigEntry);

    while (fgets(line, sizeof(line), file))
    {
        char key[512], value[512];
        int found = 0;
        if (sscanf(line, " %[^= ] = %s ", key, value) == 2)
        {
            for (int i = 0; i < num_entries; i++)
            {
                if (strcmp(key, config_entries[i].key) == 0)
                {
                    if (config_flags & config_entries[i].flag)
                    {
                        char err_message[512];
                        snprintf(err_message, sizeof(err_message), "Duplicate config key: %s", key);
                        handle_config_error(err_message);
                    }

                    config_entries[i].handler(value, config);
                    config_flags |= config_entries[i].flag;
                    found = 1;
                    break;
                }
            }
            if (!found)
            {
                char err_message[512];
                snprintf(err_message, sizeof(err_message), "Unknown config key: %s", key);
                handle_config_error(err_message);
            }
        }
    }
    fclose(file);

    for (int i = 0; i < num_entries; i++)
    {
        if (!(config_flags & config_entries[i].flag))
        {
            char err_message[512];
            snprintf(err_message, sizeof(err_message), "Missing key: %s", config_entries[i].key);
            handle_config_error(err_message);
        }
    }
}
