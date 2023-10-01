#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "server_config.h"

void log_error(ServerConfig *config, const char *format, ...)
{
    FILE *file = fopen(config->error_log, "a");
    if (file)
    {
        va_list args;
        va_start(args, format);
        vfprintf(file, format, args);
        va_end(args);
        fprintf(file, "\n");
        fclose(file);
    }
    else
    {
        fprintf(stderr, "Failed to open error log for writing: %s\n", config->error_log);
    }
}

void log_access(ServerConfig *config, const char *format, ...)
{
    FILE *file = fopen(config->access_log, "a");
    if (file)
    {
        va_list args;
        va_start(args, format);
        vfprintf(file, format, args);
        va_end(args);
        fprintf(file, "\n");
        fclose(file);
    }
    else
    {
        fprintf(stderr, "Failed to open access log for writing: %s\n", config->access_log);
    }
}