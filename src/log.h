#ifndef LOG_H
#define LOG_H

#include "server_config.h"

void log_error(ServerConfig *config, const char *format, ...);
void log_access(ServerConfig *config, const char *format, ...);

#endif 
