#pragma once

#include <stdint.h>
#include <stddef.h>

typedef enum {
    CLI_PARSE_OK, CLI_PARSE_KO
} cli_parse_status;

void print_usage(const char* prog_name);

cli_parse_status parse_cli_arguments(int32_t argc, char* const * argv, uint8_t* id, uint8_t* key_buf, size_t key_size, char** port_ptr, int32_t* baud);