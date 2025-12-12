#include "cli_helper.h"

#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>

#include "logger_helper.h"

void print_usage(const char *prog_name) {
    printf("TODO:");
}

int process_key(const char *hex, uint8_t *key_buffer, size_t key_size) {
    size_t hex_len = strlen(hex);

    if (hex_len < 2 || hex_len > key_size * 2) {
        zlog_error(error_cat, "Key must be 2-%zu hex characters\n", key_size * 2);
        return -1;
    }

    // Pad with zeros if needed
    memset(key_buffer, 0, key_size);

    // Convert what we can from the hex string
    for (size_t i = 0; i < hex_len/2 && i < key_size; i++) {
        if (!isxdigit(hex[i*2]) || !isxdigit(hex[i*2+1])) {
            zlog_error(error_cat, "Invalid hex characters in key\n");
            return -1;
        }
        sscanf(hex + i*2, "%2hhx", &key_buffer[i]);
    }

    // Handle odd-length hex string
    if (hex_len % 2 != 0) {
        if (!isxdigit(hex[hex_len-1])) {
            zlog_error(error_cat, "Invalid hex character in key\n");
            return -1;
        }
        sscanf(hex + hex_len-1, "%1hhx", &key_buffer[hex_len/2]);
    }

    return 0;
}

cli_parse_status parse_cli_arguments(const int32_t argc, char* const * argv, uint8_t* id, uint8_t* key_buf, const size_t key_size, char** port_ptr, int32_t* baud) {
    const struct option options[] = {
        {"id", required_argument, 0, 'i'},
        {"key", required_argument, 0, 'k'},
        {"port", required_argument, 0, 'p'},
        {"baud", required_argument, 0, 'b'},
        {"trials", required_argument, 0, 'n'},
        {"size", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;
    const char *id_arg = NULL;
    const char *key_hex = NULL;
    const char *baud_arg = NULL;
    const char *shortopts = "i:k:p:b:";
    while ((opt = getopt_long(argc, argv, shortopts, options, &option_index)) != -1) {
        switch (opt) {
            case 'i':
                id_arg = optarg;
            case 'k':
                key_hex = optarg;
            break;
            case 'p':
                *port_ptr = optarg;
            break;
            case 'b':
                baud_arg = optarg;
            break;
            default:
                print_usage(argv[0]);
            return CLI_PARSE_KO;
        }
    }

    if (id_arg) {
        *id = (uint8_t) atoi(id_arg);
    }

    if (!key_hex) {
        zlog_error(error_cat, "Error: Encryption key is required\n");
        print_usage(argv[0]);
        return CLI_PARSE_KO;
    }

    if (process_key(key_hex, key_buf, key_size) != 0) {
        return CLI_PARSE_KO;
    }

    if (baud_arg != NULL && strcmp("115200", baud_arg) != 0) {
        zlog_error(error_cat, "Only 115200 baudrate is supported\n");
        return CLI_PARSE_KO;
    }

    *baud = B115200;

    return CLI_PARSE_OK;
}
