#pragma once
#include <stddef.h>
#include <stdint.h>
#include <schc_sdk/fullsdknet.h>
#include <schc_sdk/schccomp.h>

typedef enum {
    SCHC_MODE_DUMMY = 0,
    SCHC_MODE_IPV6,
    SCHC_MODE_IPV6_UDP,
    SCHC_MODE_IPV6_UDP_COAP
} schc_mode_t;

typedef enum {
    SCHC_OK = 0,
    SCHC_ERR = 1,
    SCHC_BUF_TOO_SMALL = 2,
    SCHC_MODE_NOT_AVAILABLE = 3
} schc_status_t;

schc_status_t schc_service_init(schc_mode_t mode);

schc_status_t schc_service_compress(const uint8_t* in, size_t in_len,
                                    uint8_t* out, size_t out_cap,
                                    size_t* out_len);
