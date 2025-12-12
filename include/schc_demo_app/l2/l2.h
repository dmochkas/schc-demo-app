#pragma once

#include <stdint.h>
#include <stddef.h>

// send down traffic
// accept traffic

typedef enum {
    L2_INIT_OK, L2_INIT_ERROR
} l2_init_status;

typedef enum {
    L2_SEND_OK, L2_SEND_KO
} l2_send_status;

l2_init_status l2_init();

void l2_set_id(uint32_t id);

void l2_send_prepare(const void* params);

l2_send_status l2_send_run(const uint8_t* payload, size_t size);

#ifdef L2_AHOI_EXT
#include "ext/l2_ahoi_ext.h"
#endif
