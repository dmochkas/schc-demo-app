#pragma once

#include <stdint.h>

// send down traffic
// accept traffic

typedef enum {
    l2_init_ok, l2_init_error
} l2_init_status;

l2_init_status l2_init();

void set_l2_id(uint32_t id);

#ifdef L2_AHOI_EXT
#include "ext/l2_ahoi_ext.h"
#endif
