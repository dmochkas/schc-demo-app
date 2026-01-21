#pragma once
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SCHC_OK = 0,
    SCHC_ERR = 1,
    SCHC_BUF_TOO_SMALL = 2,
    SCHC_MODE_NOT_AVAILABLE = 3
} schc_status_t;

schc_status_t schc_service_init();

schc_status_t schc_service_compress(const uint8_t* in, size_t in_len,
                                    uint8_t* out, size_t out_cap,
                                    size_t* out_len);

/* ------------------------------------------------------------ */
/* Rule context getters                                         */
/* ------------------------------------------------------------ */
const uint8_t* schc_service_dev_ip(void);
const uint8_t* schc_service_app_ip(void);
uint16_t schc_service_dev_port(void);
uint16_t schc_service_app_port(void);
uint8_t  schc_service_hop_limit(void);
uint32_t schc_service_flow_label(void);
uint8_t  schc_service_coap_code(void);
uint16_t schc_service_coap_msg_id_base(void);
