#pragma once

#include <stddef.h>
#include <stdint.h>


typedef struct {
    uint8_t src_ip[16];
    uint8_t dst_ip[16];

    uint16_t src_port;
    uint16_t dst_port;


    uint8_t traffic_class; /* should be 0 */
    uint8_t next_header;   /* should be 17 */
    uint8_t hop_limit;     /* should be 255 */
} ipv6_udp_cfg_t;

/**
 * Build an IPv6(40) + UDP(8) + CoAP + payload packet.
 *
 * CoAP template (fixed by requirements):
 * - Ver=1
 * - Type=NON (1)
 * - TKL=0
 * - Code is provided (must match SCHC rule) => 0x02 (POST)
 * - Message ID = (base & 0xFFF0) | (msg_id_lsb4 & 0x0F)
 * - Options:
 *     Uri-Path: "sensor"   (option 11)   [ONLY OPTION]
 * - Payload marker 0xFF then payload bytes (sensor_data_t)
 *
 * UDP checksum is computed correctly over UDP header + (CoAP+payload).
 */
int build_ipv6_udp_coap_packet(const ipv6_udp_cfg_t *cfg,
                               uint32_t flow_lbl,
                               uint8_t coap_code,
                               uint16_t coap_msg_id_base,   /* upper 12 bits fixed */
                               uint8_t coap_msg_id_lsb4,    /* dynamic 4 bits */
                               const uint8_t *payload, size_t payload_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len);
