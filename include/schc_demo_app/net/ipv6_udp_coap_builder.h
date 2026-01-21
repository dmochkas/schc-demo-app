#pragma once

#include <stddef.h>
#include <stdint.h>
#include "schc_demo_app/net/ipv6_udp_builder.h"

/**
 * Build an IPv6(40) + UDP(8) + CoAP + payload packet.
 *
 * CoAP template
 * - Ver=1, Type=0 (CON), TKL=0
 * - Code configurable (default - set in main)
 * - Message ID = (base & 0xFFF0) | (msg_id_lsb4 & 0x0F)
 * - Options (fixed):
 *     Uri-Host:  "localhost"  (option 3)
 *     Uri-Port:  1234         (option 7)
 *     Uri-Path:  "foo"        (option 11)
 *     Uri-Path:  "bar"        (option 11)
 *     Uri-Query: "db=db"      (option 15)
 * - Payload marker 0xFF then payload bytes ( sensor struct)
 *
 * UDP checksum is computed correctly over UDP header + (CoAP+payload).
 */
int build_ipv6_udp_coap_packet(const ipv6_udp_cfg_t *cfg,
                               uint32_t flow_lbl,
                               uint8_t coap_code,
                               uint16_t coap_msg_id_base,   // upper 12 bits fixed
                               uint8_t coap_msg_id_lsb4,    // dynamic 4 bits
                               const uint8_t *payload, size_t payload_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len);
