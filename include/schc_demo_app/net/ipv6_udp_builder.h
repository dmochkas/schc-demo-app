#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t src_ip[16];
    uint8_t dst_ip[16];

    uint16_t src_port;
    uint16_t dst_port;

    // Must match the rule if MO_EQUAL / NOT_SENT
    uint8_t traffic_class; // should be 0
    uint8_t next_header;   // should be 17
    uint8_t hop_limit;     // should be 255
} ipv6_udp_cfg_t;

/**
 * Build an IPv6(40) + UDP(8) + payload packet.
 * - Writes correct IPv6 payload length and UDP length
 * - Computes UDP checksum (IPv6 pseudo-header)
 *
 * For byte-for-byte recovery with  current rule:
 *   flow_lbl MUST be 0 and cfg->hop_limit MUST be 255.
 */
int build_ipv6_udp_packet(const ipv6_udp_cfg_t *cfg,
                          uint32_t flow_lbl,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap,
                          size_t *out_len);
