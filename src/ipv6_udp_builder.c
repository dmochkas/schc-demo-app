#include "schc_demo_app/net/ipv6_udp_builder.h"

#include <string.h>

#define IPV6_HDR_LEN 40
#define UDP_HDR_LEN  8

static inline void put_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static inline uint32_t sum16_add(uint32_t sum, uint16_t v) {
    sum += v;
    return (sum & 0xFFFFu) + (sum >> 16);
}

static inline uint16_t ones_complement(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

/**
 * UDP checksum for IPv6 (pseudo-header + UDP header+payload).
 * Assumes udp points to UDP header start (8 bytes) followed by payload.
 * The UDP checksum field must be treated as 0 while computing.
 */
static uint16_t udp_checksum_ipv6(const uint8_t src_ip[16],
                                  const uint8_t dst_ip[16],
                                  const uint8_t *udp,
                                  size_t udp_len)
{
    uint32_t sum = 0;

    // Pseudo-header: src and dst (16 bytes each)
    for (int i = 0; i < 16; i += 2) {
        uint16_t w = (uint16_t)((src_ip[i] << 8) | src_ip[i + 1]);
        sum = sum16_add(sum, w);
    }
    for (int i = 0; i < 16; i += 2) {
        uint16_t w = (uint16_t)((dst_ip[i] << 8) | dst_ip[i + 1]);
        sum = sum16_add(sum, w);
    }

    // Pseudo-header: UDP length (32-bit)
    sum = sum16_add(sum, (uint16_t)((udp_len >> 16) & 0xFFFFu));
    sum = sum16_add(sum, (uint16_t)(udp_len & 0xFFFFu));

    // Pseudo-header: next header (32-bit: 0x00000011)
    sum = sum16_add(sum, 0x0000);
    sum = sum16_add(sum, 0x0011);

    // UDP header + payload (checksum field treated as zero)
    for (size_t i = 0; i + 1 < udp_len; i += 2) {
        uint16_t w;
        if (i == 6) {
            // checksum field
            w = 0x0000;
        } else {
            w = (uint16_t)((udp[i] << 8) | udp[i + 1]);
        }
        sum = sum16_add(sum, w);
    }

    // Odd length padding
    if (udp_len & 1u) {
        uint16_t w = (uint16_t)(udp[udp_len - 1] << 8);
        sum = sum16_add(sum, w);
    }

    uint16_t csum = ones_complement(sum);
    if (csum == 0x0000) csum = 0xFFFF; // per convention

    return csum;
}

int build_ipv6_udp_packet(const ipv6_udp_cfg_t *cfg,
                          uint32_t flow_lbl,
                          const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap,
                          size_t *out_len)
{
    if (!cfg || !out || !out_len) return -1;
    if (!payload && payload_len != 0) return -1;

    const size_t total_len = IPV6_HDR_LEN + UDP_HDR_LEN + payload_len;
    if (out_cap < total_len) return -1;

    // ---------------- IPv6 header ----------------
    const uint8_t version = 6;
    const uint8_t tc = cfg->traffic_class;

    // Only low 20 bits used
    const uint32_t fl20 = (flow_lbl & 0x000FFFFFu);

    // Version(4) | TC(8) | FlowLabel(20)
    out[0] = (uint8_t)((version << 4) | (tc >> 4));
    out[1] = (uint8_t)((tc << 4) | ((fl20 >> 16) & 0x0Fu));
    out[2] = (uint8_t)((fl20 >> 8) & 0xFFu);
    out[3] = (uint8_t)(fl20 & 0xFFu);

    // Payload length: UDP header + payload
    const uint16_t ipv6_payload_len = (uint16_t)(UDP_HDR_LEN + payload_len);
    put_u16_be(&out[4], ipv6_payload_len);

    // Next header + Hop limit
    out[6] = cfg->next_header; // 17
    out[7] = cfg->hop_limit;   // 255 for exact recovery with your rule

    // Addresses
    memcpy(&out[8],  cfg->src_ip, 16);
    memcpy(&out[24], cfg->dst_ip, 16);

    // ---------------- UDP header ----------------
    uint8_t *udp = &out[IPV6_HDR_LEN];

    put_u16_be(&udp[0], cfg->src_port);
    put_u16_be(&udp[2], cfg->dst_port);

    const uint16_t udp_len16 = (uint16_t)(UDP_HDR_LEN + payload_len);
    put_u16_be(&udp[4], udp_len16);

    // checksum initially zero for computation
    udp[6] = 0x00;
    udp[7] = 0x00;

    // ---------------- Payload ----------------
    if (payload_len) {
        memcpy(&out[IPV6_HDR_LEN + UDP_HDR_LEN], payload, payload_len);
    }

    // ---------------- Compute UDP checksum (IPv6) ----------------
    const uint16_t csum = udp_checksum_ipv6(cfg->src_ip, cfg->dst_ip, udp, (size_t)udp_len16);
    udp[6] = (uint8_t)(csum >> 8);
    udp[7] = (uint8_t)(csum & 0xFFu);

    *out_len = total_len;
    return 0;
}
