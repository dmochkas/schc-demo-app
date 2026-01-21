#include "schc_demo_app/net/ipv6_udp_coap_builder.h"

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

    /* Pseudo-header: src and dst (16 bytes each) */
    for (int i = 0; i < 16; i += 2) {
        uint16_t w = (uint16_t)((src_ip[i] << 8) | src_ip[i + 1]);
        sum = sum16_add(sum, w);
    }
    for (int i = 0; i < 16; i += 2) {
        uint16_t w = (uint16_t)((dst_ip[i] << 8) | dst_ip[i + 1]);
        sum = sum16_add(sum, w);
    }

    /* Pseudo-header: UDP length (32-bit) */
    sum = sum16_add(sum, (uint16_t)((udp_len >> 16) & 0xFFFFu));
    sum = sum16_add(sum, (uint16_t)(udp_len & 0xFFFFu));

    /* Pseudo-header: next header (32-bit: 0x00000011 for UDP) */
    sum = sum16_add(sum, 0x0000);
    sum = sum16_add(sum, 0x0011);

    /* UDP header + payload (checksum field treated as zero) */
    for (size_t i = 0; i + 1 < udp_len; i += 2) {
        uint16_t w;
        if (i == 6) {
            w = 0x0000; /* checksum field */
        } else {
            w = (uint16_t)((udp[i] << 8) | udp[i + 1]);
        }
        sum = sum16_add(sum, w);
    }

    /* Odd length padding */
    if (udp_len & 1u) {
        uint16_t w = (uint16_t)(udp[udp_len - 1] << 8);
        sum = sum16_add(sum, w);
    }

    uint16_t csum = ones_complement(sum);
    if (csum == 0x0000) csum = 0xFFFF; /* per convention */
    return csum;
}

/* Write CoAP with exactly:
 *  - NON, TKL=0, Code provided
 *  - 2 options:
 *      Uri-Path "sensor"
 *      Uri-Path "data"
 *  - payload marker 0xFF + payload bytes
 */
static int write_fixed_coap_packet(uint8_t coap_code,
                                  uint16_t msg_id_base,
                                  uint8_t msg_id_lsb4,
                                  const uint8_t *payload, size_t payload_len,
                                  uint8_t *out, size_t out_cap,
                                  size_t *out_len)
{
    if (!out || !out_len) return -1;
    if (!payload && payload_len != 0) return -1;

    /* CoAP header:
     * Ver=1 (01), Type=NON (01), TKL=0 (0000) => 0b0101 0000 = 0x50
     */
    const uint8_t ver_type_tkl = 0x50;

    /* Message ID: keep upper 12 bits from base, last 4 bits dynamic */
    const uint16_t mid = (uint16_t)((msg_id_base & 0xFFF0u) | (uint16_t)(msg_id_lsb4 & 0x0Fu));

    /* Option 1: Uri-Path (11), value "sensor" (len 6)
     * first option => delta=11, length=6 => 0xB6
     */
    static const uint8_t uri_path_val_1[] = { 's','e','n','s','o','r' };
    const uint8_t uri_path_len_1 = (uint8_t)sizeof(uri_path_val_1);
    const uint8_t opt1_hdr = (uint8_t)((11u << 4) | (uri_path_len_1 & 0x0Fu)); /* 0xB6 */

    /* Option 2: Uri-Path (11 again), value "data" (len 4)
     * same option number => delta=0, length=4 => 0x04
     */
    static const uint8_t uri_path_val_2[] = { 'd','a','t','a' };
    const uint8_t uri_path_len_2 = (uint8_t)sizeof(uri_path_val_2);
    const uint8_t opt2_hdr = (uint8_t)((0u << 4) | (uri_path_len_2 & 0x0Fu)); /* 0x04 */

    const size_t needed =
        4 /* CoAP header */ +
        1 + uri_path_len_1 +
        1 + uri_path_len_2 +
        1 /* payload marker */ + payload_len;

    if (out_cap < needed) return -1;

    size_t w = 0;
    out[w++] = ver_type_tkl;
    out[w++] = coap_code;
    out[w++] = (uint8_t)(mid >> 8);
    out[w++] = (uint8_t)(mid & 0xFF);

    out[w++] = opt1_hdr;
    memcpy(&out[w], uri_path_val_1, uri_path_len_1);
    w += uri_path_len_1;

    out[w++] = opt2_hdr;
    memcpy(&out[w], uri_path_val_2, uri_path_len_2);
    w += uri_path_len_2;

    out[w++] = 0xFF;
    if (payload_len) {
        memcpy(&out[w], payload, payload_len);
        w += payload_len;
    }

    *out_len = w;
    return 0;
}

int build_ipv6_udp_coap_packet(const ipv6_udp_cfg_t *cfg,
                               uint32_t flow_lbl,
                               uint8_t coap_code,
                               uint16_t coap_msg_id_base,
                               uint8_t coap_msg_id_lsb4,
                               const uint8_t *payload, size_t payload_len,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len)
{
    if (!cfg || !out || !out_len) return -1;
    if (!payload && payload_len != 0) return -1;

    /* Build CoAP into a temporary buffer first */
    uint8_t coap_buf[256];
    size_t coap_len = 0;

    if (write_fixed_coap_packet(coap_code,
                                coap_msg_id_base,
                                coap_msg_id_lsb4,
                                payload, payload_len,
                                coap_buf, sizeof(coap_buf),
                                &coap_len) != 0) {
        return -1;
    }

    const size_t total_len = IPV6_HDR_LEN + UDP_HDR_LEN + coap_len;
    if (out_cap < total_len) return -1;

    /* ---------------- IPv6 header ---------------- */
    const uint8_t version = 6;
    const uint8_t tc = cfg->traffic_class;
    const uint32_t fl20 = (flow_lbl & 0x000FFFFFu);

    out[0] = (uint8_t)((version << 4) | (tc >> 4));
    out[1] = (uint8_t)((tc << 4) | ((fl20 >> 16) & 0x0Fu));
    out[2] = (uint8_t)((fl20 >> 8) & 0xFFu);
    out[3] = (uint8_t)(fl20 & 0xFFu);

    /* IPv6 payload length = UDP header + CoAP */
    const uint16_t ipv6_payload_len = (uint16_t)(UDP_HDR_LEN + coap_len);
    put_u16_be(&out[4], ipv6_payload_len);

    out[6] = cfg->next_header; /* 17 */
    out[7] = cfg->hop_limit;   /* 255 */

    memcpy(&out[8],  cfg->src_ip, 16);
    memcpy(&out[24], cfg->dst_ip, 16);

    /* ---------------- UDP header ---------------- */
    uint8_t *udp = &out[IPV6_HDR_LEN];

    put_u16_be(&udp[0], cfg->src_port);
    put_u16_be(&udp[2], cfg->dst_port);

    const uint16_t udp_len16 = (uint16_t)(UDP_HDR_LEN + coap_len);
    put_u16_be(&udp[4], udp_len16);

    udp[6] = 0x00;
    udp[7] = 0x00;

    /* ---------------- UDP payload (CoAP) ---------------- */
    memcpy(&out[IPV6_HDR_LEN + UDP_HDR_LEN], coap_buf, coap_len);

    /* ---------------- Compute UDP checksum (IPv6) ---------------- */
    const uint16_t csum = udp_checksum_ipv6(cfg->src_ip, cfg->dst_ip, udp, (size_t)udp_len16);
    udp[6] = (uint8_t)(csum >> 8);
    udp[7] = (uint8_t)(csum & 0xFFu);

    *out_len = total_len;
    return 0;
}

