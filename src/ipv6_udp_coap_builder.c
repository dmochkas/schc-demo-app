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

static uint16_t udp_checksum_ipv6(const uint8_t src_ip[16],
                                  const uint8_t dst_ip[16],
                                  const uint8_t *udp,
                                  size_t udp_len)
{
    uint32_t sum = 0;

    for (int i = 0; i < 16; i += 2) {
        sum = sum16_add(sum, (uint16_t)((src_ip[i] << 8) | src_ip[i + 1]));
    }
    for (int i = 0; i < 16; i += 2) {
        sum = sum16_add(sum, (uint16_t)((dst_ip[i] << 8) | dst_ip[i + 1]));
    }

    // UDP length (32-bit)
    sum = sum16_add(sum, (uint16_t)((udp_len >> 16) & 0xFFFFu));
    sum = sum16_add(sum, (uint16_t)(udp_len & 0xFFFFu));

    // Next header (32-bit): 0x00000011 for UDP
    sum = sum16_add(sum, 0x0000);
    sum = sum16_add(sum, 0x0011);

    // UDP header + payload (checksum field treated as zero)
    for (size_t i = 0; i + 1 < udp_len; i += 2) {
        uint16_t w;
        if (i == 6) w = 0x0000; // checksum field
        else        w = (uint16_t)((udp[i] << 8) | udp[i + 1]);
        sum = sum16_add(sum, w);
    }

    if (udp_len & 1u) {
        sum = sum16_add(sum, (uint16_t)(udp[udp_len - 1] << 8));
    }

    uint16_t csum = ones_complement(sum);
    if (csum == 0x0000) csum = 0xFFFF;
    return csum;
}

/**
 * CoAP options encoder for this fixed sequence:
 *  - Uri-Host (3)   = "localhost" (len 9)      => first option: delta=3, len=9 => 0x39
 *  - Uri-Port (7)   = 1234 (0x04D2) (len 2)    => delta=4, len=2 => 0x42
 *  - Uri-Path (11)  = "foo" (len 3)            => delta=4, len=3 => 0x43
 *  - Uri-Path (11)  = "bar" (len 3)            => delta=0, len=3 => 0x03
 *  - Uri-Query (15) = "db=db" (len 5)          => delta=4, len=5 => 0x45
 */
static size_t write_fixed_coap_options(uint8_t *dst, size_t cap)
{
    static const uint8_t host[] = {'l','o','c','a','l','h','o','s','t'};
    static const uint8_t path1[] = {'f','o','o'};
    static const uint8_t path2[] = {'b','a','r'};
    static const uint8_t query[] = {'d','b','=','d','b'};

    size_t need = 1 + sizeof(host)
                + 1 + 2
                + 1 + sizeof(path1)
                + 1 + sizeof(path2)
                + 1 + sizeof(query);

    if (cap < need) return 0;

    size_t o = 0;

    dst[o++] = 0x39; // delta=3 len=9
    memcpy(&dst[o], host, sizeof(host)); o += sizeof(host);

    dst[o++] = 0x42; // delta=4 len=2
    dst[o++] = 0x04; // 1234
    dst[o++] = 0xD2;

    dst[o++] = 0x43; // delta=4 len=3
    memcpy(&dst[o], path1, sizeof(path1)); o += sizeof(path1);

    dst[o++] = 0x03; // delta=0 len=3
    memcpy(&dst[o], path2, sizeof(path2)); o += sizeof(path2);

    dst[o++] = 0x45; // delta=4 len=5
    memcpy(&dst[o], query, sizeof(query)); o += sizeof(query);

    return o;
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

    // CoAP fixed: header(4) + options(fixed) + payload_marker(1) + payload
    uint8_t coap_opts[64];
    const size_t coap_opts_len = write_fixed_coap_options(coap_opts, sizeof(coap_opts));
    if (coap_opts_len == 0) return -1;

    const size_t coap_len = 4 + coap_opts_len + 1 + payload_len;

    const size_t total_len = IPV6_HDR_LEN + UDP_HDR_LEN + coap_len;
    if (out_cap < total_len) return -1;

    // ---------------- IPv6 header ----------------
    const uint8_t version = 6;
    const uint8_t tc = cfg->traffic_class;
    const uint32_t fl20 = (flow_lbl & 0x000FFFFFu);

    out[0] = (uint8_t)((version << 4) | (tc >> 4));
    out[1] = (uint8_t)((tc << 4) | ((fl20 >> 16) & 0x0Fu));
    out[2] = (uint8_t)((fl20 >> 8) & 0xFFu);
    out[3] = (uint8_t)(fl20 & 0xFFu);

    // IPv6 payload length = UDP header + CoAP(...)
    const uint16_t ipv6_payload_len = (uint16_t)(UDP_HDR_LEN + coap_len);
    put_u16_be(&out[4], ipv6_payload_len);

    out[6] = cfg->next_header; // 17
    out[7] = cfg->hop_limit;

    memcpy(&out[8],  cfg->src_ip, 16);
    memcpy(&out[24], cfg->dst_ip, 16);

    // ---------------- UDP header ----------------
    uint8_t *udp = &out[IPV6_HDR_LEN];

    put_u16_be(&udp[0], cfg->src_port);
    put_u16_be(&udp[2], cfg->dst_port);

    const uint16_t udp_len16 = (uint16_t)(UDP_HDR_LEN + coap_len);
    put_u16_be(&udp[4], udp_len16);

    udp[6] = 0x00;
    udp[7] = 0x00;

    // ---------------- CoAP ----------------
    uint8_t *coap = &out[IPV6_HDR_LEN + UDP_HDR_LEN];

    // CoAP first byte: Ver(2)=1 => 01, Type(2)=0 => 00, TKL(4)=0 => 0000
    // => 0b0100_0000 = 0x40
    coap[0] = 0x40;
    coap[1] = coap_code;

    // Message ID: keep MSB 12 bits from base, force LSB 4 bits dynamic
    const uint16_t msg_id = (uint16_t)((coap_msg_id_base & 0xFFF0u) | (coap_msg_id_lsb4 & 0x0Fu));
    put_u16_be(&coap[2], msg_id);

    size_t off = 4;
    memcpy(&coap[off], coap_opts, coap_opts_len);
    off += coap_opts_len;

    coap[off++] = 0xFF; // payload marker

    if (payload_len) {
        memcpy(&coap[off], payload, payload_len);
        off += payload_len;
    }

    // ---------------- UDP checksum ----------------
    const uint16_t csum = udp_checksum_ipv6(cfg->src_ip, cfg->dst_ip, udp, (size_t)udp_len16);
    udp[6] = (uint8_t)(csum >> 8);
    udp[7] = (uint8_t)(csum & 0xFFu);

    *out_len = total_len;
    return 0;
}
