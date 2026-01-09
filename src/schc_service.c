#include "schc_service.h"

#include <string.h>
#include <limits.h>
#include <stdbool.h>

// #include <rule.h>
// #include <parser.h>
// #include <compressor.h>
// #include <utils.h>

#include "logger_helper.h"

schc_status_t schc_service_compress(const uint8_t* in, size_t in_len,
                                    uint8_t* out, size_t out_cap,
                                    size_t* out_len) {
    if (!in || !out || !out_len) return SCHC_ERR;
    if (in_len > UINT16_MAX || out_cap > UINT16_MAX) return SCHC_ERR;

    bit_buffer_t bb;
    init_bit_buffer(&bb, out, (uint16_t)(out_cap * 8u));

    static rule_t ipv6_udp_rule;
    init_rule(&ipv6_udp_rule, IPV6_UDP_RULE_ID, STACK_IPV6_UDP, rule_fields_1);
    add_rule_field(&ipv6_udp_rule, &rule_field_00);
    add_rule_field(&ipv6_udp_rule, &rule_field_01);
    add_rule_field(&ipv6_udp_rule, &rule_field_02);
    add_rule_field(&ipv6_udp_rule, &rule_field_03);
    add_rule_field(&ipv6_udp_rule, &rule_field_04);
    add_rule_field(&ipv6_udp_rule, &rule_field_05);
    add_rule_field(&ipv6_udp_rule, &rule_field_06);
    add_rule_field(&ipv6_udp_rule, &rule_field_07);
    add_rule_field(&ipv6_udp_rule, &rule_field_08);
    add_rule_field(&ipv6_udp_rule, &rule_field_09);
    add_rule_field(&ipv6_udp_rule, &rule_field_10);
    add_rule_field(&ipv6_udp_rule, &rule_field_11);
    add_rule_field(&ipv6_udp_rule, &rule_field_12);
    add_rule_field(&ipv6_udp_rule, &rule_field_13);
#ifdef ZSTD_ENABLED
    add_rule_field(&ipv6_udp_rule, &rule_field_payload);
#endif

    // initialize the rules array.
    static rules_t rules;
    static rule_t *rule_array[NB_RULES];
    init_rules(&rules, rule_array, NO_COMP_RULE_ID);
    add_rule(&rules, &ipv6_udp_rule);

    return &rules;
}
