#include "schc_service.h"

#include <string.h>
#include <limits.h>
#include <stdbool.h>

#include "logger_helper.h"

#define NB_RULES 1
#define NO_COMP_RULE_ID 150
#define IPV6_UDP_RULE_ID 28

rules_t *tpl_get_template_rules(void) {
    // IPV6 layer.
    // Version.
    static uint8_t ipv6_version = 0x60; // Only 4 MSB bits are used.
    static target_value_t ipv6_version_tv = {
        TV_BIT_STRING,
        {{&ipv6_version, 0, 4}}
    };
    // Traffic Class.
    static uint8_t ipv6_traffic_class = 0;
    static target_value_t ipv6_traffic_class_tv = {
        TV_BIT_STRING,
        {{&ipv6_traffic_class, 0, 8}}
    };
    //  Flow Label.
    static uint8_t ipv6_flow_label[] = {
        0x00, 0x00,
        0x00
    }; // Only 20 MSB bits are used.
    static target_value_t ipv6_flow_label_tv = {
        TV_BIT_STRING,
        {{ipv6_flow_label, 0, 20}}
    };
    // Next Header for UDP.
    static uint8_t ipv6_next_header_udp = 17; // For UDP.
    static target_value_t ipv6_next_header_udp_tv = {
        TV_BIT_STRING, {{&ipv6_next_header_udp, 0, 8}}
    };

    // Hop Limit.
    static uint8_t ipv6_hop_limit = 255;
    static target_value_t ipv6_hop_limit_tv = {
        TV_BIT_STRING,
        {{&ipv6_hop_limit, 0, 8}}
    };
    // Device Prefix.
    static target_value_t ipv6_prefix_dev_tv = {TV_BIT_STRING, {{dev_ip, 0, 64}}};
    // Device IID.
    static target_value_t ipv6_iid_dev_tv = {
        TV_BIT_STRING,
        {{dev_ip + 8, 0, 64}}
    };
    // Remote app prefix.
    static target_value_t ipv6_prefix_app_tv = {TV_BIT_STRING, {{app_ip, 0, 64}}};
    // Remote app IID.
    static target_value_t ipv6_iid_app_tv = {
        TV_BIT_STRING,
        {{app_ip + 8, 0, 64}}
    };
    // UDP Device port.
    static target_value_t udp_port_dev_tv = {TV_BIT_STRING, {{dev_port, 0, 16}}};
    // UDP Application port.
    static target_value_t udp_port_app_tv = {TV_BIT_STRING, {{app_port, 0, 16}}};

    // Rule entry definitions for IPv6 layer.
    static rule_field_t rule_field_00 = {
        FID_IPV6_VERSION, 1, DIR_BI, &ipv6_version_tv, 4,
        MO_EQUAL, {0}, CDA_NOT_SENT
    };
    static rule_field_t rule_field_01 = {
        FID_IPV6_TRAFFIC_CLASS,
        1,
        DIR_BI,
        &ipv6_traffic_class_tv,
        8,
        MO_EQUAL,
        {0},
        CDA_NOT_SENT
    };
    static rule_field_t rule_field_02 = {
        FID_IPV6_FLOW_LABEL, 1, DIR_BI, &ipv6_flow_label_tv, 20,
        MO_IGNORE, {0}, CDA_NOT_SENT
    };
    static rule_field_t rule_field_03 = {
        FID_IPV6_PAYLOAD_LENGTH, 1, DIR_BI, NULL, 16, MO_IGNORE, {0},
        CDA_COMPUTE_LENGTH
    };
    static rule_field_t rule_field_04 = {
        FID_IPV6_NEXT_HEADER,
        1,
        DIR_BI,
        &ipv6_next_header_udp_tv,
        8,
        MO_EQUAL,
        {0},
        CDA_NOT_SENT
    };
    static rule_field_t rule_field_05 = {
        FID_IPV6_HOP_LIMIT, 1, DIR_BI, &ipv6_hop_limit_tv, 8,
        MO_IGNORE, {0}, CDA_NOT_SENT
    };

    // IPv6 Device Prefix.
    static rule_field_t rule_field_06 = {
        FID_IPV6_PREFIX_DEV, 1, DIR_BI, &ipv6_prefix_dev_tv, 64, MO_EQUAL, {0},
        CDA_NOT_SENT
    };

    // IPv6 Device IID.
    static rule_field_t rule_field_07 = {
        FID_IPV6_IID_DEV, 1, DIR_BI, &ipv6_iid_dev_tv, 64,
        MO_EQUAL, {0}, CDA_NOT_SENT
    };

    // IPv6 Application Prefix.
    static rule_field_t rule_field_08 = {
        FID_IPV6_PREFIX_APP, 1, DIR_BI, &ipv6_prefix_app_tv, 64, MO_EQUAL, {0},
        CDA_NOT_SENT
    };

    // IPv6 Application IID.
    static rule_field_t rule_field_09 = {
        FID_IPV6_IID_APP, 1, DIR_BI, &ipv6_iid_app_tv, 64,
        MO_EQUAL, {0}, CDA_NOT_SENT
    };

    // Rule entry definitions for UDP layer.
    // UDP Device Port.
    static rule_field_t rule_field_10 = {
        FID_UDP_PORT_DEV, 1, DIR_BI, &udp_port_dev_tv, 16,
        MO_EQUAL, {0}, CDA_NOT_SENT
    };

    // UDP Application Port.
    static rule_field_t rule_field_11 = {
        FID_UDP_PORT_APP, 1, DIR_BI, &udp_port_app_tv, 16,
        MO_EQUAL, {0}, CDA_NOT_SENT
    };

    // UDP Length.
    static rule_field_t rule_field_12 = {
        FID_UDP_LENGTH, 1, DIR_BI, NULL, 16, MO_IGNORE, {0}, CDA_COMPUTE_LENGTH
    };

    // UDP Checksum.
    static rule_field_t rule_field_13 = {
        FID_UDP_CHECKSUM, 1, DIR_BI, NULL, 16, MO_IGNORE, {0},
        CDA_COMPUTE_CHECKSUM
    };

    static rule_field_t *rule_fields_1[14];

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

    // initialize the rules array.
    static rules_t rules;
    static rule_t *rule_array[NB_RULES];
    init_rules(&rules, rule_array, NO_COMP_RULE_ID);
    add_rule(&rules, &ipv6_udp_rule);

    return &rules;
}

schc_status_t schc_service_compress(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len) {
    rules_t *rules = tpl_get_template_rules();

    // TODO: Use rules and schc_compress to compress the input

    //schc_compress();
}
