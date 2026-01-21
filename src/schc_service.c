#include "schc_service.h"

#include <string.h>
#include <stdbool.h>

#include <schc_sdk/fullsdknet.h>
#include <schc_sdk/schccomp.h>

#include "l2/l2.h"
#include "logger_helper.h"

#define NB_RULES 1
#define NO_COMP_RULE_ID 150
#define IPV6_UDP_COAP_RULE_ID 28

/* -------------------------------------------------------------------------- */
/* Network context                                                            */
/* -------------------------------------------------------------------------- */

static uint8_t dev_ip[16] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01
};

static uint8_t app_ip[16] = {
    0x20,0x01,0x0d,0xb8, 0x00,0x00,0x00,0x02,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x02
};

static uint8_t dev_port[2] = { 0x12, 0x34 };
static uint8_t app_port[2] = { 0x56, 0x78 };

static const uint8_t  k_ipv6_hop_limit  = 255;
static const uint32_t k_ipv6_flow_label = 0; /* 20-bit value */

/* -------------------------------------------------------------------------- */
/* CoAP context                                                               */
/* -------------------------------------------------------------------------- */

/* POST */
static const uint8_t  k_coap_code = 0x02;

/* Upper 12 bits fixed, last 4 bits dynamic (sent) */
static const uint16_t k_coap_msg_id_base = 0x3030;

static rules_t *g_rules = NULL;

static bool mocked_ext_compress(bit_buffer_t *output_bb_ptr, bit_string_t *input_bs_ptr)
{
    (void)output_bb_ptr;
    (void)input_bs_ptr;
    return true;
}

static bool mocked_ext_decompress(bit_buffer_t *p_out_data, bit_buffer_t *p_in_data)
{
    (void)p_out_data;
    (void)p_in_data;
    return true;
}

rules_t *tpl_get_template_rules(void)
{
    /* ===================== IPv6 / UDP / CoAP RULE ===================== */

    /* ---------- IPv6 ---------- */

    static uint8_t ipv6_version = 0x60;
    static target_value_t ipv6_version_tv = { TV_BIT_STRING, {{&ipv6_version, 0, 4}} };

    static uint8_t ipv6_tc = 0;
    static target_value_t ipv6_tc_tv = { TV_BIT_STRING, {{&ipv6_tc, 0, 8}} };

    static uint8_t ipv6_fl[] = {0,0,0};
    static target_value_t ipv6_fl_tv = { TV_BIT_STRING, {{ipv6_fl, 0, 20}} };

    static uint8_t ipv6_nh = 17;
    static target_value_t ipv6_nh_tv = { TV_BIT_STRING, {{&ipv6_nh, 0, 8}} };

    static uint8_t ipv6_hl = 255;
    static target_value_t ipv6_hl_tv = { TV_BIT_STRING, {{&ipv6_hl, 0, 8}} };

    static target_value_t dev_pref_tv = { TV_BIT_STRING, {{dev_ip, 0, 64}} };
    static target_value_t dev_iid_tv  = { TV_BIT_STRING, {{dev_ip + 8, 0, 64}} };
    static target_value_t app_pref_tv = { TV_BIT_STRING, {{app_ip, 0, 64}} };
    static target_value_t app_iid_tv  = { TV_BIT_STRING, {{app_ip + 8, 0, 64}} };

    /* ---------- UDP ---------- */

    static target_value_t dev_port_tv = { TV_BIT_STRING, {{dev_port, 0, 16}} };
    static target_value_t app_port_tv = { TV_BIT_STRING, {{app_port, 0, 16}} };

    /* ---------- CoAP fixed values ---------- */

    /* CoAP Version=1 => bits "01" in the 2 MSB bits */
    static uint8_t coap_version = 0x40; /* 0b01xxxxxx */
    static target_value_t coap_version_tv = { TV_BIT_STRING, {{&coap_version, 0, 2}} };

    /* CoAP Type=NON(1) => bits "01" in the 2 MSB bits */
    static uint8_t coap_type = 0x40; /* 0b01xxxxxx */
    static target_value_t coap_type_tv = { TV_BIT_STRING, {{&coap_type, 0, 2}} };

    /* TKL = 0 (4 bits) */
    static uint8_t coap_tkl = 0;
    static target_value_t coap_tkl_tv = { TV_BIT_STRING, {{&coap_tkl, 0, 4}} };

    /* Code = POST (0x02) */
    static uint8_t coap_code = k_coap_code;
    static target_value_t coap_code_tv = { TV_BIT_STRING, {{&coap_code, 0, 8}} };

    /* Message ID target value (LSB nibble will be dynamic) */
    static uint8_t coap_msg_id[2] = {
        (uint8_t)(k_coap_msg_id_base >> 8),
        (uint8_t)(k_coap_msg_id_base & 0xFFu)
    };
    static target_value_t coap_msg_id_tv = { TV_BIT_STRING, {{coap_msg_id, 0, 16}} };

    /* ONLY OPTIONS:
     *  - Uri-Path #1 = "sensor"
     *  - Uri-Path #2 = "data"
     */
    static uint8_t coap_uri_path_sensor[] = { 's','e','n','s','o','r' };
    static target_value_t coap_uri_path_sensor_tv = {
        TV_BIT_STRING, {{ coap_uri_path_sensor, 0, sizeof(coap_uri_path_sensor) * 8 }}
    };

    static uint8_t coap_uri_path_data[] = { 'd','a','t','a' };
    static target_value_t coap_uri_path_data_tv = {
        TV_BIT_STRING, {{ coap_uri_path_data, 0, sizeof(coap_uri_path_data) * 8 }}
    };

    /* ---------- Rule fields ---------- */

    static rule_field_t f0  = { FID_IPV6_VERSION,        1, DIR_BI, &ipv6_version_tv, 4,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f1  = { FID_IPV6_TRAFFIC_CLASS,  1, DIR_BI, &ipv6_tc_tv,      8,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f2  = { FID_IPV6_FLOW_LABEL,     1, DIR_BI, &ipv6_fl_tv,      20, MO_IGNORE, {0}, CDA_NOT_SENT };
    static rule_field_t f3  = { FID_IPV6_PAYLOAD_LENGTH, 1, DIR_BI, NULL,             16, MO_IGNORE, {0}, CDA_COMPUTE_LENGTH };
    static rule_field_t f4  = { FID_IPV6_NEXT_HEADER,    1, DIR_BI, &ipv6_nh_tv,      8,  MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f5  = { FID_IPV6_HOP_LIMIT,      1, DIR_BI, &ipv6_hl_tv,      8,  MO_IGNORE, {0}, CDA_NOT_SENT };
    static rule_field_t f6  = { FID_IPV6_PREFIX_DEV,     1, DIR_BI, &dev_pref_tv,     64, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f7  = { FID_IPV6_IID_DEV,        1, DIR_BI, &dev_iid_tv,      64, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f8  = { FID_IPV6_PREFIX_APP,     1, DIR_BI, &app_pref_tv,     64, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f9  = { FID_IPV6_IID_APP,        1, DIR_BI, &app_iid_tv,      64, MO_EQUAL,  {0}, CDA_NOT_SENT };

    static rule_field_t f10 = { FID_UDP_PORT_DEV,        1, DIR_BI, &dev_port_tv,     16, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f11 = { FID_UDP_PORT_APP,        1, DIR_BI, &app_port_tv,     16, MO_EQUAL,  {0}, CDA_NOT_SENT };
    static rule_field_t f12 = { FID_UDP_LENGTH,          1, DIR_BI, NULL,             16, MO_IGNORE, {0}, CDA_COMPUTE_LENGTH };
    static rule_field_t f13 = { FID_UDP_CHECKSUM,        1, DIR_BI, NULL,             16, MO_IGNORE, {0}, CDA_COMPUTE_CHECKSUM };

    static rule_field_t f14 = { FID_COAP_VERSION,        1, DIR_BI, &coap_version_tv, 2,  MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f15 = { FID_COAP_TYPE,           1, DIR_BI, &coap_type_tv,    2,  MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f16 = { FID_COAP_TOKEN_LENGTH,   1, DIR_BI, &coap_tkl_tv,     4,  MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f17 = { FID_COAP_CODE,           1, DIR_BI, &coap_code_tv,    8,  MO_EQUAL, {0}, CDA_NOT_SENT };

    /* Keep last 4 bits dynamic (send LSB 4 bits) */
    static rule_field_t f18 = { FID_COAP_MSG_ID,         1, DIR_BI, &coap_msg_id_tv,  16, MO_MSB,   {12}, CDA_LSB };

    /* Token is empty (TKL=0). */
    static rule_field_t f19 = { FID_COAP_TOKEN,          1, DIR_BI, NULL,             0xFFFF, MO_IGNORE, {0}, CDA_VALUE_SENT };

    /* Two Uri-Path options: positions 1 and 2 */
    static rule_field_t f20 = { FID_COAP_URI_PATH,       1, DIR_BI, &coap_uri_path_sensor_tv, 0, MO_EQUAL, {0}, CDA_NOT_SENT };
    static rule_field_t f21 = { FID_COAP_URI_PATH,       2, DIR_BI, &coap_uri_path_data_tv,   0, MO_EQUAL, {0}, CDA_NOT_SENT };

    static rule_field_t *ipv6udpcoap_fields[22];
    static rule_t ipv6udpcoap_rule;

    init_rule(&ipv6udpcoap_rule, IPV6_UDP_COAP_RULE_ID, STACK_IPV6_UDP_COAP, ipv6udpcoap_fields);

    add_rule_field(&ipv6udpcoap_rule,&f0);  add_rule_field(&ipv6udpcoap_rule,&f1);
    add_rule_field(&ipv6udpcoap_rule,&f2);  add_rule_field(&ipv6udpcoap_rule,&f3);
    add_rule_field(&ipv6udpcoap_rule,&f4);  add_rule_field(&ipv6udpcoap_rule,&f5);
    add_rule_field(&ipv6udpcoap_rule,&f6);  add_rule_field(&ipv6udpcoap_rule,&f7);
    add_rule_field(&ipv6udpcoap_rule,&f8);  add_rule_field(&ipv6udpcoap_rule,&f9);
    add_rule_field(&ipv6udpcoap_rule,&f10); add_rule_field(&ipv6udpcoap_rule,&f11);
    add_rule_field(&ipv6udpcoap_rule,&f12); add_rule_field(&ipv6udpcoap_rule,&f13);

    add_rule_field(&ipv6udpcoap_rule,&f14); add_rule_field(&ipv6udpcoap_rule,&f15);
    add_rule_field(&ipv6udpcoap_rule,&f16); add_rule_field(&ipv6udpcoap_rule,&f17);
    add_rule_field(&ipv6udpcoap_rule,&f18); add_rule_field(&ipv6udpcoap_rule,&f19);

    add_rule_field(&ipv6udpcoap_rule,&f20);
    add_rule_field(&ipv6udpcoap_rule,&f21);

    /* ===================== RULE SET ===================== */

    static rules_t rules;
    static rule_t *rule_array[NB_RULES];

    init_rules(&rules, rule_array, NO_COMP_RULE_ID);
    add_rule(&rules, &ipv6udpcoap_rule);

    return &rules;
}

schc_status_t schc_service_init(void)
{
    g_rules = tpl_get_template_rules();
    return SCHC_OK;
}

schc_status_t schc_service_compress(const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len)
{
    if (!in || !out || !out_len) return SCHC_ERR;
    if (in_len > UINT16_MAX || out_cap > UINT16_MAX) return SCHC_ERR;

    if (!g_rules) {
        zlog_error(error_cat, "SCHC is not initialized");
        return SCHC_ERR;
    }

    uint16_t comp_bits = 0;

    comp_callbacks_t cb = {0};
    cb.ext_compress   = mocked_ext_compress;
    cb.ext_decompress = mocked_ext_decompress;

    const comp_status_t st = schc_compress(
        g_rules,
        out,
        (uint16_t)out_cap,
        &comp_bits,
        (uint8_t *)in,
        (uint16_t)in_len,
        &cb
    );

    if (st == COMP_RULES_NOT_FOUND_ERR) {
        zlog_info(ok_cat, "SCHC rule not found, using no compression rule %d", NO_COMP_RULE_ID);
        out[0] = g_rules->default_rule_id; /* = NO_COMP_RULE_ID */
        memcpy(out + 1, in, in_len);
        *out_len = in_len + 1;
        return SCHC_OK;
    }

    if (st != COMP_SUCCESS) {
        zlog_error(error_cat, "SCHC compress failed: %d", st);
        return SCHC_ERR;
    }

    *out_len = (comp_bits + 7) / 8;
    return SCHC_OK;
}

/* -------------------------------------------------------------------------- */
/* Getters for main.c                                                         */
/* -------------------------------------------------------------------------- */

const uint8_t* schc_service_dev_ip(void) { return dev_ip; }
const uint8_t* schc_service_app_ip(void) { return app_ip; }

uint16_t schc_service_dev_port(void) {
    return (uint16_t)((dev_port[0] << 8) | dev_port[1]);
}

uint16_t schc_service_app_port(void) {
    return (uint16_t)((app_port[0] << 8) | app_port[1]);
}

uint8_t schc_service_hop_limit(void) { return k_ipv6_hop_limit; }
uint32_t schc_service_flow_label(void) { return k_ipv6_flow_label; }
uint8_t schc_service_coap_code(void) { return k_coap_code; }
uint16_t schc_service_coap_msg_id_base(void) { return k_coap_msg_id_base; }
