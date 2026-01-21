#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <ahoi_serial/ahoi_defs.h>
#include <ahoi_serial/core.h>

#include "schc_demo_app/l2/l2.h"
#include "schc_demo_app/logger_helper.h"
#include "schc_demo_app/cli_helper.h"
#include "schc_demo_app/services/sensor_service.h"
#include "schc_demo_app/services/schc_service.h"


#include "schc_demo_app/net/ipv6_udp_builder.h"
#include "schc_demo_app/net/ipv6_udp_coap_builder.h"    /* new builder */

#ifndef SENSOR_SLEEP_SEC
#define SENSOR_SLEEP_SEC 3
#endif

const double SLEEP_MEAN_MS = SENSOR_SLEEP_SEC * 1000.0;

static void dump_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("\n=== %s (len=%zu) ===\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (len % 16 != 0)
        printf("\n");
}

static void init_net_cfg_from_schc(ipv6_udp_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    memcpy(cfg->src_ip, schc_service_dev_ip(), 16);
    memcpy(cfg->dst_ip, schc_service_app_ip(), 16);

    cfg->src_port = schc_service_dev_port();
    cfg->dst_port = schc_service_app_port();

    cfg->traffic_class = 0;
    cfg->next_header = 17;

    /* For exact byte recovery with  current rule: */
    cfg->hop_limit = schc_service_hop_limit();
}

int main(int argc, char *argv[])
{
    if (logger_init() != LOGGER_INIT_OK) {
        fprintf(stderr, "Logger initialization failed\n");
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "Logger initialized");

    srand((unsigned)time(NULL));

    uint8_t id_arg = 0x00;
    uint8_t key_arg[KEY_SIZE];
    char *port = NULL;
    int32_t baudrate;

    if (parse_cli_arguments(argc, argv, &id_arg, key_arg, KEY_SIZE, &port, &baudrate) != CLI_PARSE_OK) {
        zlog_error(error_cat, "Error parsing cli arguments");
        zlog_fini();
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "Cli arg parse OK");

    l2_set_id(id_arg);

#ifdef L2_AHOI_EXT
    l2_ahoi_set_port(port);
    l2_ahoi_set_baudrate(baudrate);
#endif

    if (l2_init() != L2_INIT_OK) {
        zlog_error(error_cat, "Layer 2 init failed");
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "Layer 2 init OK");

    if (schc_service_init() != SCHC_OK) {
        zlog_error(error_cat, "SCHC init failed");
        return EXIT_FAILURE;
    }
    zlog_info(ok_cat, "SCHC service init OK");

    static sensor_data_t sensor_data = {0};

    static ahoi_packet_t p = {0};
    p.dst = 0xff;
    p.type = 0x00;
    p.flags = 0x00;
    p.seq = 0;
    p.pl_size = 0;
    p.payload = NULL;

    static ipv6_udp_cfg_t net_cfg;
    init_net_cfg_from_schc(&net_cfg);

    uint32_t seq = 0;
    for (;;) {
        sleep_gaussian(SLEEP_MEAN_MS);

        zlog_info(ok_cat, "Sensing data...");
        (void)measure(&sensor_data);


        const uint32_t flow_label = schc_service_flow_label();

        static uint8_t ipv6udpcoap_pkt[256];
        size_t ipv6udpcoap_len = 0;

        /* CoAP parameters (must match SCHC rule expectations) */
        const uint8_t  coap_code     = schc_service_coap_code();
        const uint16_t mid_base      = schc_service_coap_msg_id_base();
        const uint8_t  mid_lsb4_dyn  = (uint8_t)(seq & 0x0Fu); /* dynamic last 4 bits */

        if (build_ipv6_udp_coap_packet(&net_cfg, flow_label,
                                       coap_code,
                                       mid_base,
                                       mid_lsb4_dyn,
                                       (const uint8_t *)&sensor_data, sizeof(sensor_data),
                                       ipv6udpcoap_pkt, sizeof(ipv6udpcoap_pkt),
                                       &ipv6udpcoap_len) != 0) {
            zlog_error(error_cat, "IPv6/UDP/CoAP packet build failed");
            seq++;
            continue;
        }

        dump_hex("IPv6+UDP+CoAP packet BEFORE SCHC", ipv6udpcoap_pkt, ipv6udpcoap_len);

        static uint8_t schc_buf[256];
        size_t schc_len = 0;

        if (schc_service_compress(ipv6udpcoap_pkt, ipv6udpcoap_len,
                                  schc_buf, sizeof(schc_buf),
                                  &schc_len) != SCHC_OK) {
            zlog_error(error_cat, "SCHC compress failed for seq=%u", seq);
            seq++;
            continue;
        }

        dump_hex("SCHC packet AFTER compression", schc_buf, schc_len);

        if (schc_len > MAX_PAYLOAD_SIZE) {
            zlog_error(error_cat, "Max payload size exceeded!");
            seq++;
            continue;
        }

        p.seq = seq;
        p.pl_size = (uint8_t)schc_len;
        p.payload = schc_buf;

        l2_send_prepare(&p);

        if (l2_send_run(p.payload, p.pl_size) != L2_SEND_OK) {
            zlog_error(error_cat, "Error sending packet %u", seq);
        }

        print_packet(&p);
        seq++;
    }
}
