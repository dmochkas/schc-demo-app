#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <ahoi_serial/ahoi_defs.h>
#include <ahoi_serial/core.h>

#include "schc_demo_app/l2/l2.h"
#include "schc_demo_app/logger_helper.h"
#include "schc_demo_app/cli_helper.h"
#include "schc_demo_app/services/sensor_service.h"
#include "schc_demo_app/services/schc_service.h"

#ifndef SENSOR_SLEEP_SEC
#define SENSOR_SLEEP_SEC 3
#endif

const double SLEEP_MEAN_MS = SENSOR_SLEEP_SEC * 1000.0;

int main(int argc, char *argv[]) {
    if (logger_init() != LOGGER_INIT_OK) {
        fprintf(stderr, "Logger initialization failed\n");
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "Logger initialized");

    srand((unsigned) time(NULL));

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

    /* Initialize SCHC service (dummy mode: wrap payload into SCHC RuleID + residue) */
    if (schc_service_init(SCHC_MODE_DUMMY) != SCHC_OK) {
        zlog_error(error_cat, "SCHC init failed");
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "SCHC service init OK (DUMMY mode)");

    static sensor_data_t sensor_data = {0};

    static ahoi_packet_t p = {0};
    p.dst = 0xff;
    p.type = 0x00;
    p.flags = 0x00;
    p.seq = 0;

    /* We will send SCHC-compressed bytes, so do not pin p.payload to sensor_data permanently */
    p.pl_size = 0;
    p.payload = NULL;

    uint32_t seq = 0;
    for (;;) {
        sleep_gaussian(SLEEP_MEAN_MS);

        zlog_info(ok_cat, "Sensing data...");
        measure(&sensor_data);

        p.seq = seq;

        /* Input payload (current dummy bytes): raw sensor_data struct */
        const uint8_t *in_payload = (const uint8_t *) &sensor_data;
        const size_t in_len = sizeof(sensor_data);

        /* SCHC output buffer: must be >= in_len + 1 for dummy mode (RuleID + payload) */
        uint8_t schc_buf[256];
        size_t schc_len = 0;

        if (schc_service_compress(in_payload, in_len, schc_buf, sizeof(schc_buf), &schc_len) != SCHC_OK) {
            zlog_error(error_cat, "SCHC compress failed for seq=%u", seq);
            seq++;
            continue;
        }

        /* Prepare AHOI header, then send SCHC packet as the payload */
        p.pl_size = (uint8_t) schc_len;
        p.payload = schc_buf;

        l2_send_prepare(&p);

        if (l2_send_run(p.payload, p.pl_size) != L2_SEND_OK) {
            zlog_error(error_cat, "Error sending packet %u", seq);
        }

        /* Prints the packet header + payload pointer contents as handled by your AHOI tools */
        print_packet(&p);

        seq++;
    }
}
