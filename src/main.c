#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <ahoi_serial/ahoi_defs.h>
#include <ahoi_serial/core.h>

#include "schc_demo_app/l2/l2.h"
#include "schc_demo_app/logger_helper.h"
#include "schc_demo_app/cli_helper.h"
#include "schc_demo_app/services/sensor_service.h"

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
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "Layer 2 init OK");

    static sensor_data_t sensor_data = {0};

    static ahoi_packet_t p = {0};
    p.dst = 0xff;
    p.type = 0x00;
    p.flags = 0x00;
    p.pl_size = sizeof(sensor_data);
    p.payload = (uint8_t*) &sensor_data;

    uint32_t seq = 0;
    for (;;) {
        sleep_gaussian(SLEEP_MEAN_MS);

        zlog_info(ok_cat, "Sensing data...");
        measure(&sensor_data);

        p.seq = seq;

        l2_send_prepare(&p);
        if (l2_send_run(p.payload, p.pl_size) != L2_SEND_OK) {
            zlog_error(error_cat, "Error sending packet %d", seq);
        }
        print_packet(&p);
        seq++;
    }
    return 0;
}