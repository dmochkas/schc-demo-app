#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <ahoi_serial/ahoi_defs.h>

#include "schc_demo_app/l2/l2.h"
#include "schc_demo_app/logger_helper.h"
#include "schc_demo_app/cli_helper.h"
#include "schc_demo_app/services/sensor_service.h"

#ifndef MODEM_ID
#define MODEM_ID 0x05
#endif

#ifndef SENSOR_SLEEP_SEC
#define SENSOR_SLEEP_SEC 3
#endif

const double SLEEP_MEAN_MS = SENSOR_SLEEP_SEC * 1000.0;
sensor_data_t sensor_data = {0};

int main(int argc, char *argv[]) {
    if (logger_init() != LOGGER_INIT_OK) {
        fprintf(stderr, "Logger initialization failed\n");
        return EXIT_FAILURE;
    }

    zlog_info(ok_cat, "Logger initialized");

    srand((unsigned)time(NULL));

    // ahoi_packet_t p = {0};
    // p.src = 0x1;
    // p.dst = 0xff;
    //
    // print_packet(&p);

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

    set_l2_id(id_arg);

#ifdef L2_AHOI_EXT
    l2_ahoi_set_port(port);
    l2_ahoi_set_baudrate(baudrate);
#endif

    if (l2_init() != l2_init_ok) {
        return EXIT_FAILURE;
    }

    for (;;) {
        sleep_gaussian(SLEEP_MEAN_MS);

        printf("Woke up!\n");
        measure(&sensor_data);
    }
    return 0;
}