#include "l2.h"

#include <termios.h>
#include "ahoilib.h"

#include "../logger_helper.h"

static int g_ahoi_fd = -1;
static const char* port = NULL;
static int32_t baudrate = -1;
static uint8_t modem_id = 0x00;

l2_init_status l2_init() {
    g_ahoi_fd = open_serial_port(port, baudrate);
    if (g_ahoi_fd == -1) {
        zlog_error(error_cat, "Error opening serial port");
        zlog_fini();
        return l2_init_error;
    }

    tcflush(g_ahoi_fd, TCIFLUSH);
    set_ahoi_id(g_ahoi_fd, modem_id);
    // set_ahoi_sniff_mode(g_ahoi_fd, false);
    return l2_init_ok;
}

void l2_ahoi_set_port(const char* val) {
    port = val;
}

void l2_ahoi_set_baudrate(const int32_t val) {
    baudrate = val;
}

void set_l2_id(const uint32_t id) {
    modem_id = (uint8_t) id;
}