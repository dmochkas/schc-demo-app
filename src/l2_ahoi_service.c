#include "l2.h"

#include <string.h>
#include <stdbool.h>
#include <termios.h>

#include <ahoilib.h>

#include "../logger_helper.h"

static int g_ahoi_fd = -1;
static const char* port = NULL;
static int32_t baudrate = -1;
static uint8_t modem_id = 0x00;
static uint32_t modem_id_32 = 0x00;
static ahoi_packet_t staging_p = {0};

l2_init_status l2_init() {
    g_ahoi_fd = open_serial_port(port, baudrate);
    if (g_ahoi_fd == -1) {
        zlog_error(error_cat, "Error opening serial port");
        zlog_fini();
        return L2_INIT_ERROR;
    }

    tcflush(g_ahoi_fd, TCIFLUSH);
    set_ahoi_id(g_ahoi_fd, modem_id);
    // set_ahoi_sniff_mode(g_ahoi_fd, false);
    return L2_INIT_OK;
}

void l2_ahoi_set_port(const char* val) {
    port = val;
}

void l2_ahoi_set_baudrate(const int32_t val) {
    baudrate = val;
}

void l2_set_id(const uint32_t id) {
    modem_id = (uint8_t) id;
    modem_id_32 = id;
}

uint32_t* l2_get_id() {
    return &modem_id_32;
}

uint8_t* l2_get_id_byte() {
    return &modem_id;
}

void l2_send_prepare(const void* header) {
    memcpy(&staging_p, header, HEADER_SIZE - 1);
}

l2_send_status l2_send_run(const uint8_t* payload, const size_t size) {
    staging_p.pl_size = (uint8_t) size;
    staging_p.payload = payload;

    const packet_send_status ret = send_ahoi_data(g_ahoi_fd, &staging_p);
    if (ret == PACKET_SEND_KO) {
        return L2_SEND_KO;
    }

    return L2_SEND_OK;
}