#pragma once

#include <zlog.h>

typedef enum {
    LOGGER_INIT_OK, LOGGER_INIT_KO
} logger_status;

extern zlog_category_t* stat_cat;
extern zlog_category_t* tx_cat;
extern zlog_category_t* rx_cat;
extern zlog_category_t* ok_cat;
extern zlog_category_t* error_cat;

logger_status logger_init();