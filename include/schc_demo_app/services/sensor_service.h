#pragma once

#include <stdint.h>

// responsible for waking up
// "performs" data sensing when woke up

typedef struct __attribute__((packed)) {
    float temp;
    float pH;
    uint8_t bat;
} sensor_data_t;

typedef enum {
    measure_status_ok, measure_status_ko
} measure_status;

void sleep_gaussian(double mean_ms);

measure_status measure(sensor_data_t* data);
