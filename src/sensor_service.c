#include "sensor_service.h"

#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <unistd.h>

#include "utils.h"

void sleep_gaussian(const double mean_ms) {
    const double sleep_stddev_ms = mean_ms * 0.1; // modest stddev
    double sampled_ms_d = gaussian_random(mean_ms, sleep_stddev_ms);
    if (sampled_ms_d < 1.0) sampled_ms_d = 1.0; // clamp to at least 1 ms
    unsigned long ms = (unsigned long) llround(sampled_ms_d);
    if (ms == 0) ms = 1; // ensure non-zero
    usleep(ms * 1000);
}

measure_status measure(sensor_data_t* data) {
    if (!data) return measure_status_ko;

    float t_min = 5.0f;
    float t_max = 15.0f;
    float t = t_min + (float)rand() / (float)RAND_MAX * (t_max - t_min); /* NOLINT */

    // pH: most plausible 6.5 - 8.5, but allow full 0-14 range with small chance of extremes
    float ph_min_common = 6.5f;
    float ph_max_common = 8.5f;
    float ph;
    if ((rand() % 100) < 95) { /* NOLINT */ // 95% of readings in common range
        ph = ph_min_common + (float)rand() / (float)RAND_MAX * (ph_max_common - ph_min_common); /* NOLINT */
    } else {
        ph = (float)rand() / (float)RAND_MAX * 14.0f; /* NOLINT */
    }

    // battery: simulate gradual decrease with some jitter
    uint8_t bat = (uint8_t)(rand() % 101); /* NOLINT */ // 0-100

    data->temp = t;
    data->pH = ph;
    data->bat = bat;

    return measure_status_ok;
}