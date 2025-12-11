#include <math.h>
#include <stdlib.h>

double gaussian_random(double mean, double stddev) {
    if (stddev <= 0.0) {
        return mean;
    }

    // Box–Muller
    double u1 = 0.0;
    double u2 = 0.0;
    do {
        u1 = (rand() + 1.0) / (RAND_MAX + 2.0); // avoid 0
        u2 = (rand() + 1.0) / (RAND_MAX + 2.0);
    } while (u1 <= 0.0 || u2 <= 0.0);

    double mag = sqrt(-2.0 * log(u1));
    double z0 = mag * cos(2.0 * M_PI * u2); // standard normal
    return mean + z0 * stddev;
}