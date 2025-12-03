
#include "ahoilib.h"

int main() {
    ahoi_packet_t p = {0};
    p.src = 0x1;
    p.dst = 0xff;

    print_packet(&p);
    return 0;
}