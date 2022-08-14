// btol.cpp
#include "btol.h"
#include <stdint.h>

uint32_t btol(uint32_t n){
    uint32_t ret = 0;
    ret |= (n & 0x000000ff) << 24;
    ret |= (n & 0x0000ff00) << 8;
    ret |= (n & 0x00ff0000) >> 8;
    ret |= (n & 0xff000000) >> 24;

    return ret;
}
