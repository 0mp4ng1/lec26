#pragma once
#include <stdint.h>
#include "mac.h"

#pragma pack(push, 1)
struct RadiotapHdr {
	uint8_t  ver_;
	uint8_t  pad_;
	uint16_t  len_;
	uint32_t  present_;
	uint8_t datarate_;
    uint8_t unknown_;
    uint16_t txflag_;
};
#pragma pack(pop)