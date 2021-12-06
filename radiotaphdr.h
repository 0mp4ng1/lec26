#pragma once
#include <stdint.h>
#include "mac.h"

#pragma pack(push, 1)
struct RadiotapHdr {
	uint8_t  ver_;
	uint8_t  pad_;
	uint16_t  len_;
	uint32_t  present_;
};
#pragma pack(pop)