#pragma once
#include "radiotaphdr.h"

#pragma pack(push, 1)
struct Dot11Hdr {
	uint8_t ver_:2;
	uint8_t type_:2;
	uint8_t subtype_:4;
	uint8_t flags_;
	uint16_t duration_;

	uint8_t typeSubtype() { return type_ << 4 | subtype_; }

	// type
	enum: uint8_t {
		Manage = 0,
		Control = 1,
		Data = 2
	};

	// typeSubtype
	enum: uint8_t {
		Beacon = 0x08,
		QosNull = 0x2C,
		Acknowledgement = 0x1D
	};
};
#pragma pack(pop)