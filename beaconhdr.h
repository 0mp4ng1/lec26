#pragma once
#include "dot11hdr.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	uint8_t frag_:4;
	uint16_t seq_:12;
	uint16_t fix_;

	Mac ra() { return addr1_;}
	Mac da() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr3_; }
};

#pragma pack(pop)