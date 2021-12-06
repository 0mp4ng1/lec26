#pragma once
#include "dot11hdr.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	uint8_t frag_:4;
	uint16_t seq_:12;

	Mac ra() { return addr1_;}
	Mac da() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr3_; }

	struct __attribute__((packed)) Fix {
		uint64_t  timestamp_; // microsecond
		uint16_t beaconInterval_; // millisecond
		uint16_t capabilities_;
	} fix_;

    struct Tag {
		uint8_t num_;
		uint8_t len_;
        char essid[256];
	};
	Tag* tag() {
		char* p = (char*)(this);
		p += sizeof(BeaconHdr);
		return (Tag*)(p);
	}
};

#pragma pack(pop)