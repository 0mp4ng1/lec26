#include "iphdr.h"


uint16_t IpHdr::calcChecksum(IpHdr* ipHdr) {
	uint32_t res = 0;
	uint16_t *p;

	// Add ipHdr buffer as array of uint16_t
	p = reinterpret_cast<uint16_t*>(ipHdr);
	for (int i = 0; i < int(sizeof(IpHdr)) / 2; i++) {
		res += ntohs(*p);
		p++;
	}

	// Do not consider padding because ip header length is always multilpe of 2.

	// Decrease checksum from sum
	res -= ipHdr->sum();

	// Recalculate sum
	while (res >> 16) {
		res = (res & 0xFFFF) + (res >> 16);
	}
	res = ~res;

	return uint16_t(res);
}

uint16_t IpHdr::recalcChecksum(uint16_t oldChecksum, uint16_t oldValue, uint16_t newValue) {
	uint32_t res = oldValue + (~newValue & 0xFFFF);
	res += oldChecksum;
	res = (res & 0xFFFF) + (res >> 16);
	return uint16_t(res + (res >> 16));
}

uint16_t IpHdr::recalcChecksum(uint16_t oldChecksum, uint32_t oldValue, uint32_t newValue) {
	uint16_t oldValue16;
	uint16_t newValue16;
	uint16_t res;

	oldValue16 = (oldValue & 0xFFFF0000) >> 16;
	newValue16 = (newValue & 0xFFFF0000) >> 16;
	res = recalcChecksum(oldChecksum, oldValue16, newValue16);

	oldValue16 = oldValue & 0x0000FFFF;
	newValue16 = newValue & 0x0000FFFF;
	res = recalcChecksum(res, oldValue16, newValue16);

	return res;
}
