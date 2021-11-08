#include "tcphdr.h"

Data TcpHdr::parseData(IpHdr* ipHdr, TcpHdr* tcpHdr) {
	Data res;
	res.size_ = ipHdr->len() - ipHdr->hl() * 4 - tcpHdr->off() * 4;
	if (res.size_ > 0)
		res.data_ = reinterpret_cast<u_char*>(tcpHdr) + tcpHdr->off() * 4;
	else
		res.data_ = nullptr;
	return res;
}