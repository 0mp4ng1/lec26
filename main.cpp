#include "headers.h"

#pragma pack(push, 1)
struct IpPacket final {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TcpPacket final{
    EthHdr eth_;
	IpHdr ip_;
	TcpHdr tcp_;
    char data[256];
};
#pragma pack(pop)

enum Protocol{
    NOT_IP_TCP,
    HTTP,
    HTTPS
};

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

//출처: https://wonillism.tistory.com/163
char *strnstr(const char *big, const char *little, size_t len)
{
	size_t llen;
	size_t blen;
	size_t i;

	if (!*little)
		return ((char *)big);
	llen = strlen(little);
	blen = strlen(big);
	i = 0;
	if (blen < llen || len < llen)
		return (0);
	while (i + llen <= len)
	{
		if (big[i] == *little && !strncmp(big + i, little, llen))
			return ((char *)big + i);
		i++;
	}
	return (0);
}

bool GetMyInfo(Mac* myMac, Ip* myIp, char* dev){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd<0){
		fprintf(stderr, "Fail Open Socket return %d\n",fd);
		return false;
	}
	ifr.ifr_addr.sa_family = AF_INET;

	memcpy(ifr.ifr_name, dev, IFNAMSIZ -1);

	if(!ioctl(fd, SIOCGIFHWADDR, &ifr))
		*myMac = Mac((uint8_t *)(ifr.ifr_hwaddr.sa_data));
    
    if(!ioctl(fd, SIOCGIFADDR, &ifr))
		*myIp = Ip(std::string(inet_ntoa(((struct sockaddr_in* )&ifr.ifr_addr)->sin_addr)));
	
	close(fd);
	return true;
}

bool checkIp(const u_char* packet){
    EthHdr *ethPacket = (struct EthHdr *)packet;
    // Check IP
    if(ethPacket->type() == EthHdr::Ip4)
        return true;
    else return false;
}

bool checkTcp(const u_char* packet){
    IpPacket *ipPacket = (struct IpPacket *)packet;
    // Check Tcp
    if(ipPacket->ip_.p() == IpHdr::Tcp)
        return true;
    else return false;
}

Protocol isOrgPkt(const u_char* packet, char* pattern){
    if(checkIp(packet)){
        if(checkTcp(packet)){
            TcpPacket *tcpPacket = (struct TcpPacket *)packet;
            int dataSize = tcpPacket->ip_.len() - tcpPacket->ip_.hl() * 4 - tcpPacket->tcp_.off() * 4;
            if(dataSize > 0){
                if(strnstr(tcpPacket->data, pattern, dataSize)){
                    if(tcpPacket->tcp_.dport() == 80)
                        return HTTP;
                    if(tcpPacket->tcp_.dport() == 443)
                        return HTTPS;
                }
            }

        }
    }
    return NOT_IP_TCP;
}

bool sendFwdBlkPkt(pcap_t* handle, const u_char* packet, uint32_t pktSize, Mac myMac){   
    u_char *fwdPkt_ = (u_char *)malloc(pktSize);
    memcpy(fwdPkt_, packet, pktSize);
    TcpPacket *orgPkt = (TcpPacket *)packet;
    TcpPacket *fwdPkt = (TcpPacket *)fwdPkt_;

    int dataSize = orgPkt->ip_.len() - orgPkt->ip_.hl() * 4 - orgPkt->tcp_.off() * 4;

    fwdPkt->eth_.smac_ = myMac;

    fwdPkt->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    fwdPkt->ip_.sum_ = htons(IpHdr::calcChecksum(&(fwdPkt->ip_)));
    
    fwdPkt->tcp_.seq_ = htonl(orgPkt->tcp_.seq() + dataSize);
    fwdPkt->tcp_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
    fwdPkt->tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
    fwdPkt->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(fwdPkt->ip_), &(fwdPkt->tcp_)));

    int res = pcap_sendpacket(handle, fwdPkt_, pktSize);
    free(fwdPkt_);
	if (res != 0){
        fprintf(stderr, "Send Forward Failed return %d error=%s\n", res, pcap_geterr(handle));
		return false;
    }

    return true;
}

bool sendBwdBlkPkt(pcap_t* handle, const u_char* packet, uint32_t pktSize, Protocol type, Mac myMac){
    char blockData[56] = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
    
    u_char *bwdPkt_ = (u_char *)malloc(pktSize);
    memcpy(bwdPkt_, packet, pktSize);
    TcpPacket *orgPkt = (TcpPacket *)packet;
    TcpPacket *bwdPkt = (TcpPacket *)bwdPkt_;

    int dataSize = orgPkt->ip_.len() - orgPkt->ip_.hl() * 4 - orgPkt->tcp_.off() * 4;

    bwdPkt->eth_.smac_ = myMac;
    bwdPkt->eth_.dmac_ = orgPkt->eth_.smac();

    bwdPkt->ip_.ttl_ = 128;
    bwdPkt->ip_.sip_ = orgPkt->ip_.dip_;
    bwdPkt->ip_.dip_ = orgPkt->ip_.sip_;
    
    bwdPkt->tcp_.sport_ = orgPkt->tcp_.dport_;
    bwdPkt->tcp_.dport_ = orgPkt->tcp_.sport_;
    bwdPkt->tcp_.seq_ = orgPkt->tcp_.ack_;
    bwdPkt->tcp_.ack_ = htonl(orgPkt->tcp_.seq() + dataSize);
    bwdPkt->tcp_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
    if(type == Protocol::HTTPS){
        bwdPkt->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
        bwdPkt->tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
    }
    if(type == Protocol::HTTP){
        bwdPkt->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr) + strlen(blockData));
        bwdPkt->tcp_.flags_ = TcpHdr::Fin | TcpHdr::Ack;
        memcpy(bwdPkt->data, blockData, strlen(blockData));
        pktSize += strlen(blockData);
    }
    bwdPkt->tcp_.flags_ &= ~TcpHdr::Syn;
    bwdPkt->ip_.sum_ = htons(IpHdr::calcChecksum(&(bwdPkt->ip_)));
    bwdPkt->tcp_.sum_ = htons(TcpHdr::calcChecksum(&(bwdPkt->ip_), &(bwdPkt->tcp_)));
    int res = pcap_sendpacket(handle, bwdPkt_, pktSize);

    free(bwdPkt_);
	if (res != 0){
        fprintf(stderr, "Send Backward Failed return %d error=%s\n", res, pcap_geterr(handle));
		return false;
    }
    return true;
}
    

bool block(pcap_t* handle, const u_char* orgPkt, uint32_t pktSize, Protocol type, Mac myMac){
    if(sendFwdBlkPkt(handle, orgPkt, pktSize, myMac))
        printf("Success : Send Forward Block Packet\n");
    else{
        printf("Failed : Send Forward Block Packet\n");
        return false;
    }

    if(sendBwdBlkPkt(handle, orgPkt, pktSize, type, myMac))
        printf("Success : Send Backward Block Packet\n");
    else{
        printf("Failed : Send Backward Block Packet\n");
        return false;
    }

    return false;



}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
    char* pattern = argv[2];


	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Mac myMac;
    Ip myIp;
    if (!GetMyInfo(&myMac, &myIp, dev))
    {
        printf("ERR: getMyMac()\n");
        pcap_close(handle);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        Protocol type = isOrgPkt(packet, pattern);

        if(type){
            if(type == Protocol::HTTP) printf("HTTP\n");
            if(type == Protocol::HTTPS) printf("HTTPS\n");
            if(block(handle, packet, header->caplen, type, myMac))
               printf("Block Success!!\n"); 
        }
    }
	

	pcap_close(handle);
}