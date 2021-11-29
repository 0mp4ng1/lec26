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
};
#pragma pack(pop)

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

bool isOrgPkt(const u_char* packet, char* pattern){
    if(checkIp(packet)){
        if(checkTcp(packet)){
            TcpPacket *tcpPacket = (struct TcpPacket *)packet;
            Data data = TcpHdr::parseData(&(tcpPacket->ip_), &(tcpPacket->tcp_));
            printf("it's tcp\n");
            if(data.size_ > 0){
                if(strnstr(reinterpret_cast<const char*>(data.data_), pattern, data.size_))
                    return true;
            }
        }
    }
    return false;
}

bool sendFwdBlkPkt(pcap_t* handle, const u_char* orgPkt, uint32_t pktSize, Mac myMac){
    u_char *fwdPkt_ = (u_char *)malloc(pktSize);
    memcpy(fwdPkt_, orgPkt, pktSize);
    TcpPacket *fwdPkt = (TcpPacket *)fwdPkt_;
    fwdPkt->eth_.smac_ = myMac;

    fwdPkt->ip_.len_ = htons(sizeof(struct IpHdr) + sizeof(struct TcpHdr));
    fwdPkt->ip_.ttl_ = 128;
    return true;
}
    

bool block(pcap_t* handle, const u_char* orgPkt, uint32_t pktSize, Mac myMac){
    // // Check Fin
    // if(orgPkt->tcp_.flags() & TcpHdr::Fin)
    //     return false;
    
    // // Check Rst
    // if(orgPkt->tcp_.flags() & TcpHdr::Rst)
    //     return false;

    // uint32_t seq = orgPkt->tcp_.seq();
    // uint32_t ack = orgPkt->tcp_.ack();
    // uint32_t newSeq = seq + orgPkt->data_.size_;

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

        if(isOrgPkt(packet, pattern)){
            printf("found\n");
            if(block(handle, packet, header->caplen, myMac)){
                printf("hi\n");
                
            }

        }

    }
	

	pcap_close(handle);
}