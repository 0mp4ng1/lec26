#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "ethHdr.h"
#include "ipHdr.h"
#include "tcpHdr.h"

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define IP2STR(a) (a)[0], (a)[1], (a)[2], (a)[3]
#define IPSTR "%u.%u.%u.%u"

int parse_Mac_Adr(const u_char*, char*, char*);
int parse_Ip_Adr(const u_char* packet, char*, char*);
int parse_Port_Num(const u_char* packet, int*, int*);

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	int pkt_cnt = 0;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		char src_mac_adr[30] ={0,}; 
		char dst_mac_adr[30] ={0,};
		char src_ip_adr[30] ={0,}; 
		char dst_ip_adr[30] ={0,};
		int src_port = 0;
		int dst_port = 0;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		pkt_cnt++;

		int eth2ip_offset = 14;
		int ip2tcp_offset = 0;
		int tcp2data_offset = 0;

		if(parse_Mac_Adr(packet, src_mac_adr, dst_mac_adr) == -1){
			continue;
		}
		packet += eth2ip_offset;

		ip2tcp_offset = parse_Ip_Adr(packet, src_ip_adr, dst_ip_adr);
		if(ip2tcp_offset == -1){
			continue;
		}
		packet += ip2tcp_offset;

		tcp2data_offset = parse_Port_Num(packet, &src_port, &dst_port);
		packet += tcp2data_offset;

		int offset_sum = eth2ip_offset + ip2tcp_offset + tcp2data_offset;

		printf("\n\n|--------------[PACKET No.%-3d]------------|\n",pkt_cnt);
		printf("|================[Ethernet]===============|\n");
		printf("| [SRC MAC ADDR] %s        |\n", src_mac_adr);
		printf("| [DST MAC ADDR] %s        |\n", dst_mac_adr);	
		printf("|                                         |\n");
		printf("|================[IPv4 ADDR]==============|\n");
		printf("| [SRC IP ADDR] %-20s      |\n", src_ip_adr);
		printf("| [DST IP ADDR] %-20s      |\n", dst_ip_adr);
		printf("|                                         |\n");
		printf("|================[TCP PORT]===============|\n");
		printf("| [SRC PORT NUM] %-5hu                    |\n", src_port);
		printf("| [DST PORT NUM] %-5hu                    |\n", dst_port);
		printf("|                                         |\n");
		printf("|==================[Data]=================|\n| ");
		for(int i=0;i<header->caplen - offset_sum;i++){
			if(i==8) break;
			printf("%#02x ",packet[i]);
		}
		printf("\n");
		printf("|-----------------------------------------|\n");

	}

	pcap_close(pcap);

	return 0;
}

int parse_Mac_Adr(const u_char* packet, char* src_mac_adr, char* des_mac_adr){
	struct EthHdr *eth;
	eth = (struct EthHdr *)packet;
	

	if(ntohs(eth->eth_type) != ETH_TYPE_IP){
		return -1;
	}

	sprintf(src_mac_adr, MACSTR, MAC2STR(eth->mac_src_adr));
	sprintf(des_mac_adr, MACSTR, MAC2STR(eth->mac_dst_adr));

	return 0;
}

int parse_Ip_Adr(const u_char* packet, char* src_ip_adr, char* des_ip_adr){
	struct IpHdr *ip;
	ip = (struct IpHdr *)packet;
	
	if(ip->ip_protocol != IP_TYPE_TCP){
		return -1;
	}
	
	sprintf(src_ip_adr, IPSTR, IP2STR(ip->ip_src_adr));
	sprintf(des_ip_adr, IPSTR, IP2STR(ip->ip_dst_adr));

	return ip->ip_hdr_len*4;
}

int parse_Port_Num(const u_char* packet, int* src_port, int* des_port){
	struct TcpHdr *tcp;
	tcp = (struct TcpHdr *)packet;
	
	*src_port = ntohs(tcp->src_port);
	*des_port = ntohs(tcp->dst_port);

	return tcp->tcp_data_offset*4;
}
