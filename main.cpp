
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <string>
#include <unordered_set>
#include <fstream>

#include "iphdr.h"
#include "tcphdr.h"

#include <libnetfilter_queue/libnetfilter_queue.h>



std::string httpMethods[9] = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
// unordered_set은 Hash를 이용하여 원소 탐색을 하기 때문에 속도가 set에 비해 빠름
std::unordered_set <std::string> blockHosts;

#pragma pack(push, 1)
struct IpTcpPacket final{
	IpHdr ip_;
	TcpHdr tcp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		//  printf("hw_protocol=0x%04x hook=%u id=%u ",
		// 	ntohs(ph->hw_protocol), ph->hook, id);
	}

	// hwph = nfq_get_packet_hw(tb);
	// if (hwph) {
	// 	int i, hlen = ntohs(hwph->hw_addrlen);

	// 	printf("hw_src_addr=");
	// 	for (i = 0; i < hlen-1; i++)
	// 		printf("%02x:", hwph->hw_addr[i]);
	// 	printf("%02x ", hwph->hw_addr[hlen-1]);
	// }

	// mark = nfq_get_nfmark(tb);
	// if (mark)
	// 	printf("mark=%u ", mark);

	// ifi = nfq_get_indev(tb);
	// if (ifi)
	// 	printf("indev=%u ", ifi);

	// ifi = nfq_get_outdev(tb);
	// if (ifi)
	// 	printf("outdev=%u ", ifi);
	// ifi = nfq_get_physindev(tb);
	// if (ifi)
	// 	printf("physindev=%u ", ifi);

	// ifi = nfq_get_physoutdev(tb);
	// if (ifi)
	// 	printf("physoutdev=%u ", ifi);

	// if (nfq_get_uid(tb, &uid))
	// 	printf("uid=%u ", uid);

	// if (nfq_get_gid(tb, &gid))
	// 	printf("gid=%u ", gid);

	// ret = nfq_get_secctx(tb, &secdata);
	// if (ret > 0)
	// 	printf("secctx=\"%.*s\" ", ret, secdata);

	// ret = nfq_get_payload(tb, &data);
	// if (ret >= 0)
	// 	printf("payload_len=%d ", ret);

	// fputc('\n', stdout);

	return id;
}

bool checkTcp(unsigned char * packet){
	IpHdr *ipPacket = (struct IpHdr *)packet;
	if (ipPacket->p() == IpHdr::Tcp)
		return true;
	else
		return false;
}

bool checkHttp(IpTcpPacket * tcpPacket){
	if (tcpPacket->tcp_.sport() == 80 || tcpPacket->tcp_.dport() == 80)
		return true;
	else
		return false;
}

bool checkMethod(Data data){
	for(auto method : httpMethods){
		if(!strncmp(reinterpret_cast<const char*>(data.data_), method.c_str(), method.length()))
			return true;
	}
	return false;
}

std::string parseHost(Data data){
	bool isHost = false;
	const char* key = "Host:";
	std::string host;
	int idx = 0;
	while(idx < data.size_){
		if(!memcmp(key, data.data_ + idx, strlen(key))){
			isHost = true;
			break;
		}
		idx++;
	}

	idx = idx + 5;

	if(isHost){
		while(data.data_[idx] != '\r' and data.data_[idx+1] != '\n'){
			if(data.data_[idx] != ' '){
				host.append(1, data.data_[idx]);
			}
			idx++;
		}
	}
	return host;
}

bool checkDrop(unsigned char *packet, int ret){
	if(ret>=0){
		if(checkTcp(packet)){
			IpTcpPacket *tcpPacket = (struct IpTcpPacket *)packet;
			if(checkHttp(tcpPacket)){
				Data data = TcpHdr::parseData(&(tcpPacket->ip_), &(tcpPacket->tcp_));
				//printf("%d\n",data.size_);
				if(data.size_ > 0){
					if(checkMethod(data)){
						std::string host = parseHost(data);
						printf("Host : %s\n",host.c_str());
						if(blockHosts.find(host)!=blockHosts.end()){
							printf("!!!!Blocked!!!!\n");
							return true;
						}
					}			
				}
			}
		}
	}
	return false;

}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	int ret;
	unsigned char *packet;
	uint32_t id = print_pkt(nfa);
	//printf("entering callback\n");
	ret = nfq_get_payload(nfa, &packet);

	if(checkDrop(packet,ret))
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	else
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

bool makeBlockHosts(const char* filename){
	std::ifstream fin(filename);
	if(fin.fail()){
		printf("cannot Find File!!\n");
		return false;
	}
	while(!fin.eof()){
		std::string host;
		getline(fin, host);
		blockHosts.insert(host);
	}
	fin.close();
	return true;
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	if (argc != 2) {
		usage();
		return -1;
	}
	const char* filename = argv[1];

	if(makeBlockHosts(filename))
		printf("Make Block Hosts Set Success!!\n");
	else{
		printf("Make Block Hosts Set Failure!!\n");
		return -1;
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			// printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
