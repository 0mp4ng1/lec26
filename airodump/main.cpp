#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "mac.h"
#include "dot11hdr.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"

#include <set>
#include <vector>
#include <map>
using namespace std;

typedef struct {
    uint8_t Beacons;
    string ESSID;
} BeaconInfo;

map<Mac, BeaconInfo> apTable;

void usage(){
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

bool airodump(const u_char *packet){
    RadiotapHdr *radiotap = (struct RadiotapHdr *)packet;
        BeaconHdr *beacon = (struct BeaconHdr *)(packet + radiotap->len_);
        if(beacon->type_ != Dot11Hdr::Manage || beacon->typeSubtype() != Dot11Hdr::Beacon) 
            return false;
        Mac BSSID = beacon->bssid();

        if(apTable.count(BSSID))
            apTable[BSSID].Beacons++;
        else{
            BeaconInfo beaconInfo;
            beaconInfo.Beacons = 1;
            for(int i=0;i<beacon->tag()->len_;i++)
                beaconInfo.ESSID.push_back(*(beacon->tag()->essid + i));
            apTable.insert({BSSID, beaconInfo});
        }
        return true;

}

void printInfo(){
    system("clear");
    printf("[BSSID]\t\t\t[Beacons]\t[ESSID]\n");
    for(auto info : apTable){
        printf("%s\t", string(info.first).c_str());
        printf("%9d\t", info.second.Beacons);
        printf("%s\n", info.second.ESSID.c_str());
    }
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
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
        if(!airodump(packet)) continue;
        printInfo();
    }
	
	pcap_close(handle);
}