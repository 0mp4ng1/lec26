#pragma once
#define MAC_ADR_LEN 6
#define ETH_TYPE_IP 0x0800

#pragma pack(push, 1)
struct EthHdr{
    unsigned char mac_dst_adr[MAC_ADR_LEN]; // destination mac addr
    unsigned char mac_src_adr[MAC_ADR_LEN];// source mac addr
    unsigned short eth_type; // ether type
};

#pragma pach(pop)