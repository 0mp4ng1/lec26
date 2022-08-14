#pragma once

#define IP_ADR_LEN 4
#define IP_TYPE_TCP 0x06

#pragma pack(push, 1)
struct IpHdr{
    // little endian
    unsigned char ip_hdr_len:4; // header length
    unsigned char ip_ver:4; // version 4
    
    unsigned char ip_tos; // TOS
    unsigned short ip_tot_len; // total length
    unsigned short ip_id; // identification

    // little endian
    unsigned short ip_frag_offset:13; // fragment offset
    unsigned short ip_flags:3; //flags
    unsigned char ip_ttl; //Time To Live
    unsigned char ip_protocol; // Protocol
    unsigned short ip_hdr_chksm; // header checksum

    unsigned char ip_src_adr[IP_ADR_LEN]; // source address
    unsigned char ip_dst_adr[IP_ADR_LEN]; // destination address
    
};

#pragma pach(pop)