#pragma once

#pragma pack(push, 1)
struct TcpHdr{
    unsigned short src_port; // source port
    unsigned short dst_port; // destination port
    unsigned int tcp_seq_num; // sequence number
    unsigned int tcp_ack_num; // acknowledgement number
    unsigned char tcp_ns:1; // ns flag
    unsigned char tcp_reserved:3; // Reserved flag
    unsigned char tcp_data_offset:4; // Data offset

    unsigned char tcp_fin:1; // fin flag
    unsigned char tcp_syn:1; // syn flag
    unsigned char tcp_rst:1; // rst flag
    unsigned char tcp_psh:1; // psh flag
    unsigned char tcp_ack:1; // ack flag
    unsigned char tcp_urg:1; // urg flag
    unsigned char tcp_ecn:1; // ece flag
    unsigned char tcp_cwr:1; // cwr flag

    unsigned short tcp_win_sz; // window size
    unsigned short tcp_chksum; // checksum
    unsigned short tcp_urg_ptr; // urgent pointer    
};

#pragma pach(pop)