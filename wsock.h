#pragma once
#include <WS2tcpip.h>
#include <memory>
#include <string>

#define RECV_SIZE 65536

namespace packetmon {
    typedef struct IP_HEADER {
        unsigned char ip_vhl;
        #define ip_v ip_vhl >> 4
        #define ip_hl ip_vhl & 0x0f
        unsigned char ip_tos;
        unsigned short ip_len;
        unsigned short ip_id;
        unsigned short ip_off;
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        unsigned char ip_ttl;
        unsigned char ip_p;
        unsigned short ip_sum;
        struct in_addr ip_src, ip_dst;
    } IP_HEADER, *PIP_HEADER;

    typedef struct TCP_HEADER {
        unsigned short th_sport;
        unsigned short th_dport;
        unsigned long th_seq;
        unsigned long th_ack;
        unsigned char th_hlr;
        unsigned char th_rfl;
#define th_hl th_hlr >> 4
#define th_flags th_rfl & 0x3f
        unsigned short th_win;
        unsigned short th_sum;
        unsigned short th_urp;
    } TCP_HEADER, *PTCP_HEADER;

    class TcpPacket {
    public:
        IP_HEADER ip;
        TCP_HEADER tcp;
        unsigned char payload[RECV_SIZE] = "";
        std::string ip_src_string;
        std::string ip_dst_string;
        std::string payload_string;
        int payload_length;
        std::string comment;
    private:
    };

    class wsock {
    public:
        std::string sock_addr_list;

        bool init();
        bool query();
        bool bind(int nic_id);
        bool cleanup();
        std::shared_ptr<TcpPacket> recv();
    private:
        WSADATA _wsaData;
        SOCKET _socket = 0;
        char _sock_addr_list_buf[4096] = "";
        SOCKET_ADDRESS_LIST* _sock_addr_list;
        SOCKADDR_IN *_nic_addr, _addr;
        ULONG _uRCVALL_OPTION = 0x01; // RCVALL_ON
        DWORD _dwBytesReturned;
    };

    std::string a2s(PVOID addr);
    std::string hexstr(unsigned char* src, int len);
}