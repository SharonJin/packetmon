#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

#include "wsock.h"

namespace packetmon {
    std::string a2s(PVOID addr) {
        char buf[INET_ADDRSTRLEN];
        return inet_ntop(AF_INET, addr, buf, sizeof(buf));
    }
    
    std::string hexstr(unsigned char* src, int len) {
        std::stringstream ss;
        for (int i = 0; i < len; ++i)
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)src[i];
        return ss.str();
    }

    bool wsock::init() {
        WSAStartup(MAKEWORD(2, 2), &_wsaData);

        _socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (_socket == INVALID_SOCKET) {
            ::OutputDebugString("invalid_socket");
            return false;
        }

        return true;
    }

    bool wsock::cleanup() {
        closesocket(_socket);
        WSACleanup();
        return true;
    }

    bool wsock::query() {
        int ret = WSAIoctl(_socket, SIO_ADDRESS_LIST_QUERY, NULL, 0,
            _sock_addr_list_buf, sizeof(_sock_addr_list_buf), &_dwBytesReturned, NULL, NULL);
        if (ret == WSAEFAULT) {
            ::OutputDebugString("wsaefault");
            return false;
        }

        _sock_addr_list = (SOCKET_ADDRESS_LIST*)_sock_addr_list_buf;
        std::vector<std::string> list;
        for (int i = 0; i < _sock_addr_list->iAddressCount; i++) {
            auto nic_addr = (SOCKADDR_IN*)_sock_addr_list->Address[i].lpSockaddr;
            list.push_back(a2s(&nic_addr->sin_addr));
        }
        if (list.empty())
            return false;

        std::string sret = "";
        std::for_each(list.begin(), list.end(), [&sret](std::string s) {
            sret += s;
            sret += '\0';
        });

        sock_addr_list = sret;

        return true;
    }

    bool wsock::bind(int nic_id) {
        if (_socket != 0) {
            cleanup();
            init();
            setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, (char*)0, sizeof(BOOL));
        }

        _nic_addr = (SOCKADDR_IN*)_sock_addr_list->Address[nic_id].lpSockaddr;

        _addr.sin_addr.S_un.S_addr = _nic_addr->sin_addr.S_un.S_addr;
        _addr.sin_family = AF_INET;
        _addr.sin_port = htons(0);
        int ret = ::bind(_socket, (SOCKADDR*)&_addr, sizeof(_addr));
        if (ret == SOCKET_ERROR)
            return false;

        ret = WSAIoctl(_socket, 0x98000001, &_uRCVALL_OPTION, sizeof(ULONG), NULL, 0, &_dwBytesReturned, NULL, NULL);
        if (ret != 0)
            return false;

        return true;
    }

    std::shared_ptr<TcpPacket> wsock::recv() {
        char szBuff[RECV_SIZE] = "";
        auto tcpPacket(std::make_shared<TcpPacket>());

        _dwBytesReturned = ::recv(_socket, szBuff, sizeof(szBuff), 0);
        if (_dwBytesReturned == SOCKET_ERROR || _dwBytesReturned == 0)
            return nullptr;
        memmove(&tcpPacket->ip, szBuff, sizeof(IP_HEADER));

        tcpPacket->ip_src_string = a2s(&tcpPacket->ip.ip_src);
        tcpPacket->ip_dst_string = a2s(&tcpPacket->ip.ip_dst);

        if (tcpPacket->ip.ip_p == 6) { // tcp
            memmove(&tcpPacket->tcp, szBuff + ((tcpPacket->ip.ip_hl) * 4), sizeof(TCP_HEADER));
            int totalHeaderLen = ((tcpPacket->ip.ip_hl) * 4) + ((tcpPacket->tcp.th_hl) * 4);
            memmove(tcpPacket->payload, (szBuff + totalHeaderLen), _dwBytesReturned - totalHeaderLen);

            tcpPacket->payload_string = hexstr(tcpPacket->payload, _dwBytesReturned - totalHeaderLen);
            tcpPacket->payload_length = _dwBytesReturned - totalHeaderLen;

            return tcpPacket;
        }

        return nullptr;
    }
}