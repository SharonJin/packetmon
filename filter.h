#pragma once
#include <memory>
#include "wsock.h"

namespace packetmon {
    class filter {
    public:
        // packet filtering
        char filter_ip_src[17] = "211.*";
        char filter_ip_dst[17] = "192.*";
        char filter_port[6] = "";
        bool active = true;

        /* write your code */
        /* return true -> output to gui (and http post) */
        int received_packet_count = 0;
        int matched_packet_count = 0;
        virtual bool init();
        virtual bool doFilter(std::shared_ptr<TcpPacket> rp);
    };
}
