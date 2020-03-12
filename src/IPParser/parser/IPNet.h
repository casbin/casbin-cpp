#ifndef IP_PARSER_PARSER_IP_NET
#define IP_PARSER_PARSER_IP_NET

#include <sstream>

#include "./IP.h"
#include "./IPMask.h"

class IPNet {
    public:
        IP net_ip;
        IPMask mask;

        string NETIP_toString() {
            string ip1, ip2, ip3, ip4;
            stringstream ss1, ss2, ss3, ss4;
            ss1 << net_ip.ip[0];
            ss1 >> ip1;
            ss2 << net_ip.ip[1];
            ss2 >> ip2;
            ss3 << net_ip.ip[2];
            ss3 >> ip3;
            ss4 << net_ip.ip[3];
            ss4 >> ip4;
            return ip1 + "." + ip2 + "." + ip3 + "." + ip4;
        }

        string IPMask_toString() {
            string mask1, mask2, mask3, mask4;
            stringstream ss1, ss2, ss3, ss4;
            ss1 << mask[0];
            ss1 >> mask1;
            ss2 << mask[1];
            ss2 >>mask2;
            ss3 << mask[2];
            ss3 >>mask3;
            ss4 << mask[3];
            ss4 >>mask4;
            return mask1 + "." + mask2 + "." + mask3 + "." + mask4;
        }
};

#endif