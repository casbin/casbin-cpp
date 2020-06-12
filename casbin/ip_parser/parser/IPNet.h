#ifndef IP_PARSER_PARSER_IP_NET
#define IP_PARSER_PARSER_IP_NET

#include <utility>
#include <sstream>

#include "./IP.h"
#include "./IPMask.h"

class IPNet {
    public:
        IP net_ip;
        IPMask mask;

        string NETIP_toString();

        string IPMask_toString();

        // Contains reports whether the network includes ip.
        bool contains(IP ipNew);

        static pair<IP, IPMask> networkNumberAndMask(IPNet n);

};

#endif