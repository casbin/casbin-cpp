#ifndef IP_PARSER_PARSER_IP_NET
#define IP_PARSER_PARSER_IP_NET

#include <utility>
#include <sstream>

#include "./IP.h"
#include "./IPMask.h"

namespace casbin {

class IPNet {
    public:
        IP net_ip;
        IPMask mask;

        std::string NETIP_toString();

        std::string IPMask_toString();

        // Contains reports whether the network includes ip.
        bool contains(IP ipNew);

        static std::pair<IP, IPMask> networkNumberAndMask(IPNet n);

};

} // namespace casbin

#endif