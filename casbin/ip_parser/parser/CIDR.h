#ifndef IP_PARSER_PARSER_CIDR
#define IP_PARSER_PARSER_CIDR

#include "./IP.h"
#include "./IPNet.h"

namespace casbin {

class CIDR {
    public:
        IP ip;
        IPNet net;
};

} // namespace casbin

#endif