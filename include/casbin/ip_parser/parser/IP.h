#ifndef IP_PARSER_PARSER_IP
#define IP_PARSER_PARSER_IP

#include <sstream>
#include <vector>

#include "./IPMask.h"
#include "./allFF.h"
#include "./byte.h"
#include "./equal.h"

namespace casbin {

class IP {
public:
    std::vector<byte> ip;
    bool isLegal;
    static byte IPv4len;
    static byte IPv6len;
    static IPMask v4InV6Prefix;

    IP();

    IP Mask(IPMask mask);

    bool Equal(IP x);

    std::string toString();

    // To4 converts the IPv4 address ip to a 4-byte representation.
    // If ip is not an IPv4 address, To4 returns nil.
    IP To4();

    // Is p all zeros?
    static bool isZeros(IP p);
};

} // namespace casbin

#endif