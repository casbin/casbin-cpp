#include "casbin/pch.h"

#ifndef IPV4_CPP
#define IPV4_CPP


#include "casbin/ip_parser/parser/IPv4.h"

namespace casbin {

IP IPv4(byte a, byte b, byte c, byte d) {
    IP p;
    std::vector <byte> newIP(IP :: v4InV6Prefix.begin(), IP :: v4InV6Prefix.end());
    p.ip = newIP;
    p.ip.push_back(a);
    p.ip.push_back(b);
    p.ip.push_back(c);
    p.ip.push_back(d);
    p.isLegal = true;
    return p;
}

} // namespace casbin

#endif // IPV4_CPP
