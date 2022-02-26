#include "casbin/pch.h"

#ifndef PARSECIDR_CPP
#define PARSECIDR_CPP


#include "casbin/ip_parser/parser/parseCIDR.h"

namespace casbin {

CIDR parseCIDR(std::string s) {
    size_t pos = s.find("/");
    if(pos == std::string :: npos) {
        throw ParserException("Illegal CIDR address.");
    }
    std::string addr = s.substr(0, pos);
    std::string mask = s.substr(pos+1, s.length()-pos-1);
    byte iplen = IP :: IPv4len;
    IP ip;
    ip = parseIPv4(addr);
    if(ip.isLegal == false) {
        iplen = IP :: IPv6len;
        ip = parseIPv6(addr);
    }
    std::pair<int, int> p = dtoi(mask);
    if(ip.isLegal == false || (p.first >= big || p.second==0) ||  p.second != mask.length() || p.first < 0 || p.first > 8*iplen) {
        throw ParserException("Illegal CIDR address.");
    }
    IPMask m = CIDRMask(p.first, 8*iplen);
    CIDR cidr_addr;
    cidr_addr.ip = ip;
    cidr_addr.net.net_ip = ip.Mask(m);
    cidr_addr.net.mask = m;

    return cidr_addr;
}

} // namespace casbin

#endif // PARSECIDR_CPP
