#include "casbin/pch.h"

#ifndef PARSEIPV4_CPP
#define PARSEIPV4_CPP


#include "casbin/ip_parser/parser/parseIPv4.h"

namespace casbin {

IP parseIPv4(std::string_view s) {
    std::vector <byte> pb(IP :: IPv4len, 0);
    IP ipv4;
    for(int i = 0; i < IP :: IPv4len ; i++) {
        if(s.length() == 0) {
            // Missing octets.
            ipv4.isLegal = false;
            return ipv4;
        }
        if(i > 0) {
            if(s[0] != '.') {
                ipv4.isLegal = false;
                return ipv4;
            }
            s = s.substr(1,s.length() - 1);
        }
        std::pair<int,int> p = dtoi(s);
        if ((p.first>=big || p.second==0) || p.first > 0xFF) {
            ipv4.isLegal = false;
            return ipv4;
        }
        s = s.substr(p.second, s.length() - p.second);
        pb[i] = p.first;
    }
    if(s.length() != 0) {
        ipv4.isLegal = false;
        return ipv4;
    }
    return IPv4(pb[0], pb[1], pb[2], pb[3]);
}

} // namespace casbin

#endif // PARSEIPV4_CPP
