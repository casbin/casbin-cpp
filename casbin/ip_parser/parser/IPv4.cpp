#include "pch.h"

#ifndef IPV4_CPP
#define IPV4_CPP


#include "./IPv4.h"

IP IPv4(Byte a, Byte b, Byte c, Byte d) {
    IP p;
    vector <Byte> newIP(IP :: v4InV6Prefix.begin(), IP :: v4InV6Prefix.end());
    p.ip = newIP;
    p.ip.push_back(a);
    p.ip.push_back(b);
    p.ip.push_back(c);
    p.ip.push_back(d);
    p.isLegal = true;
    return p;
}

#endif // IPV4_CPP
