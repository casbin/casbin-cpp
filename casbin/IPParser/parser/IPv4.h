#ifndef IP_PARSER_PARSER_IPv4
#define IP_PARSER_PARSER_IPv4

#include "./IP.h"
#include "./Byte.h"

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

#endif