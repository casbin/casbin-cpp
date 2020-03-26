#ifndef IP_PARSER_PARSER_PARSE_CIDR
#define IP_PARSER_PARSER_PARSE_CIDR

#include <string>

#include "./CIDR.h"
#include "./IP.h"
#include "./IPMask.h"
#include "./dtoi.h"
#include "./byte.h"
#include "./parseIPv4.h"
#include "./parseIPv6.h"
#include "./CIDRMask.h"
#include "../exceptions/ParseException.h"

CIDR parseCIDR(string s) {
	size_t pos = s.find("/");
	CIDR cidr_addr;
	if(pos == string :: npos) {
		// throw ParserException("Illegal CIDR address.");
		cidr_addr.ip.isLegal = false;
		return cidr_addr;
	}
	string addr = s.substr(0, pos);
	string mask = s.substr(pos+1, s.length()-pos-1);
	byte iplen = IP :: IPv4len;
	IP ip;
	ip = parseIPv4(addr);
	if(ip.isLegal == false) {
		iplen = IP :: IPv6len;
		ip = parseIPv6(addr);
	}
	pair<int, int> p = dtoi(mask);
	if(ip.isLegal == false || (p.first >= big || p.second==0) ||  p.second != mask.length() || p.first < 0 || p.first > 8*iplen) {
		// throw ParserException("Illegal CIDR address.");
		cidr_addr.ip.isLegal = false;
		return cidr_addr;
	}
	IPMask m = CIDRMask(p.first, 8*iplen);
	cidr_addr.ip = ip;
	cidr_addr.net.net_ip = ip.Mask(m);
	cidr_addr.net.mask = m;

	return cidr_addr;
}

#endif