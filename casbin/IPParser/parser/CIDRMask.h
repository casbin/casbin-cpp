#ifndef IP_PARSER_PARSER_CIDR_MASK
#define IP_PARSER_PARSER_CIDR_MASK

#include "./Byte.h"
#include "./IPMask.h"
#include "./IP.h"

IPMask CIDRMask(int ones, int bits) {
    IPMask mask;
	if(bits != 8 * IP :: IPv4len && bits != 8 * IP :: IPv6len) {
		return mask;
	}
	if(ones < 0 || ones > bits) {
		return mask;
	}
	int l = bits / 8;
    IPMask newMask(l, 0);
    mask = newMask;
	int n = int(ones);
	for(int i = 0 ; i < l ; i++) {
		if(n >= 8) {
			mask[i] = 0xff;
			n -= 8;
			continue;
		}
		mask[i] = ~char(0xff >> n);
		n = 0;
	}
	return mask;
}

#endif