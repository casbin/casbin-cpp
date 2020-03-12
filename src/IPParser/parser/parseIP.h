#ifndef IP_PARSER_PARSER_PARSE_IP
#define IP_PARSER_PARSER_PARSE_IP

#include <string>

#include "./IP.h"
#include "./parseIPv4.h"
#include "./parseIPv6.h"

using namespace std;

IP parseIP(string s) {
	for(int i = 0 ; i < s.length() ; i++) {
		switch(s[i]) {
		case '.':
			return parseIPv4(s);
		case ':':
			return parseIPv6(s);
		}
	}
    IP p;
    p.isLegal = false;
	return p;
}

#endif