#ifndef IP_PARSER_PARSER_CIDR_MASK
#define IP_PARSER_PARSER_CIDR_MASK

#include "./byte.h"
#include "./IPMask.h"
#include "./IP.h"

IPMask CIDRMask(int ones, int bits);

#endif