#ifndef IP_PARSER_PARSER_CIDR_MASK
#define IP_PARSER_PARSER_CIDR_MASK

#include "./IP.h"
#include "./IPMask.h"
#include "./byte.h"

namespace casbin {

IPMask CIDRMask(int ones, int bits);

} // namespace casbin

#endif