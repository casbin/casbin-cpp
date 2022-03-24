#ifndef IP_PARSER_PARSER_PARSE_CIDR
#define IP_PARSER_PARSER_PARSE_CIDR

#include <string>

#include "../exception/parser_exception.h"
#include "./CIDR.h"
#include "./CIDRMask.h"
#include "./IP.h"
#include "./IPMask.h"
#include "./byte.h"
#include "./dtoi.h"
#include "./parseIPv4.h"
#include "./parseIPv6.h"

namespace casbin {

CIDR parseCIDR(std::string s);

} // namespace casbin

#endif