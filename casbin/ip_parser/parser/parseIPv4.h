#ifndef IP_PARSER_PARSER_PARSE_IPV4
#define IP_PARSER_PARSER_PARSE_IPV4

#include <string>

#include "./IP.h"
#include "./dtoi.h"
#include "./byte.h"
#include "./IPv4.h"

namespace casbin {

IP parseIPv4(std::string s);

} // namespace casbin

#endif