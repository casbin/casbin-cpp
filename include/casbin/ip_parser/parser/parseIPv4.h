#ifndef IP_PARSER_PARSER_PARSE_IPV4
#define IP_PARSER_PARSER_PARSE_IPV4

#include <string>

#include "./IP.h"
#include "./IPv4.h"
#include "./byte.h"
#include "./dtoi.h"

namespace casbin {

IP parseIPv4(std::string_view s);

} // namespace casbin

#endif