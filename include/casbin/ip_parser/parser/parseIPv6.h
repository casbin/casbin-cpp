#ifndef IP_PARSER_PARSER_PARSE_IPV6
#define IP_PARSER_PARSER_PARSE_IPV6

#include <string>

#include "./IP.h"
#include "./xtoi.h"
#include "./parseIPv4.h"

namespace casbin {

IP parseIPv6(std::string_view s);

} // namespace casbin

#endif