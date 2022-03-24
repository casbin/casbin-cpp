#ifndef IP_PARSER_PARSER_PARSE_IPV6
#define IP_PARSER_PARSER_PARSE_IPV6

#include <string>

#include "./IP.h"
#include "./parseIPv4.h"
#include "./xtoi.h"

namespace casbin {

IP parseIPv6(std::string_view s);

} // namespace casbin

#endif