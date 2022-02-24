#ifndef IP_PARSER_PARSER_XTOI
#define IP_PARSER_PARSER_XTOI

#include <string>
#include <utility>

#include "./byte.h"

namespace casbin {

std::pair<int, int> xtoi(std::string_view s);

} // namespace casbin

#endif