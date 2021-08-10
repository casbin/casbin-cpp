#ifndef IP_PARSER_PARSER_DTOI
#define IP_PARSER_PARSER_DTOI

#include <string>
#include <utility>

#include "./byte.h"

namespace casbin {

// Decimal to integer.
// Returns number, characters consumed, success.
std::pair<int, int> dtoi(std::string_view s);

} // namespace casbin

#endif