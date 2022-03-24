#ifndef IP_PARSER_PARSER_EQUAL
#define IP_PARSER_PARSER_EQUAL

#include <string>
#include <vector>

#include "IPMask.h"

namespace casbin {

bool equal(const IPMask& m1, const IPMask& m2);

} // namespace casbin

#endif