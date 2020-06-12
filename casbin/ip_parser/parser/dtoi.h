#ifndef IP_PARSER_PARSER_DTOI
#define IP_PARSER_PARSER_DTOI

#include <string>
#include <utility>

#include "./byte.h"

using namespace std;

// Decimal to integer.
// Returns number, characters consumed, success.
pair<int, int> dtoi(string s);

#endif