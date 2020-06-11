#ifndef CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS
#define CASBIN_CPP_UTIL_BUILT_IN_FUNCTIONS

#include "../model/scope_config.h"

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
ReturnType KeyMatch(Scope scope);

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
ReturnType KeyMatch2(Scope scope);

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
ReturnType KeyMatch3(Scope scope);

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
ReturnType RegexMatch(Scope scope);

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24"
ReturnType IPMatch(Scope scope);

// GFunction is the method of the g(_, _) function.
ReturnType GFunction(Scope scope);

#endif