#pragma once

#ifdef CASBIN_EXPORTS
#define BUILTIN_OPERATORS_API __declspec(dllexport)
#else
#define BUILTIN_OPERATORS_API __declspec(dllimport)
#endif

#include <utility>
#include <bitset>
#include <functional>
#include "../rbac/role_manager.h"
#include "utils.h"

extern "C++" BUILTIN_OPERATORS_API bool keyMatch(string, string);

extern "C++" BUILTIN_OPERATORS_API bool keyMatch2(string, string);

extern "C++" BUILTIN_OPERATORS_API bool keyMatch4(string, string);

extern "C++" BUILTIN_OPERATORS_API bool ipMatch(string, string);

extern "C++" BUILTIN_OPERATORS_API bool regexMatch(string, string);

extern "C++" BUILTIN_OPERATORS_API string escapeAssertion(string);

extern "C++" BUILTIN_OPERATORS_API function<bool(string, string)> generateGFunction(RoleManager*);