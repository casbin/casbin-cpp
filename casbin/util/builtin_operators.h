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

extern "C++" BUILTIN_OPERATORS_API auto key_match(string, string) -> bool;

extern "C++" BUILTIN_OPERATORS_API auto key_match2(string, string) -> bool;

extern "C++" BUILTIN_OPERATORS_API auto key_match4(string, string) -> bool;

extern "C++" BUILTIN_OPERATORS_API auto ip_match(string, string) -> bool;

extern "C++" BUILTIN_OPERATORS_API auto regex_match(string, string) -> bool;

extern "C++" BUILTIN_OPERATORS_API auto escape_assertion(string) -> string;

extern "C++" BUILTIN_OPERATORS_API auto generate_g_function(role_manager*) -> function<bool(string, string)>;
