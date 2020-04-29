#pragma once

#ifdef CASBIN_EXPORTS
#define BULTIN_API __declspec(dllexport)
#else
#define BULTIN_API __declspec(dllimport)
#endif

#include "../third_party/Cparse/shunting-yard.h"
#include "util.h"
#include <initializer_list>



extern const string KEY_ROLEMANAGER;


class BULTIN_API BuiltinOperators {
public:
	//Error validateVariadicArgs();
	static bool KeyMatch(string key1, string key2);
	static bool KeyMatch2(string key1, string key2);
	static bool KeyMatch3(string key1, string key2);
	static bool KeyMatch4(string key1, string key2);
	static bool RegexMatch(string key1, string key2);
	static bool IPMatch(string key1, string key2);
	static bool GlobMatch(string key1, string key2);
	static packToken KeyMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken KeyMatch2Func(TokenMap GlobalMap, TokenMap Scope);
	static packToken KeyMatch3Func(TokenMap GlobalMap, TokenMap Scope);
	static packToken KeyMatch4Func(TokenMap GlobalMap, TokenMap Scope);
	static packToken RegexMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken IPMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken GlobMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	
};