#pragma once
#include"../errors/exceptions.h"
#include"../rbac/role_manager.h"
#include "../Cparse/shunting-yard.h"
#include <initializer_list>

extern const string KEY_ROLEMANAGER;


class BuiltinOperators {
public:
	Error validateVariadicArgs();
	static bool KeyMatch(string key1, string key2);
	static bool KeyMatch2(string key1, string key2);
	static bool KeyMatch3(string key1, string key2);
	static bool KeyMatch4(string key1, string key2);
	static bool RegexMatch(string key1, string key2);
	static bool IPMatch(string key1, string key2);
	static bool GlobMatch(string key1, string key2);
	static bool GFunction(RoleManager* rm, initializer_list<string> ils);
	static packToken KeyMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken KeyMatch2Func(TokenMap GlobalMap, TokenMap Scope);
	static packToken KeyMatch3Func(TokenMap GlobalMap, TokenMap Scope);
	static packToken KeyMatch4Func(TokenMap GlobalMap, TokenMap Scope);
	static packToken RegexMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken IPMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken GlobMatchFunc(TokenMap GlobalMap, TokenMap Scope);
	static packToken GFunctionFunc(TokenMap GlobalMap, TokenMap Scope);
	
};