#pragma once

#ifdef CASBIN_EXPORTS
#define BULTIN_API __declspec(dllexport)
#else
#define BULTIN_API __declspec(dllimport)
#endif


#include"../rbac/role_manager.h"
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
	static bool GFunction(RoleManager* rm, vector<string> ils);
	static packToken KeyMatchFunc(TokenMap Scope);
	static packToken KeyMatch2Func(TokenMap Scope);
	static packToken KeyMatch3Func(TokenMap Scope);
	static packToken KeyMatch4Func(TokenMap Scope);
	static packToken RegexMatchFunc(TokenMap Scope);
	static packToken IPMatchFunc(TokenMap Scope);
	static packToken GlobMatchFunc(TokenMap Scope);
	static function<packToken(TokenMap)> GenerateGFunc(RoleManager* rm);
	
};