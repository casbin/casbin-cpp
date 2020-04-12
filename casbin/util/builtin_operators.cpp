#include"builtin_operators.h"

const string KEY_ROLEMANAGER = "default_rolemanager";

Error validateVariadicArgs();
bool KeyMatch(string key1, string key2);
bool BuiltinOperatorsKeyMatch2(string key1, string key2);
bool KeyMatch3(string key1, string key2);
bool KeyMatch4(string key1, string key2);
bool RegexMatch(string key1, string key2);
bool IPMatch(string key1, string key2);
bool GlobMatch(string key1, string key2);
bool BuiltinOperators::GFunction(RoleManager* rm, initializer_list<string> ils)
{
	int lenargs = ils.size();
	auto beg = ils.begin();
	string name1 = *beg;
	beg++;
	string name2 = *beg;

	if (rm == NULL) {
		return name1 == name2;
	}
	else if (lenargs == 2) {
		bool res = false;
		rm->HasLink(res, name1, name2, {});
		return res;
	}
	else {
		bool res = false;
		beg++;
		string domain = *beg;
		rm->HasLink(res, name1, name2, {domain});
		return res;
	}
}

packToken KeyMatchFunc(TokenMap GlobalMap, TokenMap Scope);
packToken KeyMatch2Func(TokenMap GlobalMap, TokenMap Scope);
packToken KeyMatch3Func(TokenMap GlobalMap, TokenMap Scope);
packToken KeyMatch4Func(TokenMap GlobalMap, TokenMap Scope);
packToken RegexMatchFunc(TokenMap GlobalMap, TokenMap Scope);
packToken IPMatchFunc(TokenMap GlobalMap, TokenMap Scope);
packToken GlobMatchFunc(TokenMap GlobalMap, TokenMap Scope);

packToken BuiltinOperators::GFunctionFunc(TokenMap GlobalMap, TokenMap Scope)
{
	RoleManager* rm = GlobalMap[KEY_ROLEMANAGER].asPtype().rm;

	if (Scope["C"].str() != "None") {
		return GFunction(rm, {Scope["A"].asString(),Scope["B"].asString() ,Scope["C"].asString() });
	}
	else if (Scope["B"].str() != "None") {
		return GFunction(rm, { Scope["A"].asString(),Scope["B"].asString()});
	}
}