#include"function.h"
#include"../util/builtin_operators.h"

FunctionMap FunctionMap::LoadFunctionMap() {
	FunctionMap fm;
	TokenMap gm;
	list<string> ls = {"A","B"};
	fm.AddFunction("keyMatch", CppFunction(gm, &BuiltinOperators::KeyMatchFunc, ls));
	fm.AddFunction("keyMatch2", CppFunction(gm, &BuiltinOperators::KeyMatch2Func, ls));
	fm.AddFunction("keyMatch3", CppFunction(gm, &BuiltinOperators::KeyMatch3Func, ls));
	fm.AddFunction("keyMatch4", CppFunction(gm, &BuiltinOperators::KeyMatch4Func, ls));
	fm.AddFunction("regexMatch", CppFunction(gm, &BuiltinOperators::RegexMatchFunc, ls));
	fm.AddFunction("ipMatch", CppFunction(gm, &BuiltinOperators::IPMatchFunc, ls));
	fm.AddFunction("globMatch", CppFunction(gm, &BuiltinOperators::GlobMatchFunc, ls));
	return fm;
}

void FunctionMap::AddFunction(string name, CppFunction function) {
	fm[name] = function;
}