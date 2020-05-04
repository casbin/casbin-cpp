#include "function.h"

#include "../util/builtin_operators.h"

FunctionMap FunctionMap::LoadFunctionMap() {
    FunctionMap fm;
    fm.AddFunction("keyMatch", &BuiltinOperators::KeyMatchFunc);
    fm.AddFunction("keyMatch2", &BuiltinOperators::KeyMatch2Func);
    fm.AddFunction("keyMatch3", &BuiltinOperators::KeyMatch3Func);
    fm.AddFunction("keyMatch4", &BuiltinOperators::KeyMatch4Func);
    fm.AddFunction("regexMatch", &BuiltinOperators::RegexMatchFunc);
    fm.AddFunction("ipMatch", &BuiltinOperators::IPMatchFunc);
    fm.AddFunction("globMatch", &BuiltinOperators::GlobMatchFunc);
    return fm;
}

void FunctionMap::AddFunction(string name, WrapFunc func) {
    list<string> ls = {"A", "B"};
    fm[name] = CppFunction(func, ls);
}