#pragma once
#include <map>
#include <string>

#include "../third_party/Cparse/shunting-yard.h"
using namespace std;

// WrapFunc represents a wrap function.
typedef packToken (*WrapFunc)(TokenMap a);

// FunctionMap represents the collection of Function.
class FunctionMap {
public:
    //fm[function name] = Cppfunction
    map<string, CppFunction> fm;
    static FunctionMap LoadFunctionMap();
    // AddFunction adds an expression function.
    void AddFunction(string name, WrapFunc func);
};