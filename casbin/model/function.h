#pragma once
#include<map>
#include<string>
#include "../third_party/Cparse/shunting-yard.h"
using namespace std;

typedef packToken(*WrapFunc)(TokenMap a, TokenMap b);

class FunctionMap {
public:
	map<string, CppFunction> fm;
	static FunctionMap LoadFunctionMap();
	void AddFunction(string name, WrapFunc func);
};