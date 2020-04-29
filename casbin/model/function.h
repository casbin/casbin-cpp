#pragma once
#include<map>
#include<string>
#include "../third_party/Cparse/shunting-yard.h"
using namespace std;


class FunctionMap {
public:
	map<string, CppFunction> fm;
	static FunctionMap LoadFunctionMap();
	void AddFunction(string name, CppFunction cppFunction);
};