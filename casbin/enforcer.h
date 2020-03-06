#pragma once

#include <string>
using namespace std;

class Enforcer {
	string modelPath;

	bool enforce(string sub, string obj, string act);
};
