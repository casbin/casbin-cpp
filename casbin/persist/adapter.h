#pragma once
#include <vector>
#include "../util/utils.h"
#include "../model/model.h"

using namespace std;

class Adapter {
public:
	virtual void loadPolicy(Model*)= 0;
	virtual void savePolicy(Model*) = 0;
	virtual void addPolicy(string, string, vector<string>) = 0;
	virtual void removePolicy(string, string, vector<string>) = 0;
	void loadPolicyLine(string, Model*);
};