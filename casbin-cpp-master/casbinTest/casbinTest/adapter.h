#pragma once
#include "model.h"
#include "util.h"
class Adapter
{
public:
	static void LoadPolicyLine(string line, Model& model);
	virtual void LoadPolicy(Model& model) = 0;
	virtual void SavePolicy(Model& model) = 0;
	virtual void AddPolicy(string sec,string ptype,vector<string> rule) = 0;
	virtual void RemovePolicy(string sec, string ptype, vector<string> rule) = 0;
	virtual void RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues) = 0;
};
