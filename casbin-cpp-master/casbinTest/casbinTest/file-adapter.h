#pragma once
#include "adapter.h"
class FileAdapter : public Adapter
{
public:
	string filePath;
	FileAdapter(string filePath);
	void LoadPolicy(Model &model);
	void LoadPolicyFile(Model &model,void (*handler)(string, Model&));
	static void LoadPolicyLine(string line, Model& model);
	void SavePolicy(Model &model);
	void SavePolicyFile(const string& text);
	void AddPolicy(string sec, string ptype, vector<string> rule);
	void AddPolicies(string sec, string ptype, vector<vector<string>> rules);
	void RemovePolicy(string sec, string ptype, vector<string> rule);
	void RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues);
};