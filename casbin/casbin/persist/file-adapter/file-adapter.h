#pragma once

#ifdef CASBIN_EXPORTS
#define FILE_ADAPTER_API __declspec(dllexport)
#else
#define FILE_ADAPTER_API __declspec(dllimport)
#endif

#include "../adapter.h"
class FILE_ADAPTER_API FileAdapter : public Adapter
{
public:
	FileAdapter();
	FileAdapter(const string& filePath);
	static FileAdapter* newFileAdapter(const string& filePath);
	static FileAdapter* newFileAdapter();
	void LoadPolicy(Model *model);
	void LoadPolicyFile(Model *model,void (*handler)(const string&, Model*));
	static void LoadPolicyLine(const string& line, Model* model);
	void SavePolicy(Model *model);
	void SavePolicyFile(const string& text);
	void AddPolicy(const string& sec, const string& ptype, const vector<string>& rule);
	void AddPolicies(const string& sec, const string& ptype, const vector<vector<string>>& rules);
	void RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule);
	void RemoveFilteredPolicy(const string& sec,const string& ptype,const int& fieldIndex,const vector <string>& fieldValues);
};