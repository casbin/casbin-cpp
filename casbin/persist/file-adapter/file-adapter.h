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
	FileAdapter(const string& filePath);
	static FileAdapter* newFileAdapter(const string& filePath);
	Error LoadPolicy(Model *model);
	Error LoadPolicyFile(Model *model,void (*handler)(const string&, Model*));
	static void LoadPolicyLine(const string& line, Model* model);
	Error SavePolicy(Model *model);
	Error SavePolicyFile(const string& text);
	Error AddPolicy(const string& sec, const string& ptype, const vector<string>& rule);
	Error AddPolicies(const string& sec, const string& ptype, const vector<vector<string>>& rules);
	Error RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule);
	Error RemoveFilteredPolicy(const string& sec,const string& ptype,const int& fieldIndex,const vector <string>& fieldValues);
};