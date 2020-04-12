#pragma once

#ifdef CASBIN_EXPORTS
#define ADAPTER_API __declspec(dllexport)
#else
#define ADAPTER_API __declspec(dllimport)
#endif

#include "../model/model.h"
#include "../util/util.h"
#include "../errors/exceptions.h"
class ADAPTER_API Adapter
{
public:
	string filePath;
	static void LoadPolicyLine(const string& line, Model* model);
	virtual Error LoadPolicy(Model* model) = 0;
	virtual Error SavePolicy(Model* model) = 0;
	virtual Error AddPolicy(const string& sec, const string& ptype, const vector<string>& rule) = 0;
	virtual Error RemovePolicy(const string& sec, const string& ptype, const  vector<string>& rule) = 0;
	virtual Error RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector <string>& fieldValues) = 0;
};
