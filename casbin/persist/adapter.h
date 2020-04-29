#pragma once

#ifdef CASBIN_EXPORTS
#define ADAPTER_API __declspec(dllexport)
#else
#define ADAPTER_API __declspec(dllimport)
#endif

#include "../model/model.h"
#include "../util/util.h"
#include <exception>
class ADAPTER_API Adapter
{
public:
	string filePath;
	static void LoadPolicyLine(const string& line, Model* model);
	virtual void LoadPolicy(Model* model) = 0;
	virtual void SavePolicy(Model* model) = 0;
	virtual void AddPolicy(const string& sec, const string& ptype, const vector<string>& rule) = 0;
	virtual void RemovePolicy(const string& sec, const string& ptype, const  vector<string>& rule) = 0;
	virtual void RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector <string>& fieldValues) = 0;
};
