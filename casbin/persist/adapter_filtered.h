#pragma once
#include "adapter.h"

#ifdef CASBIN_EXPORTS
#define FILTER_API __declspec(dllexport)
#define FILTERED_ADAPTER_API __declspec(dllexport)
#else
#define FILTER_API __declspec(dllimport)
#define FILTERED_ADAPTER_API __declspec(dllimport)
#endif

class FILTER_API Filter {
public:
	vector<string> P;
	vector<string> G;
	Filter();
	Filter(const vector<string>& p, const vector<string>& g);
};

class FILTERED_ADAPTER_API Filteredadapter:public Adapter {
public:
	Adapter* adapter;
	bool filtered;
	static Filteredadapter* NewFilteredAdapter(const string& filePath);
	Error LoadPolicy(Model* model);
	Error LoadFilteredPolicy(Model* model, Filter* filter);
	Error LoadFilteredPolicyFile(Model* model, Filter* filter,void (*handler)(const string&,Model*));
	bool IsFiltered();
	Error SavePolicy(Model* model);
	static bool filterLine(const string& line, Filter* filter);
	static bool filterWords(const vector<string>&  line, const  vector<string>& filter);
	virtual Error AddPolicy(const string& sec, const string& ptype, const vector<string>& rule);
	virtual Error RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule);
	virtual Error RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& fieldValues);
};