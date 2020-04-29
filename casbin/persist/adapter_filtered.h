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
	unique_ptr<Adapter> adapter;
	bool filtered;
	Filteredadapter();
	Filteredadapter(Filteredadapter& fa);
	Filteredadapter(const string& filePath);
	static Filteredadapter* NewFilteredAdapter(const string& filePath);
	void LoadPolicy(Model* model);
	void LoadFilteredPolicy(Model* model, Filter* filter);
	void LoadFilteredPolicyFile(Model* model, Filter* filter,void (*handler)(const string&,Model*));
	bool IsFiltered();
	void SavePolicy(Model* model);
	static bool filterLine(const string& line, Filter* filter);
	static bool filterWords(const vector<string>&  line, const  vector<string>& filter);
	virtual void AddPolicy(const string& sec, const string& ptype, const vector<string>& rule);
	virtual void RemovePolicy(const string& sec, const string& ptype, const vector<string>& rule);
	virtual void RemoveFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& fieldValues);
};