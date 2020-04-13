#pragma once

#ifdef CASBIN_EXPORTS
#define ENFORCER_API __declspec(dllexport)
#else
#define ENFORCER_API __declspec(dllimport)
#endif

#include "./model/model.h"
#include "./persist/file-adapter/file-adapter.h"
#include "./persist/adapter_filtered.h"
#include "./persist/adapter.h"
#include "./util/util.h"
#include "./effect/effect.h"
#include <initializer_list>
#include"Cparse/shunting-yard.h"

using namespace std;

class ENFORCER_API Enforcer
{
public:
	string modelPath;
	Model* model;
	Effect eft;
	TokenMap fm;

	Adapter* adapter;
	//Watcher* watcher;
	RoleManager* rm;
	bool enabled;
	bool autoSave;
	bool autoBuildRoleLinks;
	bool autoNotifyWatcher;

	Enforcer();
	~Enforcer();

	Enforcer(Model* model, const string& policyPath);
	Enforcer(const string& modelPath, Adapter* adapter);
	Enforcer(Model* model, Adapter* adapter);
	Enforcer(const string& modelPath, const string& policyPath);

	void Initialize();
	void InitWithFile(const string& modelPath, const string& policyPath);
	void InitWithAdapter(const string& modelPath, Adapter* adapter);
	void InitWithModelAndAdapter(Model* model, Adapter* adapter);
	void LoadModel();
	Model* GetModel();
	void SetModel(Model* model);
	Adapter* GetAdapter();
	void SetAdapter(Adapter* adapter);
	//void SetWatcher(Watcher* watcher);
	RoleManager* GetRoleManager();
	void SetRoleManager(RoleManager* rm);
	void SetEffector();
	void ClearPolicy();
	void LoadPolicy();
	void LoadFilteredPolicy(Filter* filter);
	bool IsFiltered();
	void SavePolicy();
	void EnableEnforce(const bool& enable);
	void EnableLog(const bool& enable);
	void EnableAutoNotifyWatcher(const bool& enable);
	void EnableAutoSave(const bool& enable);
	void EnableAutoBuildRoleLinks(const bool& enable);
	void BuildRoleLinks();
	bool enforce(const string& matcher,const initializer_list<string> rval);
	bool Enforce(initializer_list<string> rval);
	void EnforceWithMatcher(bool& res, const string& matcher, initializer_list<string> rval);
	bool MergeEffects(const string& expr,const vector<Effect>& effects, const vector<double>& results);
	void SetTokenMap(TokenMap& tokenmap, map<string, int>& rTokens, map<string, int>& pTokens, vector<string>& rVals, vector<string>& pVals);
};