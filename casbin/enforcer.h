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
	unique_ptr<Model> model;
	Effect eft;
	TokenMap fm;

	unique_ptr<Adapter> adapter;
	//Watcher* watcher;
	RoleManager* rm;
	bool enabled;
	bool autoSave;
	bool autoBuildRoleLinks;
	bool autoNotifyWatcher;

	Enforcer();
	~Enforcer();

	Enforcer(const Enforcer& e);
	Enforcer(unique_ptr<Model>& model, const string& policyPath);
	Enforcer(const string& modelPath, unique_ptr<Adapter>& adapter);
	Enforcer(unique_ptr<Model>& model, unique_ptr<Adapter>& adapter);
	Enforcer(const string& modelPath, const string& policyPath);

	void Initialize();
	void InitWithFile(const string& modelPath, const string& policyPath);
	void InitWithAdapter(const string& modelPath, unique_ptr<Adapter>& adapter);
	void InitWithModelAndAdapter(unique_ptr<Model>& model, unique_ptr<Adapter>& adapter);
	void LoadModel();
	unique_ptr<Model>& GetModel();
	void SetModel(unique_ptr<Model>& model);
	unique_ptr<Adapter>& GetAdapter();
	void SetAdapter(unique_ptr<Adapter>& adapter);
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
	bool EnforceWithMatcher(const string& matcher, initializer_list<string> rval);
	bool MergeEffects(const string& expr,const vector<Effect>& effects, const vector<double>& results);
	void SetTokenMap(TokenMap& tokenmap, map<string, int>& rTokens, map<string, int>& pTokens, vector<string>& rVals, vector<string>& pVals);
};