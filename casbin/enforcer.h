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
	Error InitWithFile(const string& modelPath, const string& policyPath);
	Error InitWithAdapter(const string& modelPath, Adapter* adapter);
	Error InitWithModelAndAdapter(Model* model, Adapter* adapter);
	Error LoadModel();
	Model* GetModel();
	void SetModel(Model* model);
	Adapter* GetAdapter();
	void SetAdapter(Adapter* adapter);
	//void SetWatcher(Watcher* watcher);
	RoleManager* GetRoleManager();
	void SetRoleManager(RoleManager* rm);
	void SetEffector();
	void ClearPolicy();
	Error LoadPolicy();
	Error LoadFilteredPolicy(Filter* filter);
	bool IsFiltered();
	Error SavePolicy();
	void  EnableEnforce(const bool& enable);
	void  EnableLog(const bool& enable);
	void  EnableAutoNotifyWatcher(const bool& enable);
	void  EnableAutoSave(const bool& enable);
	void  EnableAutoBuildRoleLinks(const bool& enable);
	Error BuildRoleLinks();
	bool enforce(Error& err, const string& matcher,const initializer_list<string> rval);
	bool Enforce(Error& err,initializer_list<string> rval);
	Error EnforceWithMatcher(bool& res, const string& matcher, initializer_list<string> rval);
	Error MergeEffects(bool& res, const string& expr,const vector<Effect>& effects, const vector<double>& results);
	void SetTokenMap(TokenMap& tokenmap, map<string, int>& rTokens, map<string, int>& pTokens, vector<string>& rVals, vector<string>& pVals);
};