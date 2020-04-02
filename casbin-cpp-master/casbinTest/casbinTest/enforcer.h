#pragma once
#include "model.h"
#include "file-adapter.h"
#include "adapter.h"
#include "util.h"
#include "effect.h"
#include <initializer_list>
#include"Cparse/shunting-yard.h"

using namespace std;

class Enforcer
{
public:
	string modelPath;
	Model model;
	Effect eft;
	//FunctionMap fm;

	Adapter* adapter;
	//Watcher* watcher;
	//RoleManager rm;
	bool enabled;
	bool autoSave;
	bool autoBuildRoleLinks;
	bool autoNotifyWatcher;

	Enforcer();
	Enforcer(Model& model,Adapter* adapter);
	void Initialize();
	void InitWithAdapter(string modelPath, Adapter* adapter);
	void InitWithModelAndAdapter(Model& model, Adapter* adapter);
	void LoadPolicy();
	bool enforce(string matcher, initializer_list<string> rval);
	bool Enforce(initializer_list<string> rval);
	bool MergeEffects(string expr, vector<Effect> effects, vector<double> results);
	void SetTokenMap(TokenMap& tokenmap, map<string, int>& rTokens, map<string, int>& pTokens, vector<string>& rVals, vector<string>& pVals);
};