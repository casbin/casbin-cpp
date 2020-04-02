#include"enforcer.h"
#include "effect.h"
#include "exceptions.h"
#include"Cparse/shunting-yard.h"

using namespace std;
Enforcer::Enforcer()
{

}

Enforcer::Enforcer(Model& model, Adapter* adapter)
{
	InitWithModelAndAdapter(model, adapter);
}

void Enforcer::Initialize()
{
	/*
	e.rm = defaultrolemanager.NewRoleManager(10)
	e.eft = effect.NewDefaultEffector()
	e.watcher = nil
	*/

	enabled = true;
	autoSave = true;
	autoBuildRoleLinks = true;
	autoNotifyWatcher = true;
}
void Enforcer::InitWithAdapter(string modelPath, Adapter* adapter)
{

}
void Enforcer::InitWithModelAndAdapter(Model& m, Adapter* adapter)
{
	this->adapter = adapter;
	this->model = m;
	//this->model.PrintModel();
	//fm = LoadFunctionMap();
	Initialize();
	LoadPolicy();
}
void Enforcer::LoadPolicy()
{
	model.ClearPolicy();
	adapter->LoadPolicy(model);
	//model.PrintPolicy();
	/*
	if e.autoBuildRoleLinks {
		err := e.BuildRoleLinks()
		if err != nil {
			return err
		}
	}
	return nil
	*/
}

bool Enforcer::enforce(string matcher, initializer_list<string> rlists)
{
	if (!enabled)
		return true;
	/*
	for k, v := range e.fm {
		functions[k] = v
	}
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			rm := ast.RM
			functions[key] = util.GenerateGFunction(rm)
		}
	}
	*/
	string expString;
	if (matcher == ""){
		expString = model.modelmap["m"]["m"].Value;
	}
	else {
		expString = matcher;
	}

	calculator c1;
	c1 = calculator(expString.data());
	map<string, int> rTokens, pTokens;

	vector<string> rVals;
	bool result = false;

	for (auto beg = rlists.begin(); beg != rlists.end();beg++)
	{
		rVals.push_back(*beg);
	}

	vector<string>* r = &model.modelmap["r"]["r"].Tokens;
	for (int i=0;i< (*r).size();i++){
		rTokens[(*r)[i]] = i;
	}

	vector<string>* p = &model.modelmap["p"]["p"].Tokens;
	for (int i = 0; i < (*p).size(); i++) {
		pTokens[(*p)[i]] = i;
	}



	int policyLen = model.modelmap["p"]["p"].Policy.size();
	vector<Effect> policyEffects = vector<Effect>(policyLen);
	vector<double> matcherResults = vector<double>(policyLen);

	if (policyLen != 0){
		for (int i = 0; i < policyLen;i++) {
			vector<string> pVals = model.modelmap["p"]["p"].Policy[i];
			try {
				if (model.modelmap["r"]["r"].Tokens.size() != rVals.size())
				{
					string errorInfo;
					stringstream ss;
					ss << "invalid policy size: expected "
						<< model.modelmap["r"]["r"].Tokens.size()
						<< ", got " << pVals.size() << ", pvals: "
						<< Util::ArrayToString(pVals) << endl;
					ss >> errorInfo;
					throw Exception(errorInfo);
				}
			}
			catch (exception& e) {
				cout << e.what() << endl;
			}
			

			TokenMap vars;
			SetTokenMap(vars, rTokens, pTokens, rVals, pVals);
			
			result = c1.eval(vars).asBool();

			if (!result) {
				policyEffects[i] = Indeterminate;
				continue;
			}

			if (pTokens.count("p_eft")){
				string eft = pVals[pTokens["p_eft"]];
				if (eft == "allow") {
					policyEffects[i] = Allow;
				}
				else if (eft == "deny") {
					policyEffects[i] = Deny;
				}
				else {
					policyEffects[i] = Indeterminate;
				}
			}
			else {
				policyEffects[i] = Allow;
			}

			if (model.modelmap["e"]["e"].Value == "priority(p_eft) || deny")
				break;
		}
	}
	else
	{

	}


	try {
		result = MergeEffects(model.modelmap["e"]["e"].Value, policyEffects, matcherResults);
	}
	catch(exception &e){
		cout << e.what() << endl;
		return false;
	}

	return result;
}

bool Enforcer::Enforce(initializer_list<string> rvals)
{

	bool res = false;
	return res;
}


void Enforcer::SetTokenMap(TokenMap& tokenmap, map<string, int>& rTokens, map<string, int>& pTokens, vector<string>& rVals, vector<string>& pVals)
{
	for (auto r : rTokens)
	{
		tokenmap[r.first] = rVals[rTokens[r.first]];
	}
	for (auto p : pTokens)
	{
		tokenmap[p.first] = pVals[pTokens[p.first]];
	}
}

bool Enforcer::MergeEffects(string expr, vector<Effect> effects, vector<double> results)
{
	bool result = false;
	if( expr == "some(where (p_eft == allow))" ){
		result = false;
			for (Effect eft :  effects){
				if (eft == Allow) {
					result = true;
						break;
				}
			}
	}
	else if (expr == "!some(where (p_eft == deny))" ){
		result = true;
			for (Effect eft :  effects){
				if (eft == Deny ){
					result = false;
					break;
				}
			}
	}
	else if (expr == "some(where (p_eft == allow)) && !some(where (p_eft == deny))") {
		result = false;
			for (Effect eft : effects) {
				if (eft == Allow) {
					result = true;
				}
				else if (eft == Deny) {
				result = false;
				break;
				}
			}
	}
	else if (expr == "priority(p_eft) || deny") {
		result = false;
			for (Effect eft : effects) {
				if (eft != Indeterminate) {
					if (eft == Allow) {
						result = true;
					}
					else {
						result = false;
					}
					break;
				}
			}
	}
	else {
		throw Exception("unsupported effect");
		return false; 
	}

	return result;
}