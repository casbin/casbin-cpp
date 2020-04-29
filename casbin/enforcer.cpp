#include"enforcer.h"
#include "./effect/effect.h"
#include"third_party/Cparse/shunting-yard.h"
#include "./rbac/default-role-manager/default_role_manager.h"
#include "./util/builtin_operators.h"

using namespace std;
Enforcer::Enforcer()
{

}

Enforcer::~Enforcer()
{

}

Enforcer::Enforcer(Enforcer& e) {
	modelPath=e.modelPath;
	model = move(e.model);
	eft = e.eft;
	tm = e.tm;
	fm = e.fm;
	adapter = move(e.adapter);
	//Watcher* watcher;
	rm = move(e.rm);
	enabled = e.enabled;
	autoSave = e.autoSave;
	autoBuildRoleLinks = e.autoBuildRoleLinks;
	autoNotifyWatcher = e.autoNotifyWatcher;
}

Enforcer::Enforcer(const string& modelPath, const string& policyPath)
{
	InitWithFile(modelPath, policyPath);
}


Enforcer::Enforcer(unique_ptr<Model>& model, unique_ptr<Adapter>& adapter)
{
	InitWithModelAndAdapter(model, adapter);
}

Enforcer::Enforcer(const string& modelPath) {

	this->adapter = unique_ptr<Adapter>(FileAdapter::newFileAdapter());
	this->model = unique_ptr<Model>(Model::NewModelFromFile(modelPath));
	fm = FunctionMap::LoadFunctionMap();
	Initialize();
	LoadPolicy();
}

void Enforcer::Initialize()
{
	rm = unique_ptr<RoleManager>( new DefaultRoleManager(10));

	/*
	e.eft = effect.NewDefaultEffector()
	e.watcher = nil
	*/

	enabled = true;
	autoSave = true;
	autoBuildRoleLinks = true;
	autoNotifyWatcher = true;
}

void Enforcer::BuildRoleLinks()
{
	rm->Clear();

	return model->BuildRoleLinks(rm.get());
}

void Enforcer::InitWithFile(const string& modelPath, const string& policyPath) {
	this->adapter = unique_ptr<Adapter> (FileAdapter::newFileAdapter(policyPath));
	this->model = unique_ptr<Model>(Model::NewModelFromFile(modelPath));
	fm = FunctionMap::LoadFunctionMap();
	Initialize();
	LoadPolicy();
}

void Enforcer::InitWithAdapter(const string& modelPath, unique_ptr<Adapter>& adapter)
{

}

void Enforcer::InitWithModelAndAdapter(unique_ptr<Model>& m, unique_ptr<Adapter>& adapter)
{
	this->adapter = move(adapter);
	this->model = move(m);
	fm = FunctionMap::LoadFunctionMap();
	//this->model.PrintModel();
	Initialize();
	LoadPolicy();
}

void Enforcer::LoadPolicy()
{
	model->ClearPolicy();
	try {
		adapter->LoadPolicy(model.get());
	}
	catch (exception& e) {

	}

	model->PrintModel();
	//model.PrintPolicy();
	if (autoBuildRoleLinks) {
		BuildRoleLinks();
	}
	
	tm = TokenMap();

	tm[KEY_ROLEMANAGER] = Ptype(rm.get());

	for (auto element : fm.fm) {
		tm[element.first] = element.second;
	}

	for (auto ast : model->modelmap["g"]) {
		//rm = ast.second.RM;
		list<string> ls = { "A","B","C" };
		tm[ast.first] = CppFunction(tm, &BuiltinOperators::GFunctionFunc, ls);
	}
}

void Enforcer::LoadFilteredPolicy(Filter* filter)
{
	model->ClearPolicy();
	Filteredadapter* fa = dynamic_cast<Filteredadapter*>(adapter.get());
	if (fa == NULL) {
		throw exception("filtered policies are not supported by this adapter");
	}

	try {
		fa->LoadFilteredPolicy(model.get(), filter);
	}
	catch (exception& e) {
		if (e.what() != "invalid file path, file path cannot be empty") {
			throw e;
		}
	}

	if (autoBuildRoleLinks) {
		BuildRoleLinks();
	}

	tm = TokenMap();

	tm[KEY_ROLEMANAGER] = Ptype(rm.get());

	for (auto element : fm.fm) {
		tm[element.first] = element.second;
	}

	for (auto ast : model->modelmap["g"]) {
		//rm = ast.second.RM;
		list<string> ls = { "A","B","C" };
		tm[ast.first] = CppFunction(tm, &BuiltinOperators::GFunctionFunc, ls);
	}
}



bool Enforcer::enforce(const string& matcher,  vector<string> rVals)
{
	if (!enabled) {
		return true;
	}

	/*

	for k, v := range e.fm {
		functions[k] = v
	}

	if _, ok : = e.model["g"]; ok{
		for key, ast : = range e.model["g"] {
			rm: = ast.RM
			functions[key] = util.GenerateGFunction(rm)
		}
	}
	*/


	string expString;
	if (matcher == ""){
		expString = model->modelmap["m"]["m"].Value;
	}
	else {
		expString = matcher;
	}

	calculator c1;
	c1 = calculator(expString.data());

	map<string, int> rTokens, pTokens;

	bool result = false;

	vector<string>* r = &model->modelmap["r"]["r"].Tokens;
	for (int i=0;i< (*r).size();i++){
		rTokens[(*r)[i]] = i;
	}

	vector<string>* p = &model->modelmap["p"]["p"].Tokens;
	for (int i = 0; i < (*p).size(); i++) {
		pTokens[(*p)[i]] = i;
	}



	int policyLen = model->modelmap["p"]["p"].Policy.size();
	vector<Effect> policyEffects = vector<Effect>(policyLen);
	vector<double> matcherResults = vector<double>(policyLen);

	if (policyLen != 0){
		for (int i = 0; i < policyLen;i++) {
			vector<string> pVals = model->modelmap["p"]["p"].Policy[i];
			if (model->modelmap["r"]["r"].Tokens.size() != rVals.size())
			{
				string errorInfo;
				stringstream ss;
				ss << "invalid policy size: expected "
					<< model->modelmap["r"]["r"].Tokens.size()
					<< ", got " << pVals.size() << ", pvals: "
					<< Util::ArrayToString(pVals) << endl;
				ss >> errorInfo;
				throw exception(errorInfo.data());
				return false;
			}

			TokenMap vars;

			vars = tm.getChild();

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

			if (model->modelmap["e"]["e"].Value == "priority(p_eft) || deny")
				break;
		}
	}
	else
	{

	}

	try {
		result = MergeEffects(model->modelmap["e"]["e"].Value, policyEffects, matcherResults);
	}
	catch (exception& e) {
		return false;
	}

	return result;
}

bool Enforcer::Enforce(const vector<string>& rvals)
{
	return enforce("", rvals);
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

bool Enforcer::MergeEffects(const string& expr, const vector<Effect>& effects, const vector<double>& results)
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
		throw exception("unsupported effect");
		//return false;
	}
	return result;
}

void Enforcer::LoadModel() {
	model = unique_ptr<Model>(Model::NewModelFromFile(modelPath));

	model->PrintModel();
	fm = FunctionMap::LoadFunctionMap();

	Initialize();
}

unique_ptr<Model>& Enforcer::GetModel() {
	return model;
}

void Enforcer::SetModel(unique_ptr<Model>& model) {
	this->model=move(model);
}

unique_ptr<Adapter>& Enforcer::GetAdapter() {
	return adapter;
}

void Enforcer::SetAdapter(unique_ptr<Adapter>& adapter) {
	this->adapter = move(adapter);
}
//void SetWatcher(Watcher* watcher);
unique_ptr<RoleManager>& Enforcer::GetRoleManager() {
	return rm;
}

void Enforcer::SetRoleManager(unique_ptr<RoleManager>& rm) {
	this->rm = move(rm);
}

void Enforcer::SetEffector() {

}
void Enforcer::ClearPolicy() {
	model->ClearPolicy();
}
bool Enforcer::IsFiltered() {
	Filteredadapter* fa = dynamic_cast<Filteredadapter*>(adapter.get());
	if (fa == NULL) {
		return false;
	}
	return fa->IsFiltered();
}

void Enforcer::SavePolicy() {
	if (IsFiltered()) {
		throw exception("cannot save a filtered policy");
	}
	adapter->SavePolicy(model.get());
	/*
		if(watcher != NULL){
			return watcher->Update();
		}
	*/
}

void  Enforcer::EnableEnforce(const bool& enable) {
	enabled = enable;
}

void  Enforcer::EnableLog(const bool& enable) {
	//
}

void  Enforcer::EnableAutoNotifyWatcher(const bool& enable) {
	autoNotifyWatcher = enable;
}

void  Enforcer::EnableAutoSave(const bool& enable) {
	autoSave = autoSave;
}

void  Enforcer::EnableAutoBuildRoleLinks(const bool& enable) {
	autoBuildRoleLinks = autoBuildRoleLinks;
}