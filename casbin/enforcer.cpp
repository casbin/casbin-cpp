#include"enforcer.h"
#include "./effect/effect.h"
#include "./errors/exceptions.h"
#include"Cparse/shunting-yard.h"
#include "./rbac/default-role-manager/default_role_manager.h"
#include "./util/builtin_operators.h"

using namespace std;
Enforcer::Enforcer()
{

}

Enforcer::~Enforcer()
{
	delete model;
	delete adapter;
	delete rm;

}

Enforcer::Enforcer(const string& modelPath, const string& policyPath)
{
	InitWithFile(modelPath, policyPath);
}

Enforcer::Enforcer(Model* model, Adapter* adapter)
{
	InitWithModelAndAdapter(model, adapter);
}

void Enforcer::Initialize()
{
	rm = new DefaultRoleManager(10);
	fm[KEY_ROLEMANAGER] = Ptype(rm);

	/*
	e.eft = effect.NewDefaultEffector()
	e.watcher = nil
	*/

	enabled = true;
	autoSave = true;
	autoBuildRoleLinks = true;
	autoNotifyWatcher = true;
}

Error Enforcer::BuildRoleLinks()
{
	Error err = rm->Clear();
	if (!err.IsNull()){
		return err;
	}

	return model->BuildRoleLinks(rm);
}

Error Enforcer::InitWithFile(const string& modelPath, const string& policyPath) {
	Error err;
	this->adapter = FileAdapter::newFileAdapter(policyPath);
	this->model = Model::NewModelFromFile(err,modelPath);
	Initialize();
	LoadPolicy();
	return err;
}

Error Enforcer::InitWithAdapter(const string& modelPath, Adapter* adapter)
{
	return Error();
}
Error Enforcer::InitWithModelAndAdapter(Model* m, Adapter* adapter)
{
	this->adapter = adapter;
	this->model = m;
	//this->model.PrintModel();
	//fm = LoadFunctionMap();
	Initialize();
	LoadPolicy();
	return Error();
}

Error Enforcer::LoadPolicy()
{
	model->ClearPolicy();
	adapter->LoadPolicy(model);
	//model.PrintPolicy();
	
	if (autoBuildRoleLinks) {
		Error err = BuildRoleLinks();
		if( !err.IsNull()){
			return err;
		}
	}
	
	return Error();
}

Error Enforcer::LoadFilteredPolicy(Filter* filter)
{
	model->ClearPolicy();
	Filteredadapter* fa = dynamic_cast<Filteredadapter*>(adapter);
	if (fa == NULL) {
		return Error("filtered policies are not supported by this adapter");
	}

	Error err = fa->LoadFilteredPolicy(model, filter);
	if (!err.IsNull() && err.Info() != "invalid file path, file path cannot be empty") {
		return err;
	}

	if (autoBuildRoleLinks) {
		Error err = BuildRoleLinks();
		if (!err.IsNull()) {
			return err;
		}
	}
	return Error();
}

bool Enforcer::enforce(Error& err, const string& matcher, initializer_list<string> rlists)
{
	if (!enabled) {
		err = Error();
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


	for (auto ast : model->modelmap["g"]) {
		rm = ast.second.RM;
		list<string> ls = { "A","B","C" };
		fm[ast.first] = CppFunction(fm, &BuiltinOperators::GFunctionFunc , ls);
	}

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

	vector<string> rVals;
	bool result = false;

	for (auto beg = rlists.begin(); beg != rlists.end();beg++)
	{
		rVals.push_back(*beg);
	}

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
				err = Error(errorInfo);
				return false;
			}

			TokenMap vars;

			vars = fm.getChild();

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


	err = MergeEffects(result,model->modelmap["e"]["e"].Value, policyEffects, matcherResults);
	if (!err.IsNull()) {
		return false;
	}

	err = Error();
	return result;
}

bool Enforcer::Enforce(Error& err, initializer_list<string> rvals)
{

	return enforce(err, "", rvals);
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

Error Enforcer::MergeEffects(bool& res, const string& expr, const vector<Effect>& effects, const vector<double>& results)
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
		res = false;
		return Error("unsupported effect");
	}
	res = result;
	return Error();
}

Error Enforcer::LoadModel() {
	Error err;
	model = Model::NewModelFromFile(err,modelPath);
	if (!err.IsNull()) {
		return err;
	}

	model->PrintModel();
	//fm = model.LoadFunctionMap();

	Initialize();
	return Error();
}

Model* Enforcer::GetModel() {
	return model;
}

void Enforcer::SetModel(Model* model) {
	this->model = model;
}

Adapter* Enforcer::GetAdapter() {
	return adapter;
}

void Enforcer::SetAdapter(Adapter* adapter) {
	this->adapter = adapter;
}
//void SetWatcher(Watcher* watcher);
RoleManager* Enforcer::GetRoleManager() {
	return rm;
}

void Enforcer::SetRoleManager(RoleManager* rm) {
	this->rm = rm;
}

void Enforcer::SetEffector() {

}
void Enforcer::ClearPolicy() {
	model->ClearPolicy();
}
bool Enforcer::IsFiltered() {
	Filteredadapter* fa = dynamic_cast<Filteredadapter*>(adapter);
	if (fa == NULL) {
		return false;
	}
	return fa->IsFiltered();
}

Error Enforcer::SavePolicy() {
	if (IsFiltered()) {
		return Error("cannot save a filtered policy");
	}
	Error err = adapter->SavePolicy(model);
	if (!err.IsNull()) {
		return err;
	}
	/*
		if(watcher != NULL){
			return watcher->Update();
		}
	*/
	return Error();
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