#include "model.h"
#include "assertion.h"
#include "../util/util.h"
#include <iostream>
using namespace std;

map<string, string> sectionNameMap = {
   {"r","request_definition"},
   {"p","policy_definition"},
   {"g","role_definition"},
   {"e","policy_effect"},
   {"m","matchers"}
};

const vector<string> requiredSections = { "r","p","e","m" };

Model::Model()
{
	modelmap = {};
}



bool Model::AddDef(string sec, string key, string value)
{
	if (value == "")
	{
		return false;
	}
	Assertion ast = Assertion();
	ast.Key = key;
	ast.Value = value;


	if (sec == "r" || sec == "p")
	{

		ast.Tokens = Util::Split(ast.Value, ",");
		for (int i = 0; i< ast.Tokens.size(); i++)
		{
			ast.Tokens[i] = key + "_" + Util::Trim(ast.Tokens[i]," ");
		}
	}
	else
	{
		ast.Value = Util::RemoveComments(Util::EscapeAssertion(ast.Value));
	}

	modelmap[sec][key] = ast;
	return true;
}



void Model::BuildRoleLinks(RoleManager* rm)
{
	for (auto ast : modelmap["g"]) {
		ast.second.buildRoleLinks(rm);
	}
}


void Model::PrintPolicy()
{

}

void Model::ClearPolicy() 
{
	for (auto& ast : modelmap["p"]) {
		ast.second.Policy.clear();
	}
	for (auto& ast : modelmap["g"]) {
		ast.second.Policy.clear();
	}
}

vector<vector<string>> Model::GetPolicy(const string& sec, const string& ptype)
{
	return modelmap[sec][ptype].Policy;
}

bool Model::AddPolicy(const string& sec, const string& ptype, const vector<string>& rule)
{
	if (!HasPolicy(sec, ptype, rule))
	{
		modelmap[sec][ptype].Policy.push_back(rule);
		return true;
	}
	return false;
}

bool Model::AddPolicies(const string& sec, const string& ptype, const vector<vector<string>>& rules)
{
	for (int i = 0; i < rules.size(); i++){
		if (HasPolicy(sec, ptype, rules[i])) {
			return false;
		}
	}

	for (int i = 0; i < rules.size(); i++) {
		modelmap[sec][ptype].Policy.push_back(rules[i]);
	}
	return true;
}

bool Model::HasPolicy(const string& sec, const  string& ptype, const vector<string>& rule)
{
	for (auto p : modelmap[sec][ptype].Policy)
	{
		if (Util::ArrayEquals(rule, p))
			return true;
	}
	return false;
}

Model* Model::NewModelFromFile(const string& path) {
	Model* m = new Model();
	m->LoadModel(path);
	return m;
}

Model*  Model::NewModelFromString(const string& text) {
	Model* m =new Model();
	m->LoadModelFromText(text);
	return m;
}

Model Model::ModelFromFile(const string& path) {
	Model m = Model();
	m.LoadModel(path);
	return m;
}
Model Model::ModelFromString(const string& text) {
	Model m = Model();
	m.LoadModelFromText(text);
	return m;
}

bool  Model::loadAssertion(Model* model, Config* cfg, const string& sec, const string& key) {
	string value = cfg->String(sectionNameMap[sec] + "::" + key);
	return model->AddDef(sec, key, value);
}

string  Model::getKeySuffix(const int& i) {
	if (i == 1) {
		return "";
	}
	return to_string(i);
}

void  Model::loadSection(Model* model, Config* cfg, const string& sec) {
	int i = 1;
	while (true) {
		if (!loadAssertion(model,cfg, sec, sec + getKeySuffix(i))) {
			break;
		}
		else {
			i++;
		}
	}
}

void Model::LoadModel(const string& path) {
	Config cfg  = Config::NewConfigFromFile(path);
	loadModelFromConfig(&cfg);
}

void Model::LoadModelFromText(const string& text) {
	Config cfg = Config::NewConfigFromText(text);
	loadModelFromConfig(&cfg);
}

void Model::loadModelFromConfig(Config* cfg) {
	for (auto s : sectionNameMap) {
		loadSection(this,cfg,s.first);
	}
	vector<string> ms;
	for (auto rs : requiredSections) {
		if (!HasSection(rs)) {
			ms.push_back(sectionNameMap[rs]);
		}
	}
	if (ms.size() > 0) {
		throw exception("missing required sections");
	}
}

bool Model::HasSection(const string& sec) {
	return modelmap.count(sec);
}

void Model::PrintModel(void)
{

}


vector<vector<string>> Model::GetFilteredPolicy(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& fieldValues) {
	vector<vector<string>> res;

	for (auto rule : modelmap[sec][ptype].Policy) {
		bool matched = true;
		int i = 0;
		for (string fieldValue : fieldValues) {
			if (fieldValue != "" && rule[fieldIndex + i] != fieldValue){
				matched = false;
					break;
			}
		}

		if (matched){
			res.push_back(rule);
		}
	}

	return res;
}

bool Model::RemovePolicy(const string& sec, const  string& ptype, const vector<string>& rule) {
	int i = 0;
	for (auto r : modelmap[sec][ptype].Policy){
		if (Util::ArrayEquals(rule, r)) {
			modelmap[sec][ptype].Policy.erase(modelmap[sec][ptype].Policy.begin()+i);
			return true;
		}
		i++;
	}
	return false;
}

bool Model::RemovePolicies(const string& sec, const string& ptype, const vector<vector<string>>& rules) {
	bool res;
	for (int j = 0; j < rules.size(); j++) {
		int i = 0;
		for (auto r : modelmap[sec][ptype].Policy) {
			if (!Util::ArrayEquals(rules[j], r)) {
				res = false;
				break;
			}
			i++;
		}
		if (!res)
			break;
	}
	if (!res)
		return false;

	for (int j = 0; j < rules.size(); j++) {
		RemovePolicy(sec, ptype, rules[j]);
	}
	return true;
}

bool Model::RemoveFilteredPolicies(const string& sec, const string& ptype, const int& fieldIndex, const vector<string>& fieldValues) {
	vector<vector<string>>tmp;
	bool res = false;
	for (auto rule : modelmap[sec][ptype].Policy) {
		bool matched = true;
		int i = 0;
		for (string fieldValue : fieldValues) {
			if (fieldValue != "" && rule[fieldIndex + i] != fieldValue) {
				matched = false;
				break;
			}
			i++;
		}

		if (matched) {
			res = true;
		} else {
			tmp.push_back(rule);
		}
	}

	modelmap[sec][ptype].Policy = tmp;
	return res;
}

vector<string> Model::GetValuesForFieldInPolicy(const string& sec, const string& ptype, const int& fieldIndex) {
	vector<string> values;

	for(auto rule :modelmap[sec][ptype].Policy) {
		values.push_back(rule[fieldIndex]);
	}

	Util::ArrayRemoveDuplicates(&values);

	return values;
}

vector<string> Model::GetValuesForFieldInPolicyAllTypes(const string& sec, const int& fieldIndex) {
	vector<string> values;

	for (auto ptype : modelmap[sec]) {
		vector<string> v=GetValuesForFieldInPolicy(sec, ptype.first, fieldIndex);
		values.insert(values.end(),v.begin(),v.end());
	}

	Util::ArrayRemoveDuplicates(&values);

	return values;
}