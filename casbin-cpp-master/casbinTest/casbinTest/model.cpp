#include "model.h"
#include "assertion.h"
#include "util.h"
#include <iostream>
using namespace std;

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
		ast.Tokens = Util::Split(ast.Value, ", ");
		for (int i = 0; i< ast.Tokens.size(); i++)
		{
			ast.Tokens[i] = key + "_" + ast.Tokens[i];
		}
	}
	else
	{
		ast.Value = Util::RemoveComments(Util::EscapeAssertion(ast.Value));
	}
	modelmap[sec][key] = ast;
	return true;
}


/*
void Model::BuildRoleLinke()
{

}
*/
void Model::PrintPolicy()
{
	cout << "--------------------Policy------------------"<<endl;
	for (auto ast : modelmap["p"]) {
		cout << "key:" << ast.first << " value: " << ast.second.Value << "" << endl;
		cout << "Policies:"<<endl;
		for (auto v : ast.second.Policy)
		{
			cout << Util::ArrayToString(v) << endl;
		}
	}
	cout << "--------------------Policy------------------" << endl;
}
void Model::ClearPolicy() 
{
	for (auto ast : modelmap["p"]) {
		ast.second.Policy.clear();
	}
	for (auto ast : modelmap["g"]) {
		ast.second.Policy.clear();
	}
}
vector<vector<string>> Model::GetPolicy(string sec, string ptype)
{
	return modelmap[sec][ptype].Policy;
}

/*vector<vector<string>> Model::GetFilteredPolicy(string sec, string ptype, int fieldIndex, string ...)
{
	// !!
	vector<vector<string>> s;
	return s;
}*/

bool Model::AddPolicy(string sec, string ptype, vector<string> rule)
{
	if (!HasPolicy(sec, ptype, rule))
	{
		modelmap[sec][ptype].Policy.push_back(rule);
		return true;
	}
	return false;
}

bool Model::AddPolicies(string sec, string ptype, vector<vector<string>> rules)
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

bool Model::HasPolicy(string sec, string ptype, vector<string> rule)
{
	for (auto p : modelmap[sec][ptype].Policy)
	{
		if (Util::ArrayEquals(rule, p))
			return true;
	}
	return false;
}