#ifndef CASBIN_CPP_MANAGEMENT_API
#define CASBIN_CPP_MANAGEMENT_API

#include "./enforcer.h"

// GetAllSubjects gets the list of subjects that show up in the current policy.
vector<string> Enforcer :: GetAllSubjects() {
	return this->model.GetValuesForFieldInPolicyAllTypes("p", 0);
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedSubjects(string ptype) {
	return this->model.GetValuesForFieldInPolicy("p", ptype, 0);
}

// GetAllObjects gets the list of objects that show up in the current policy.
vector<string> Enforcer :: GetAllObjects() {
	return this->model.GetValuesForFieldInPolicyAllTypes("p", 1);
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedObjects(string ptype) {
	return this->model.GetValuesForFieldInPolicy("p", ptype, 1);
}

// GetAllActions gets the list of actions that show up in the current policy.
vector<string> Enforcer :: GetAllActions() {
	return this->model.GetValuesForFieldInPolicyAllTypes("p", 2);
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedActions(string ptype) {
	return this->model.GetValuesForFieldInPolicy("p", ptype, 2);
}

// GetAllRoles gets the list of roles that show up in the current policy.
vector<string> Enforcer :: GetAllRoles() {
	return this->model.GetValuesForFieldInPolicyAllTypes("g", 1);
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
vector<string> Enforcer :: GetAllNamedRoles(string ptype) {
	return this->model.GetValuesForFieldInPolicy("g", ptype, 1);
}

// GetPolicy gets all the authorization rules in the policy.
vector<vector<string>> Enforcer :: GetPolicy() {
	return this->GetNamedPolicy("p");
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredPolicy(int fieldIndex, vector<string> fieldValues) {
	return this->GetFilteredNamedPolicy("p", fieldIndex, fieldValues);
}

// GetNamedPolicy gets all the authorization rules in the named policy.
vector<vector<string>> Enforcer :: GetNamedPolicy(string ptype) {
	return this->model.GetPolicy("p", ptype);
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
	return this->model.GetFilteredPolicy("p", ptype, fieldIndex, fieldValues);
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> Enforcer :: GetGroupingPolicy() {
	return this->GetNamedGroupingPolicy("g");
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues) {
	return this->GetFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
vector<vector<string>> Enforcer :: GetNamedGroupingPolicy(string ptype) {
	return this->model.GetPolicy("g", ptype);
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
vector<vector<string>> Enforcer :: GetFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
	return this->model.GetFilteredPolicy("g", ptype, fieldIndex, fieldValues);
}

// HasPolicy determines whether an authorization rule exists.
bool Enforcer :: HasPolicy(vector<string> params) {
	return this->HasNamedPolicy("p", params);
}

// HasNamedPolicy determines whether a named authorization rule exists.
bool Enforcer :: HasNamedPolicy(string ptype, vector<string> params) {
	if(params.size() == 1){
		vector<string> strSlice{params[0]};
		return this->model.HasPolicy("p", ptype, strSlice);
	}

	vector<string> policy;
	for(int i = 0 ; i < params.size() ; i++)
		policy.push_back(params[i]);
	return this->model.HasPolicy("p", ptype, policy);
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddPolicy(vector<string> params) {
	return this->AddNamedPolicy("p", params);
}


// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddNamedPolicy(string ptype, vector<string> params) {
	if(params.size() == 1){
		vector<string> strSlice{params[0]};
		return this->addPolicy("p", ptype, strSlice);
	}

	vector<string> policy;
	for(int i = 0 ; i < params.size() ; i++)
		policy.push_back(params[i]);
	return this->addPolicy("p", ptype, policy);
}

// RemovePolicy removes an authorization rule from the current policy.
bool Enforcer :: RemovePolicy(vector<string> params) {
	return this->RemoveNamedPolicy("p", params);
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
bool Enforcer :: RemoveFilteredPolicy(int fieldIndex, vector<string> fieldValues) {
	return this->RemoveFilteredNamedPolicy("p", fieldIndex, fieldValues);
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
bool Enforcer :: RemoveNamedPolicy(string ptype, vector<string> params) {
	if(params.size() == 1){
		vector<string> strSlice{params[0]};
		return this->removePolicy("p", ptype, strSlice);
	}

	vector<string> policy;
	for(int i = 0 ; i < params.size() ; i++)
		policy.push_back(params[i]);
	return this->removePolicy("p", ptype, policy);
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
	return this->removeFilteredPolicy("p", ptype, fieldIndex, fieldValues);
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
bool Enforcer :: HasGroupingPolicy(vector<string> params) {
	return this->HasNamedGroupingPolicy("g", params);
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
bool Enforcer :: HasNamedGroupingPolicy(string ptype, vector<string> params) {
	if(params.size() == 1){
		vector<string> strSlice{params[0]};
		return this->model.HasPolicy("g", ptype, strSlice);
	}

	vector<string> policy;
	for(int i = 0 ; i < params.size() ; i++)
		policy.push_back(params[i]);
	return this->model.HasPolicy("g", ptype, policy);
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddGroupingPolicy(vector<string> params) {
	return this->AddNamedGroupingPolicy("g", params);
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
bool Enforcer :: AddNamedGroupingPolicy(string ptype, vector<string> params) {
	bool ruleAdded ;
	if(params.size() == 1) {
		vector<string> strSlice{params[0]};
		ruleAdded = this->addPolicy("g", ptype, strSlice);
	} else {
		vector<string> policy;
		for(int i = 0 ; i < params.size() ; i++)
			policy.push_back(params[i]);

		ruleAdded = this->addPolicy("g", ptype, policy);
	}

	if(this->autoBuildRoleLinks)
		this->BuildRoleLinks();

	return ruleAdded;
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
bool Enforcer :: RemoveGroupingPolicy(vector<string> params) {
	return this->RemoveNamedGroupingPolicy("g", params);
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
bool Enforcer :: RemoveFilteredGroupingPolicy(int fieldIndex, vector<string> fieldValues ) {
	return this->RemoveFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues);
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
bool Enforcer :: RemoveNamedGroupingPolicy(string ptype, vector<string> params) {
	bool ruleRemoved;
	if(params.size() == 1){
		vector<string> strSlice{params[0]};
		ruleRemoved = this->removePolicy("g", ptype, strSlice);
	} else {
		vector<string> policy;
		for(int i = 0 ; i < params.size() ; i++)
			policy.push_back(params[i]);

		ruleRemoved = this->removePolicy("g", ptype, policy);
	}

	if(this->autoBuildRoleLinks)
		this->BuildRoleLinks();

	return ruleRemoved;
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
bool Enforcer :: RemoveFilteredNamedGroupingPolicy(string ptype, int fieldIndex, vector<string> fieldValues) {
	bool ruleRemoved = this->removeFilteredPolicy("g", ptype, fieldIndex, fieldValues);

	if(this->autoBuildRoleLinks)
		this->BuildRoleLinks();

	return ruleRemoved;
}

// AddFunction adds a customized function.
void Enforcer :: AddFunction(string name, Function function) {
	this->fm.AddFunction(name, function);
}

#endif