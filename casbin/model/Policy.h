#ifndef CASBIN_CPP_MODEL_POLICY
#define CASBIN_CPP_MODEL_POLICY

#include <unordered_map>
#include <string>
#include <vector>

#include "../rbac/RoleManager.h"
#include "./Model.h"
#include "../log/Logger.h"
#include "../util/arrayEquals.h"
#include "../util/arrayRemoveDuplicates.h"

using namespace std;

// BuildRoleLinks initializes the roles in RBAC.
void Model::BuildRoleLinks(RoleManager* rm) {
    for(unordered_map <string, Assertion *> :: iterator it = this->M["g"].AMap.begin() ; it != this->M["g"].AMap.end() ; it++) {
        (it->second)->buildRoleLinks(rm);
    }
}

// PrintPolicy prints the policy to log.
void Model::PrintPolicy() {
	DefaultLogger df_logger;
	df_logger.EnableLog(true);

	Logger *logger = &df_logger;
	LogUtil::SetLogger(*logger);

	LogUtil::LogPrint("Policy:");

    for(unordered_map <string, Assertion *> :: iterator it = this->M["p"].AMap.begin() ; it != this->M["p"].AMap.end() ; it++) {
        LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->Policy);
    }

    for(unordered_map <string, Assertion *> :: iterator it = this->M["g"].AMap.begin() ; it != this->M["g"].AMap.end() ; it++) {
        LogUtil::LogPrint(it->first, ": ", (it->second)->Value, ": ", (it->second)->Policy);
    }
}

// ClearPolicy clears all current policy.
void Model::ClearPolicy() {
	for(unordered_map <string, Assertion *> :: iterator it = this->M["p"].AMap.begin() ; it != this->M["p"].AMap.end() ; it++) {
        (it->second)->Policy.clear();
    }

	for(unordered_map <string, Assertion *> :: iterator it = this->M["g"].AMap.begin() ; it != this->M["g"].AMap.end() ; it++) {
        (it->second)->Policy.clear();
	}
}

// GetPolicy gets all rules in a policy.
vector < vector < string > > Model::GetPolicy(string sec, string ptype) {
	return (this->M)[sec].AMap[ptype]->Policy;
}

// GetFilteredPolicy gets rules based on field filters from a policy.
vector < vector < string > > Model::GetFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues) {
	vector < vector < string > > res;

	for( vector < vector < string > > :: iterator it1 = M[sec].AMap[ptype]->Policy.begin() ; it1 != M[sec].AMap[ptype]->Policy.end() ; it1++){
		bool matched = true;
		for(int i = 0 ; i < fieldValues.size() ; i++){
			if(fieldValues[i] != "" && (*it1)[fieldIndex + i] != fieldValues[i] ){
				matched = false;
				break;
			}
		}
		if(matched) {
			res.push_back(*it1);
		}
	}

	return res;
}

// HasPolicy determines whether a model has the specified policy rule.
bool Model::HasPolicy(string sec, string ptype, vector <string> rule) {
	for(vector < vector < string > > :: iterator it = M[sec].AMap[ptype]->Policy.begin() ; it != M[sec].AMap[ptype]->Policy.end() ; it++){
		if(arrayEquals(rule, *it)){
			return true;
		}
	}

	return false;
}

// AddPolicy adds a policy rule to the model.
bool Model::AddPolicy(string sec, string ptype,  vector <string> rule) {
	if(!this->HasPolicy(sec, ptype, rule)) {
		M[sec].AMap[ptype]->Policy.push_back(rule);
		return true;
	}
	return false;
}

// RemovePolicy removes a policy rule from the model.
bool Model::RemovePolicy(string sec, string ptype, vector <string> rule) {
	for(int i = 0 ; i < M[sec].AMap[ptype]->Policy.size() ; i++){
		if(arrayEquals(rule, M[sec].AMap[ptype]->Policy[i])) {
			for(int j = i + 1 ; j < M[sec].AMap[ptype]->Policy.size() ; j++){
				M[sec].AMap[ptype]->Policy.push_back(M[sec].AMap[ptype]->Policy[j]);
			}
			return true;
		}
	}

	return false;
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
bool Model::RemoveFilteredPolicy(string sec, string ptype, int fieldIndex, vector <string> fieldValues) {
	vector < vector < string > > tmp;
	bool res = false;
	for(vector < vector < string > > :: iterator it = M[sec].AMap[ptype]->Policy.begin() ; it != M[sec].AMap[ptype]->Policy.end() ; it++){
		bool matched = true;
		for(int i = 0 ; i < fieldValues.size() ; i++){
			if(fieldValues[i] != "" && (*it)[fieldIndex+i] != fieldValues[i]) {
				matched = false;
				break;
			}
		}
		if(matched) {
			res = true;
		} else {
			tmp.push_back(*it);
		}
	}

	M[sec].AMap[ptype]->Policy = tmp;
	return res;
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
vector <string> Model::GetValuesForFieldInPolicy(string sec, string ptype, int fieldIndex) {
	vector <string> values;

	for(vector < vector < string > > :: iterator it = M[sec].AMap[ptype]->Policy.begin() ; it != M[sec].AMap[ptype]->Policy.end() ; it++){
		values.push_back((*it)[fieldIndex]);
	}

	arrayRemoveDuplicates(values);

	return values;
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
vector <string> Model::GetValuesForFieldInPolicyAllTypes(string sec, int fieldIndex) {
	vector <string> values;

	for(unordered_map <string, Assertion*> :: iterator it = M[sec].AMap.begin() ; it != M[sec].AMap.end() ; it++){
		for(vector <string> :: iterator it1 = this->GetValuesForFieldInPolicy(sec, it->first, fieldIndex).begin() ; it1 != this->GetValuesForFieldInPolicy(sec, it->first, fieldIndex).end() ; it1++) {
			values.push_back(*it1);
		}
	}

	arrayRemoveDuplicates(values);

	return values;
}

#endif