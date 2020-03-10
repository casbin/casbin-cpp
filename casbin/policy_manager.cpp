#include "pch.h"
#include "policy_manager.h"

void PolicyManager::injectIntoPolicies(vector<vector<string>> temp) {
	for (vector<string> ele : temp) {
		string key = ele.at(0);
		if (policies.find(key) != policies.end()) {
			ele.erase(ele.begin(), ele.begin() + 1);
			policies.find(key)->second.push_back(ele);
		}
		else {
			policies.insert({ key, {ele} });
		}
	}
}

void PolicyManager::readPolicy(string fileName) {
	adapter.readFile(fileName);
	injectIntoPolicies(adapter.getData());
}

vector<vector<string>> PolicyManager::getFilteredPolicy(string key) {
	return policies.find(key)->second;
}

vector<vector<string>> PolicyManager::getPolicy() {
	return adapter.getData();
}

