#pragma once

#ifndef POLICYMANAGER_H
#define POLICYMANAGER_H

#endif

#include <string>
#include <map>
#include "csv_adapter.h"

using namespace std;

class PolicyManager {
	CSVAdapter adapter;
	map<string, vector<vector<string>>> policies;
public:
	PolicyManager() {

	}
	PolicyManager(string p) {
		adapter.readFile(p);
	}
	void injectIntoPolicies(vector<vector<string>>);
	void readPolicy(string);
	vector<vector<string>> getFilteredPolicy(string);
	vector<vector<string>> getPolicy();
};