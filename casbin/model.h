#pragma once

#ifdef CASBIN_EXPORTS
#define MODEL_API __declspec(dllexport)
#else
#define MODEL_API __declspec(dllimport)
#endif

#include <string>
#include "config.h"

using namespace std;

class MODEL_API Model {
	Config adapter;
	map<string, string> model;
public:
	Model() {

	}
	Model(string fileName) {
		adapter.readFile(fileName);
		injectIntoModel();
	}
	void injectIntoModel();
	void readModel(string fileName);
	map<string, vector<string>> getRPStructure();
	string getPolicyEffect();
	string getMatcherString();
};