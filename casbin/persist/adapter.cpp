#include "adapter.h"

void Adapter::loadPolicyLine(string line, Model* model) {
	if (line == "" || *line.begin() == '#') {
		return;
	}

	vector<string> tokens = split(line, ',');
	for (auto itr = tokens.begin(); itr != tokens.end(); itr++) {
		*itr = trim(*itr);
	}

	vector<string> result = vector(tokens.begin() + 1, tokens.end());
	string key = tokens[0];
	string sec = key.substr(0, 1);
	AssertionMap* tempasm = model->model.find(sec)->second;
	Assertion* tempas = tempasm->data.find(key)->second;
	tempas->policy.push_back(result);
}