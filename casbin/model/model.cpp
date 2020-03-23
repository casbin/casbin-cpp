#include "model.h"

string getKeySuffix(int i) {
	if (i == 1) {
		return "";
	}

	return to_string(i);
}

bool Model::loadAssertion(Config c, string sec, string key) {
	string value = c.get(sectionNameMap.find(sec)->second + "::" + key);
	return addDef(sec, key, value);
}

bool Model::addDef(string sec, string key, string value) {
	if (value == "") return false;
	Assertion* ast = new Assertion();
	ast->key = key;
	ast->value = value;

	// Stores tokens in assertion such as r_sub, p_sub
	if (sec == "r" || sec == "p") {
		ast->tokens = split(ast->value, ',');
		for (auto itr = ast->tokens.begin(); itr != ast->tokens.end(); itr++) {
			*itr = trim(*itr);
			*itr = key + "_" + *itr;
		}
	}
	else {
		ast->value = escapeAssertion(value); // Replaces r.sub in matcher to p_sub
	}

	if (model.find(sec) == model.end()) {
		AssertionMap* temp = new AssertionMap(key, ast);
		model.insert(make_pair(sec, temp));
	}

	return true;
}

void Model::loadModel(string filePath) {
	Config cfg = Config(filePath);
	loadModelFromConfig(cfg);
}

void Model::loadModelFromConfig(Config cfg) {
	for (auto& sectionName : sectionNameMap) {
		loadSection(cfg, sectionName.first);
	}

	vector<string> ms;
	for (string rs : requiredSections) {
		if (!hasSection(rs)) ms.push_back(sectionNameMap.find(rs)->second);
	}
	if (ms.size() > 0) cout << "Missing sections are: " << join(ms, ',');
}

void Model::loadSection(Config cfg, string sec) {
	int i = 1;
	while (true) {
		if (!loadAssertion(cfg, sec, sec + getKeySuffix(i))) break;
		else i++;
	}
}

bool Model::hasSection(string sec) {
	return model.find(sec) != model.end();
}

void Model::printModel() {
	for (auto& item : model) {
		for (auto& assertion : item.second->data) {
			printf("%s.%s: %s \n", item.first.c_str(), assertion.first.c_str(), assertion.second->value.c_str());
		}
	}
}