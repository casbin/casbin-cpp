#include "pch.h"
#include "model.h"

bool loadAssertion(Model m, Config c, string sec, string key) {
	string value = c.get(m.sectionNameMap.find(sec)->second + "::" + key);
	return m.addDef(sec, key, value);
}

bool Model::addDef(string sec, string key, string value) {
	if (value == "") return false;
	Assertion ast;
	ast.key = key;
	ast.value = value;

	if (sec == "r" || sec == "p") {
		ast.tokens = split(ast.value, ',');
		for (auto itr = ast.tokens.begin(); itr != ast.tokens.end(); itr++) {
			*itr = key + "_" + *itr;
		}
	}
	else {
		ast.value = escapeAssertion(value);
	}

	if (model.find(sec) == model.end()) {
		AssertionMap temp(key, &ast);
		model.insert(make_pair(sec, &temp));
	}

	return true;
}