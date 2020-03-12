#include "pch.h"
#include "model.h"

void Model::injectIntoModel() {
	for (string section : adapter.getSections()) {
		string line = adapter.getSectionData(section).at(0);
		vector<string> linearr;
		linearr.push_back(line.substr(0, line.find_first_of('=')));
		linearr.push_back(line.substr(line.find_first_of('=')+1));
		if (section == "request_definition" || section == "policy_definition") {
			vector<string> lhsarr = split(trim(linearr.at(1)), ',');
			for (auto itr = lhsarr.begin(); itr != lhsarr.end(); itr++) {
				*itr = trim(linearr.at(0)) + "." + trim(*itr);
			}
			model.insert({ section,  join(lhsarr, ',') });
		}
		else {
			model.insert({ section,  trim(linearr.at(1)) });
		}
	}
}

void Model::readModel(string fileName) {
	adapter.readFile(fileName);
	injectIntoModel();
}

map<string, vector<string>> Model::getRPStructure() {
	map<string, vector<string>> temp;
	temp.insert({ "request_definition", split(model.find("request_definition")->second, ',') });
	temp.insert({ "policy_definition", split(model.find("policy_definition")->second, ',') });

	return temp;
}

string Model::getPolicyEffect() {
	return model.find("policy_effect")->second;
}

string Model::getMatcherString() {
	return model.find("matchers")->second;
}

