#include "pch.h"
#include "matcher.h"

bool Matcher::mergeDecisions(vector<string> policyeffects) {
	if (policyeffect == "some(where (p.eft == allow))") {
		for (string ele : policyeffects) {
			if (ele == "true") return true;
		}
		return false;
	}
	else if (policyeffect == "!some(where (p.eft == deny))") {
		for (string ele : policyeffects) {
			if (ele == "false") return false;
		}
		return true;
	}
	return false;
}

string Matcher::injectValue(map<string, vector<string>> structure, string request, string policy, string equation) {
	vector<string> rarr = split(request, ',');
	vector<string> parr = split(policy, ',');
	int i = 0;

	for (string ele : structure.find("request_definition")->second) {
		regex e(ele);
		equation = regex_replace(equation, e, rarr.at(i));
		i++;
	}
	
	i = 0;
	for (string ele : structure.find("policy_definition")->second) {
		regex e(ele);
		equation = regex_replace(equation, e, parr.at(i));
		i++;
	}

	return equation;
 }

string Matcher::parseString(string line)
{
	line = trim(line);
	regex e("\\([^(].*?\\)");
	smatch m;

	while (regex_search(line, m, e)) {
		string temp = m.str();
		temp.erase(0, 1);
		temp.erase(temp.length() - 1);
		line = regex_replace(line, e, parseString(temp));
	}

	for (Operator* op : knownOperators)
	{
		size_t location = line.find(op->symbol);
		if (location != std::string::npos)
		{
			return op->operate(parseString(line.substr(0, location - 1)), parseString(line.substr(location + op->symbol.length())));
		}
	}

	return trim(line);
}

bool Matcher::addPolicyEffect(string p) {
	policyeffect = p;
	return true;
}