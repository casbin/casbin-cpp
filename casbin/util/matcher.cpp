#include "matcher.h"

// Injects value from the structure to the equation
string Matcher::injectValue(map<string, string> structure, string equation) {
	for (auto& value : structure) {
		regex e(value.first);
		equation = regex_replace(equation, e, value.second);
	}

	return equation;
 }

// Parses the equation using recursive descent tree.
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

void printStructure(map<string, string> structure) {
	for (auto& kv : structure) {
		cout << kv.first << ":" << kv.second << "0";
	}
}

// Returns the final result of the evaluation
bool Matcher::eval(map<string, string> struc, string equation) {
	string temp = injectValue(struc, equation);
	temp = parseString(temp);
	if (temp == "true") return true;
	return false;
}