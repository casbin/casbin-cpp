#include "matcher.h"

// Injects value from the structure to the equation
string Matcher::injectValue(map<string, string> structure, string equation) {
	for (auto& value : structure) {
		regex e(value.first);
		equation = regex_replace(equation, e, value.second);
	}

	return equation;
 }

string Matcher::parseFunctions(map<string, string> structure, string line) {
	smatch m;

	// Check for functions and operate on them
	for (auto itr = functions.begin(); itr != functions.end(); itr++) {
		string temp = regex_replace(line, regex(" "), ""); // Remove all whitespaces from the string
		while (regex_search(temp, m, regex(itr->first + "\\(.*?\\)"))) {
			regex_search(temp, m, regex("\\(.*?\\)")); // Get content inside the paranthensis
			temp = m.str();
			temp = temp.substr(1, temp.size() - 2);
			vector<string> arr = split(temp, ',');

			if (structure.find(arr[0]) != structure.end() && structure.find(arr[1]) != structure.end()) {
				bool result = itr->second(structure.find(arr[0])->second, structure.find(arr[1])->second);
				if (result) line = regex_replace(line, regex(itr->first + "\\(.*?\\)"), "true");
				else line = regex_replace(line, regex(itr->first + "\\(.*?\\)"), "false");
			}
		}
	}

	return trim(line);
}

// Parses the equation using recursive descent tree.
string Matcher::parseString(string line)
{
	line = trim(line);
	regex e("\\([^(].*?\\)"); // Check for inner parathensis
	smatch m;

	// Parse all the values in the parathensis
	while (regex_search(line, m, e)) {
		string temp = m.str();
		temp.erase(0, 1);
		temp.erase(temp.length() - 1);
		line = regex_replace(line, e, parseString(temp));
	}

	// Check for symbol and operate the expression 
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

// Returns the final result of the evaluation
bool Matcher::eval(map<string, string> struc, string equation) {
	string temp = parseFunctions(struc, equation);
	temp = injectValue(struc, temp);
	temp = parseString(temp);
	if (temp == "true") return true;
	return false;
}