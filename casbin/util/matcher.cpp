#include "matcher.h"

// Injects value from the structure to the equation
string matcher::inject_value(const unordered_map<string, string>& structure, string equation) const
{
	for (auto& value : structure) {
		regex e(value.first);
		equation = regex_replace(equation, e, value.second);
	}

	return equation;
 }

string matcher::parse_functions(unordered_map<string, string> structure, string line) {
	smatch m;

	// Check for functions and operate on them
	for (auto itr = functions_.begin(); itr != functions_.end(); ++itr) {
		auto temp = regex_replace(line, regex(" "), ""); // Remove all whitespaces from the string
		while (regex_search(temp, m, regex(itr->first + "\\(.*?\\)"))) {
			regex_search(temp, m, regex("\\(.*?\\)")); // Get content inside the parenthesis
			temp = m.str();
			temp = temp.substr(1, temp.size() - 2);
			auto arr = split(temp, ',');

			if (structure.find(arr[0]) != structure.end() && structure.find(arr[1]) != structure.end()) {
				const auto result = itr->second(structure.find(arr[0])->second, structure.find(arr[1])->second);
				if (result) line = regex_replace(line, regex(itr->first + "\\(.*?\\)"), "true");
				else line = regex_replace(line, regex(itr->first + "\\(.*?\\)"), "false");
			}
		}
	}

	return trim(line);
}

matcher::matcher()
= default;

// Parses the equation using recursive descent tree.
string matcher::parse_string(string line) const
{
	line = trim(line);
	regex e("\\([^(].*?\\)"); // Check for inner parenthesis
	smatch m;

	// Parse all the values in the parenthesis
	while (regex_search(line, m, e)) {
		string temp = m.str();
		temp.erase(0, 1);
		temp.erase(temp.length() - 1);
		line = regex_replace(line, e, parse_string(temp));
	}

	// Check for symbol and operate the expression 
	for (auto op : known_operators_)
	{
		const auto location = line.find(op->symbol);
		if (location != std::string::npos)
		{
			return op->operate(parse_string(line.substr(0, location - 1)), parse_string(line.substr(location + op->symbol.length())));
		}
	}

	return trim(line);
}

// Returns the final result of the evaluation
auto matcher::eval(const unordered_map<string, string>& struc, const string equation) -> bool
{
	auto temp = parse_functions(struc, equation);
	temp = inject_value(struc, temp);
	temp = parse_string(temp);
	if (temp == "true") return true;
	return false;
}
