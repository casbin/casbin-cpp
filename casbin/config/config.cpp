#include "config.h"

const string DEFAULT_SECTION = "default";

void Config::parseStream(stringstream& stream) {
	string line;
	string key;
	string section = "";
	bool canWrite = false;
	smatch m;
	while (getline(stream, line))
	{
		line = regex_replace(line, std::regex("[#;].*"), ""); // Remove comments from config
		line = trim(line);
		if (line.length() == 0)
			continue;
		if (regex_search(line, m, regex("\\[.*\\]"))) // Check for section
		{
			section.clear();
			section = m.str().substr(1, m.str().length() - 2);
		}
		else
		{
			smatch mat;
			regex_search(line, mat, regex("="));
			addConfig(section, mat.prefix(), mat.suffix());
		}
	}
}

bool Config::addConfig(string section, string option, string value) {
	// section = trim(section);
	option = trim(option);
	value = trim(value);

	if (section == "")  section = DEFAULT_SECTION;
	if (data.find(section) == data.end()) {
		map<string, string> temp = { { option, value } };
		data.insert({ section, temp });

		return true;
	}
	else {
		if(data.find(section)->second.find(option) != data.find(section)->second.end())
			data.find(section)->second.find(option)->second = value;
		else
			data.find(section)->second.insert({ option, value });
	}
	return false;
}

void Config::readFromFile(string fileName) {
	ifstream file(fileName, ios::out);
	if (!file.is_open())
	{
		cerr << "Error: Unable to open INI file " << fileName << " for reading!" << endl;
		return;
	}
	stringstream str;
	str << file.rdbuf();

	parseStream(str);
}

void Config::readFromText(string text) {
	stringstream str;
	str << text;

	parseStream(str);
}

string Config::get(string key) {
	string section;
	string option;

	vector<string> temp = split(key, "::");
	if (temp.size() >= 2) {
		section = temp[0];
		option = temp[1];
	}
	else {
		section = DEFAULT_SECTION;
		option = temp[0];
	}

	if (data.find(section) != data.end())
		if (data.find(section)->second.find(option) != data.find(section)->second.end())
			return data.find(section)->second.find(option)->second;
		else
			return "";
	else
		return "";
}

vector<string> Config::strings(string key) {
	string temp = get(key);
	vector<string> arr = split(temp, ',');

	for (auto itr = arr.begin(); itr != arr.end(); itr++) { // Trim all the whitepaces
		*itr = trim(*itr);
	}

	return arr;
}

void Config::set(string key, string value) {
	string section;
	string option;

	vector<string> temp = split(key, "::");
	if (temp.size() >= 2) {
		section = temp[0];
		option = temp[1];
	}
	else {
		section = DEFAULT_SECTION;
		option = temp[0];
	}

	addConfig(section, option, value);
}