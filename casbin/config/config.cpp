#include "config.h"


const string default_section = "default";

Config::Config()
= default;

Config::Config(const string& conf_name)
{
	read_from_file(conf_name);
}

auto Config::parse_stream(stringstream& stream) -> void
{
	string line;
	string key;
	string section;
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
			add_config(section, mat.prefix(), mat.suffix());
		}
	}
}

auto Config::add_config(string section, string option, string value) -> bool
{
	// section = trim(section);
	option = trim(option);
	value = trim(value);

	if (section.empty())  section = default_section;
	if (data_.find(section) == data_.end()) {
		unordered_map<string, string> temp = { { option, value } };
		data_.insert({ section, temp });

		return true;
	}
	else {
		if(data_.find(section)->second.find(option) != data_.find(section)->second.end())
			data_.find(section)->second.find(option)->second = value;
		else
			data_.find(section)->second.insert({ option, value });
	}
	return false;
}

auto Config::read_from_file(const string& file_name) -> void
{
	lock_guard<mutex> guard(data_mutex);
	const ifstream file(file_name, ios::out);
	if (!file.is_open())
	{
		cerr << "Error: Unable to open INI file " << file_name << " for reading!" << endl;
		return;
	}
	stringstream str;
	str << file.rdbuf();

	parse_stream(str);
}

auto Config::read_from_text(const string& text) -> void
{
	stringstream str;
	str << text;

	parse_stream(str);
}

string Config::get(string key) {
	string section;
	string option;

	vector<string> temp = split(move(key), "::");
	if (temp.size() >= 2) {
		section = temp[0];
		option = temp[1];
	}
	else {
		section = default_section;
		option = temp[0];
	}

	if (data_.find(section) != data_.end())
		if (data_.find(section)->second.find(option) != data_.find(section)->second.end())
			return data_.find(section)->second.find(option)->second;
		else
			return "";
	else
		return "";
}

auto Config::strings(const string& key) -> vector<string>
{
	const auto temp = get(key);
	auto arr = split(temp, ',');

	for (auto itr = arr.begin(); itr != arr.end(); ++itr) { // Trim all the whitespace
		*itr = trim(*itr);
	}

	return arr;
}

auto Config::set(const string& key, const string& value) -> void
{
	string section;
	string option;

	auto temp = split(key, "::");
	if (temp.size() >= 2) {
		section = temp[0];
		option = temp[1];
	}
	else {
		section = default_section;
		option = temp[0];
	}

	add_config(section, option, value);
}
