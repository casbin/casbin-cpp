#include "config.h"
#include "../util/util.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <exception>

const string DEFAULT_SECTION = "default";
const string DEFAULT_COMMENT = "#";
const string DEFAULT_COMMENT_SEM = ";";
const string DEFAULT_MULTI_LINE_SEPARATOR = "\\";



Config::Config() {

}

Config::Config(const Config& cfg) {
	data = cfg.data;
}

Config Config::NewConfigFromFile(const string& path) {
	Config c = Config() ;
	c.parseFile(path);
	return c;
}


Config Config::NewConfigFromText(const string& text) {
	Config cfg =Config();
	cfg.parseText(text);
	return cfg;
}

void Config::parseFile(const string& fname) {
	ifstream fin(fname);
	if (!fin.is_open()) {
		string err_info = "Can't open the file: " + fname;
		throw exception(err_info.data());
	}

	stringstream ss ;
	ss << fin.rdbuf();
	fin.close();
	parseBuffer(ss);
}


void Config::parseText(const string& text) {
	stringstream ss = stringstream(text);
	parseBuffer(ss);
}

bool Config::AddConfig(const string& section, const string& option, const string& value) {
	string section_tmp = section;
	if (section == "") {
		section_tmp = DEFAULT_SECTION;
	}

	bool ok = data.count(section_tmp) && data[section_tmp].count(option);
	data[section_tmp][option] = value;
	return !ok;
}

void Config::parseBuffer(stringstream& buf) {
	string section;
	int lineNum = 0;
	string buffer;
	bool canWrite = false;
	while (true) {
		if (canWrite) {
			write(section, lineNum, buffer);
			canWrite = false;
		}
		lineNum++;
		string line;
		if (!getline(buf, line)) {
			if (buffer.size() > 0) {
				write(section, lineNum, buffer);
			}
			break;
		}
		line = Util::Trim(line, " ");
		if (Util::HasPrefix(line, DEFAULT_COMMENT_SEM) || Util::HasPrefix(line, DEFAULT_COMMENT)) {
			canWrite = true;
			continue;
		}
		else if (Util::HasPrefix(line,"[") && Util::HasSuffix(line,"]")) {
			if (buffer.size() > 0) {
				write(section, lineNum, buffer);
				canWrite = false;
			}
			section = line.substr(1, line.size()-2);
		}
		else {
			string p;
			if (Util::HasSuffix(line, DEFAULT_MULTI_LINE_SEPARATOR)) {
				p = line.substr(0, line.size() - 1);
				p = Util::Trim(p ," ");
				p += " ";
			}
			else {
				p = line;
				canWrite = true;
			}
			buffer += p;
		}
	}
}

void Config::write(const string& section, const  int& lineNum,  string& buffer) {
	if (buffer.size() <= 0) {
		return;
		//throw exception("buffer is empty");
	}

	vector<string> optionVal = Util::SplitN(buffer, "=", 2);
	if (optionVal.size() != 2) {
		string error_info = "parse the content error : line" + to_string(lineNum) +string(" , ") + optionVal[0] + string(" = ? ");
		throw exception(error_info.data());
	}
	string option = Util::Trim(optionVal[0], " ");
	string value = Util::Trim(optionVal[1], " ");
	AddConfig(section,option , value);
	buffer = "";
}

void Config::Set(const string& key, const string& value) {
	string key_tmp = key;
	m.lock();
	if (key_tmp.size() == 0) {
		throw exception("key is empty");
	}

	string section;
	string option;

	transform(key_tmp.begin(), key_tmp.end(), key_tmp.begin(), ::tolower);
	vector<string> keys = Util::Split(key_tmp, "::");
	if (keys.size() >= 2) {
		section = keys[0];
		option = keys[1];
	}
	else {
		option = keys[0];
	}

	AddConfig(section, option, value);
	m.unlock();

}

string Config::get(const string& key) {
	string section;
	string option;
	string key_tmp = key;
	transform(key_tmp.begin(), key_tmp.end(), key_tmp.begin(), ::tolower);
	vector<string> keys = Util::Split(key_tmp, "::");

	if (keys.size() >= 2) {
		section = keys[0];
		option = keys[1];
	}
	else {
		section = DEFAULT_SECTION;
		option = keys[0];
	}

	if (data.count(section) && data[section].count(option)) {
		return data[section][option];
	}

	return "";
}

string Config::String(const string& key) {
	return get(key);
}

vector<string> Config::Strings(const string& key) {
	string v = get(key);
	return Util::Split(v, ",");
}

bool Config::Bool(const string& key) {
	bool b;
	istringstream(get(key)) >> boolalpha >> b;
	return b;
}
int Config::Int(const string& key) {
	return atoi(get(key).c_str());
}

double Config::Double(const string& key) {
	return atof(get(key).c_str());
}

long Config::Long(const string& key) {
	long b = atoi(get(key).c_str());
	return b;
}
