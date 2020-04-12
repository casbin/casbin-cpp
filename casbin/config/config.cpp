#include "config.h"
#include "../util/util.h"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <fstream>

const string DEFAULT_SECTION = "default";
const string DEFAULT_COMMENT = "#";
const string DEFAULT_COMMENT_SEM = ";";
const string DEFAULT_MULTI_LINE_SEPARATOR = "\\";



Config::Config() {

}

Config* Config::NewConfigFromFile(Error& err,const string& path) {
	Config* cfg = new Config();
	err = cfg->parseFile(path);
	return cfg;
}

Config* Config::NewConfigFromText(Error& err, const string& text) {
	Config* cfg = new Config();
	err = cfg->parseText(text);
	return cfg;
}

Error Config::parseFile(const string& fname) {
	m.lock();
	ifstream fin(fname);
	if (!fin.is_open()) {
		return Error("file can't open");
	}
	stringstream ss ;
	ss << fin.rdbuf();
	fin.close();
	Error err = parseBuffer(ss);
	m.unlock();
	return err;
}


Error Config::parseText(const string& text) {
	stringstream ss = stringstream(text);
	return parseBuffer(ss);
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

Error Config::parseBuffer(stringstream& buf) {
	string section;
	int lineNum = 0;
	string buffer;
	bool canWrite = false;
	while (true) {
		if (canWrite) {
			Error err = write(section, lineNum, buffer);
			if (!err.IsNull()) {
				return err;
			}
			else {
				canWrite = false;
			}
		}
		lineNum++;
		string line;
		if (!getline(buf, line)) {
			if (buffer.size() > 0) {
				Error err = write(section, lineNum, buffer);
				if (!err.IsNull()) {
					return err;
				}
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
				Error err = write(section, lineNum, buffer);
				if (!err.IsNull()) {
					return err;
				}
				canWrite = false;
			}
			section = line.substr(1, line.size()-2);
		}
		else {
			string p;
			if (Util::HasSuffix(line, DEFAULT_MULTI_LINE_SEPARATOR)) {
				p = line.substr(0, line.size() - 1);
				p = Util::Trim(p ," ");
			}
			else {
				p = line;
				canWrite = true;
			}
			buffer += p;
		}
	}
	return Error();
}

Error Config::write(const string& section, const  int& lineNum,  string& buffer) {
	if (buffer.size() <= 0) {
		return Error();
	}

	vector<string> optionVal = Util::SplitN(buffer, "=", 2);
	if (optionVal.size() != 2) {
		string error_info = "parse the content error : line" + to_string(lineNum) +string(" , ") + optionVal[0] + string(" = ? ");
		return Error(error_info);
	}
	string option = Util::Trim(optionVal[0], " ");
	string value = Util::Trim(optionVal[1], " ");
	AddConfig(section,option , value);
	buffer = "";
	return Error();
}

Error Config::Set(const string& key, const string& value) {
	string key_tmp = key;
	m.lock();
	if (key_tmp.size() == 0) {
		return Error("key is empty");
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
	return Error();
}

string Config::get(const string& key) {
	string section;
	string option;
	string key_tmp = key;
	transform(key_tmp.begin(), key_tmp.end(), key_tmp.begin(), ::tolower);
	vector<string> keys = Util::Split(key_tmp, "::");

	if (key_tmp.size() >= 2) {
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