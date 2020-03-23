#pragma once

#ifdef CASBIN_EXPORTS
#define CONFADAPTER_API __declspec(dllexport)
#else
#define CONFADAPTER_API __declspec(dllimport)
#endif

#include <map>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>
#include "../util/utils.h"

using namespace std;

class CONFADAPTER_API Config {
	map<string, map<string, string>> data;
public:
	Config() {
	}

	Config(string confName) {
		readFromFile(confName);
	}

	void parseStream(stringstream&);
	void readFromFile(string);
	void readFromText(string);
	bool addConfig(string, string, string);
	string get(string);
	void set(string, string);
	vector<string> strings(string);
};