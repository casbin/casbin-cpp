#pragma once

#ifdef CASBIN_EXPORTS
#define CONFIG_API __declspec(dllexport)
#else
#define CONFIG_API __declspec(dllimport)
#endif

#include<string>
#include<mutex>
#include<map>
#include<sstream>
#include<vector>


using namespace std;

extern const string DEFAULT_SECTION;
extern const string DEFAULT_COMMENT;
extern const string DEFAULT_COMMENT_SEM;
extern const string DEFAULT_MULTI_LINE_SEPARATOR;



class CONFIG_API Config {
public:
	map<string, map<string, string>> data;
	mutex m;
	Config();
	Config(const Config& cfg);
	static Config NewConfigFromFile(const string& path);
	static Config NewConfigFromText(const string& text);
	void parseFile(const string& fname);
	void parseText(const string& text);
	void parseBuffer(stringstream& buf);
	void write(const string& section, const int& lineNum, string& buffer);
	bool AddConfig(const string& section, const string& option, const string& value);
	void Set(const string& key, const string& value);
	string get(const string& key);
	string String(const string& key);
};