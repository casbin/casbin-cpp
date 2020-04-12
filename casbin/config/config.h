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
#include"../errors/exceptions.h"


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
	static Config* NewConfigFromFile(Error& err,const string& path);
	static Config* NewConfigFromText(Error& err, const string& text);
	Error parseFile(const string& fname);
	Error parseText(const string& text);
	Error parseBuffer(stringstream& buf);
	Error write(const string& section, const int& lineNum, string& buffer);
	bool AddConfig(const string& section, const string& option, const string& value);
	Error Set(const string& key, const string& value);
	string get(const string& key);
	string String(const string& key);
};