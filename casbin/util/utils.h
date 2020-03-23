#pragma once

#ifdef CASBIN_EXPORTS
#define UTILS_API __declspec(dllexport)
#else
#define UTILS_API __declspec(dllimport)
#endif

#include <string>
#include <vector>
#include <iostream>
#include <stdio.h>
#include <sstream>
#include <regex>
#include <map>

using namespace std;

extern "C++" UTILS_API inline string ltrim(string, const string = "\t\n\v\f\r ");

extern "C++" UTILS_API inline std::string rtrim(string, const string = "\t\n\v\f\r ");

extern "C++" UTILS_API inline std::string trim(string, const string = "\t\n\v\f\r ");

extern "C++" UTILS_API vector<string> split(const string&, char);

extern "C++" UTILS_API vector<string> split(string, string);

extern "C++" UTILS_API string join(vector<string>, char);

extern "C++" UTILS_API bool keyMatch(string, string);

extern "C++" UTILS_API bool keyMatch2(string, string);

extern "C++" UTILS_API bool keyMatch4(string, string);

extern "C++" UTILS_API bool regexMatch(string, string);

extern "C++" UTILS_API string escapeAssertion(string);


