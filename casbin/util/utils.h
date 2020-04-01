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
#include <unordered_map>


using namespace std;

extern "C++" UTILS_API inline string ltrim(string, const string = "\t\n\v\f\r ");

extern "C++" UTILS_API inline string rtrim(string, const string = "\t\n\v\f\r ");

extern "C++" UTILS_API inline string trim(string, const string = "\t\n\v\f\r ");

extern "C++" UTILS_API vector<string> split(const string&, char);

extern "C++" UTILS_API vector<string> split(string, string);

extern "C++" UTILS_API string join(vector<string>, char);

extern "C++" UTILS_API string escape_assertion(string);




