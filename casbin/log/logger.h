#pragma once

#ifdef CASBIN_EXPORTS
#define LOGGER_API __declspec(dllexport)
#else
#define LOGGER_API __declspec(dllimport)
#endif

#include<iostream>
#include<string>
#include<fstream>
#include <ctime>

using namespace std;

class LOGGER_API Logger {
	string file_name_ = "casbin_test.log";
public:
	void append_to_file(const string&) const;
	void print(const string&) const;
};