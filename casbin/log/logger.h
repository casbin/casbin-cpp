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
	string fileName = "casbin_test.log";
public:
	void appendToFile(string);
	void print(string);
};