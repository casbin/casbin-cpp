#pragma once

#ifdef CASBIN_EXPORTS
#define CONFADAPTER_API __declspec(dllexport)
#else
#define CONFADAPTER_API __declspec(dllimport)
#endif

#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <regex>
#include "utils.h"

using namespace std;

class CONFADAPTER_API ConfAdapter {
protected:
    map<string, vector<string>> data;

public:
    void readFile(string);
    void display();
    vector<string> getSections();
    vector<string> getSectionData(string);
};