#pragma once

#ifdef CASBIN_EXPORTS
#define CSVADAPTER_API __declspec(dllexport)
#else
#define CSVADAPTER_API __declspec(dllimport)
#endif

#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include "utils.h"

using namespace std;

class CSVADAPTER_API CSVAdapter {
    vector<vector<string>> data;

public:
    vector<string> readLine(string);
    void readFile(string);
    void writeFile(string);
    void display();
    vector<vector<string>> getData();
};