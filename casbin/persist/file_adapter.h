#pragma once

#include <iostream>
#include <fstream>
#include "adapter.h"

using namespace std;

class FileAdapter: public Adapter {
	string filePath;
public:
	FileAdapter(string path) {
		filePath = path;
	}
	void loadPolicy(Model*);
	void savePolicy(Model*);
	void addPolicy(string, string, vector<string>);
	void removePolicy(string, string, vector<string>);
};